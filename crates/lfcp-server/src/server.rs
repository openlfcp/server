//! The server process: one listener, one task per connection, graceful
//! shutdown of HTTP and WebSocket connections alike.
//!
//! Shutdown: a `watch` channel tells every connection to stop; each HTTP
//! connection finishes its request, each WebSocket connection sends a close
//! frame (1001) and drains its queue. Every connection task holds a clone of
//! an `mpsc` sender, so the server knows when the last one has ended, and
//! waits for that at most [`SHUTDOWN_GRACE`].
//!
//! Connection cap (security review M2): each TCP connection holds a permit
//! of a semaphore of [`Config::max_connections`] for its whole life, a
//! WebSocket after the upgrade included. A connection accepted past the
//! cap gets `503 Service Unavailable` with `Retry-After` and is closed,
//! without its request being read.

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch, OwnedSemaphorePermit, Semaphore};

use crate::config::Config;
use crate::http;
use crate::identity::{ServerId, ServerIdentity};
use crate::store::Store;
use crate::ws::{self, ConnectionContext, Limits, SessionFactory};

/// How long open connections get to finish after shutdown starts.
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

/// The answer to a connection past [`Config::max_connections`].
const BUSY: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\nretry-after: 5\r\ncontent-type: text/plain\r\ncontent-length: 19\r\nconnection: close\r\n\r\nserver at capacity\n";

/// How many refused connections may be answering [`BUSY`] at once; past
/// that they are closed without an answer.
const BUSY_ANSWERS: usize = 64;

/// A bound, not yet running server.
pub struct Server {
    admin: Option<Arc<crate::admin::Admin>>,
    listener: TcpListener,
    identity: Arc<dyn ServerIdentity>,
    store: Arc<Store>,
    config: Config,
}

/// What every connection task shares.
struct Shared<F> {
    admin: Option<Arc<crate::admin::Admin>>,
    config: Config,
    server_id: ServerId,
    sessions: F,
    next_id: AtomicU64,
    connections: Arc<Semaphore>,
    busy_answers: Arc<Semaphore>,
    shutdown: watch::Receiver<bool>,
    alive: mpsc::Sender<()>,
}

impl Server {
    /// Bind the configured address. The identity and the store are opened
    /// by the caller once per process and shared by every connection.
    pub async fn bind(
        config: Config,
        identity: Arc<dyn ServerIdentity>,
        store: Arc<Store>,
    ) -> std::io::Result<Server> {
        let listener = TcpListener::bind(config.bind).await?;
        Ok(Server {
            admin: None,
            listener,
            identity,
            store,
            config,
        })
    }

    /// Serve the setup/admin HTTP API (LFCP-046) on this listener too.
    pub fn with_admin(mut self, admin: Arc<crate::admin::Admin>) -> Server {
        self.admin = Some(admin);
        self
    }

    /// The store.
    pub fn store(&self) -> &Arc<Store> {
        &self.store
    }

    /// The bound address (useful with port 0).
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// The server ID every connection sees.
    pub fn server_id(&self) -> ServerId {
        self.identity.server_id()
    }

    /// The configuration.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Serve until `shutdown` completes, with `sessions` creating the
    /// session of each WebSocket connection. Then stop accepting, ask every
    /// connection to close, and wait for them at most [`SHUTDOWN_GRACE`].
    pub async fn run<F: SessionFactory>(self, sessions: F, shutdown: impl Future<Output = ()>) {
        let (stop, stopping) = watch::channel(false);
        let (alive, mut all_done) = mpsc::channel::<()>(1);
        let shared = Arc::new(Shared {
            admin: self.admin.clone(),
            config: self.config.clone(),
            server_id: self.identity.server_id(),
            sessions,
            next_id: AtomicU64::new(1),
            connections: Arc::new(Semaphore::new(self.config.max_connections)),
            busy_answers: Arc::new(Semaphore::new(BUSY_ANSWERS)),
            shutdown: stopping,
            alive,
        });
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                accepted = self.listener.accept() => match accepted {
                    Ok((stream, peer)) => match shared.connections.clone().try_acquire_owned() {
                        Ok(permit) => {
                            tokio::spawn(serve_http(stream, peer, shared.clone(), Arc::new(permit)));
                        }
                        Err(_) => {
                            tracing::warn!(%peer, "connection limit reached; refusing");
                            if let Ok(answering) = shared.busy_answers.clone().try_acquire_owned() {
                                tokio::spawn(refuse(stream, answering));
                            }
                        }
                    },
                    Err(error) => tracing::warn!(%error, "accept failed"),
                },
                () = &mut shutdown => break,
            }
        }
        drop(self.listener);
        tracing::info!("shutting down");
        let _ = stop.send(true);
        drop(shared); // our own `alive` sender
        if tokio::time::timeout(SHUTDOWN_GRACE, all_done.recv())
            .await
            .is_err()
        {
            tracing::warn!("connections still open after the grace period; closing them");
        }
    }
}

/// Answer a connection past the cap with [`BUSY`], then close it. The
/// request is drained briefly, not parsed, so the close does not reset the
/// connection before the client reads the answer.
async fn refuse(mut stream: tokio::net::TcpStream, _answering: OwnedSemaphorePermit) {
    let _ = tokio::time::timeout(Duration::from_secs(1), async {
        stream.write_all(BUSY).await?;
        stream.shutdown().await?;
        let mut sink = [0u8; 1024];
        while stream.read(&mut sink).await? > 0 {}
        Ok::<(), std::io::Error>(())
    })
    .await;
}

/// One TCP connection: HTTP/1.1, possibly upgraded to WebSocket. `permit`
/// is its place under the connection cap, held until it closes.
async fn serve_http<F: SessionFactory>(
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    shared: Arc<Shared<F>>,
    permit: Arc<OwnedSemaphorePermit>,
) {
    let _alive = shared.alive.clone();
    let mut shutdown = shared.shutdown.clone();
    let handler = shared.clone();
    let service = service_fn(move |request| route(request, peer, handler.clone(), permit.clone()));
    // A client must send its request headers within the handshake
    // timeout (security review M2).
    let connection = hyper::server::conn::http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_millis(shared.config.handshake_timeout_ms))
        .serve_connection(TokioIo::new(stream), service)
        .with_upgrades();
    tokio::pin!(connection);
    tokio::select! {
        result = connection.as_mut() => {
            if let Err(error) = result {
                tracing::debug!(%peer, %error, "connection ended with an error");
            }
        }
        () = stopped(&mut shutdown) => {
            connection.as_mut().graceful_shutdown();
            let _ = connection.await;
        }
    }
}

/// Completes when shutdown has been requested (or the server is gone).
async fn stopped(shutdown: &mut watch::Receiver<bool>) {
    let _ = shutdown.wait_for(|stop| *stop).await.map(|_| ());
}

async fn route<F: SessionFactory>(
    request: Request<Incoming>,
    peer: SocketAddr,
    shared: Arc<Shared<F>>,
    permit: Arc<OwnedSemaphorePermit>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    if request.uri().path() != shared.config.ws_path {
        if let Some(admin) = shared
            .admin
            .as_ref()
            .filter(|_| crate::admin::Admin::handles(request.uri().path()))
        {
            return Ok(admin.handle(request).await);
        }
        return Ok(http::route(request.method(), request.uri().path()));
    }
    let response = match ws::check_upgrade(&request) {
        ws::Upgrade::Accept(response) => response,
        ws::Upgrade::Reject(rejection) => return Ok(rejection),
    };
    let connection = ConnectionContext {
        id: shared.next_id.fetch_add(1, Ordering::Relaxed),
        peer,
        server_id: shared.server_id,
        limits: Limits::new(shared.config.max_message_bytes, shared.config.heartbeat_ms)
            .with_handshake_timeout(Duration::from_millis(shared.config.handshake_timeout_ms)),
    };
    let session = shared.sessions.open(&connection);
    let alive = shared.alive.clone();
    let shutdown = shared.shutdown.clone();
    tokio::spawn(async move {
        let _alive = alive;
        let _permit = permit;
        ws::serve(request, connection, session, shutdown).await;
    });
    Ok(response)
}
