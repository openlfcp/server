//! The server process: one listener, one task per connection, graceful
//! shutdown.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use hyper_util::server::graceful::GracefulShutdown;
use tokio::net::TcpListener;

use crate::config::Config;
use crate::http;
use crate::identity::{ServerId, ServerIdentity};

/// How long open connections get to finish after shutdown starts.
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

/// A bound, not yet running server.
pub struct Server {
    listener: TcpListener,
    identity: Arc<dyn ServerIdentity>,
    config: Config,
}

impl Server {
    /// Bind the configured address. The identity is loaded by the caller
    /// once per process and shared by every connection.
    pub async fn bind(
        config: Config,
        identity: Arc<dyn ServerIdentity>,
    ) -> std::io::Result<Server> {
        let listener = TcpListener::bind(config.bind).await?;
        Ok(Server {
            listener,
            identity,
            config,
        })
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

    /// Serve until `shutdown` completes, then stop accepting, let open
    /// connections finish for up to [`SHUTDOWN_GRACE`], and return.
    pub async fn run(self, shutdown: impl Future<Output = ()>) {
        let graceful = GracefulShutdown::new();
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                accepted = self.listener.accept() => {
                    let (stream, peer) = match accepted {
                        Ok(pair) => pair,
                        Err(error) => {
                            tracing::warn!(%error, "accept failed");
                            continue;
                        }
                    };
                    // LFCP-047 adds the WebSocket upgrade; hyper-util's graceful
                    // watcher covers plain HTTP/1 connections.
                    let connection = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service_fn(http::handle));
                    let connection = graceful.watch(connection);
                    tokio::spawn(async move {
                        if let Err(error) = connection.await {
                            tracing::debug!(%peer, %error, "connection ended with an error");
                        }
                    });
                }
                () = &mut shutdown => break,
            }
        }
        drop(self.listener);
        tracing::info!("shutting down");
        if tokio::time::timeout(SHUTDOWN_GRACE, graceful.shutdown())
            .await
            .is_err()
        {
            tracing::warn!("connections still open after the grace period; closing them");
        }
    }
}
