//! A running server with the LFCP session and a minimal LFCP client over
//! real TCP WebSocket connections.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use lfcp::principal::PrincipalKeys;
use lfcp::wire::message::{Body, DecodeOptions, HelloBody, Message};
use lfcp::wire::session::{auth, WIRE_PROFILE};
use lfcp_server::config::Config;
use lfcp_server::identity::{ServerId, ServerIdentity};
use lfcp_server::rng::Random;
use lfcp_server::server::Server;
use lfcp_server::session::{HostingPolicy, Lfcp};
use lfcp_server::store::Store;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::Message as Frame;
use tokio_tungstenite::WebSocketStream;

/// Random values handed out in order, then a counter: tests can inject
/// the server nonce, session ID and message IDs of a published vector.
#[derive(Default)]
pub struct Script {
    values: Mutex<VecDeque<[u8; 16]>>,
    counter: AtomicU64,
}

impl Script {
    pub fn push(&self, value: [u8; 16]) {
        self.values.lock().unwrap().push_back(value);
    }

    pub fn clear(&self) {
        self.values.lock().unwrap().clear();
    }
}

impl Random for Script {
    fn fill(&self, bytes: &mut [u8]) -> Result<(), String> {
        if bytes.len() == 16 {
            if let Some(value) = self.values.lock().unwrap().pop_front() {
                bytes.copy_from_slice(&value);
                return Ok(());
            }
        }
        let n = self.counter.fetch_add(1, Ordering::SeqCst) + 1;
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (n >> ((i % 8) * 8)) as u8 ^ 0x5a;
        }
        Ok(())
    }
}

/// A fixed server ID.
pub struct FixedIdentity(pub [u8; 32]);

impl ServerIdentity for FixedIdentity {
    fn server_id(&self) -> ServerId {
        ServerId::from_bytes(self.0)
    }
}

pub struct Options {
    pub identity: Option<Arc<dyn ServerIdentity>>,
    pub random: Arc<Script>,
    pub hosting: Option<Arc<dyn HostingPolicy>>,
    pub public_urls: Vec<String>,
    pub ingest: Option<Arc<dyn lfcp_server::ingest::IngestPolicy>>,
    pub max_message_bytes: Option<usize>,
    /// The setup code's lifetime (LFCP-046); default one hour.
    pub setup_ttl: Option<Duration>,
    /// Overrides of the configuration defaults.
    pub handshake_timeout_ms: Option<u64>,
    pub max_connections: Option<usize>,
    /// The abuse limits (POST-003); default `AbuseLimits::default()`
    /// without the free disk check (`min_free_bytes = 0`), so tests do not
    /// depend on the machine's free space.
    pub abuse: Option<lfcp_server::limits::AbuseLimits>,
    /// The free disk space reader of the storage floor; default the OS.
    pub disk: Option<Arc<dyn lfcp_server::limits::DiskSpace>>,
    /// Any other change to the configuration, applied last.
    pub configure: Option<fn(&mut Config)>,
}

impl Default for Options {
    fn default() -> Options {
        Options {
            identity: None,
            random: Arc::new(Script::default()),
            hosting: None,
            public_urls: Vec::new(),
            ingest: None,
            max_message_bytes: None,
            setup_ttl: None,
            handshake_timeout_ms: None,
            max_connections: None,
            abuse: None,
            disk: None,
            configure: None,
        }
    }
}

pub struct Running {
    pub addr: SocketAddr,
    /// The setup code the admin surface created, while unpaired.
    pub setup_code: Option<String>,
    pub store: Arc<Store>,
    pub server_id: ServerId,
    /// The server-wide outbound byte budget (POST-004).
    pub outbound: Arc<lfcp_server::budget::ByteBudget>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

impl Running {
    /// Stop the server and wait for it (the state directory is kept).
    pub async fn stop(mut self) {
        let _ = self.stop.take().unwrap().send(());
        tokio::time::timeout(Duration::from_secs(12), &mut self.task)
            .await
            .expect("shut down in time")
            .unwrap();
    }
}

/// A fresh state directory for test `name`.
pub fn state_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("lfcp-session-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// Start a server on `state` (created if new) with default limits.
pub async fn start(state: &std::path::Path, options: Options) -> Running {
    let mut config = Config {
        bind: "127.0.0.1:0".parse().unwrap(),
        state_dir: state.to_owned(),
        public_urls: options.public_urls,
        max_message_bytes: options
            .max_message_bytes
            .unwrap_or(lfcp::wire::message::DEFAULT_MAX_MESSAGE_BYTES),
        handshake_timeout_ms: options
            .handshake_timeout_ms
            .unwrap_or(Config::default().handshake_timeout_ms),
        max_connections: options
            .max_connections
            .unwrap_or(Config::default().max_connections),
        abuse: options.abuse.unwrap_or(lfcp_server::limits::AbuseLimits {
            min_free_bytes: 0,
            ..Default::default()
        }),
        ..Config::default()
    };
    if let Some(configure) = options.configure {
        configure(&mut config);
    }
    let identity: Arc<dyn ServerIdentity> = match options.identity {
        Some(identity) => identity,
        None => Arc::new(lfcp_server::identity::FileIdentity::load_or_create(state).unwrap()),
    };
    let store = Arc::new(Store::open(state).unwrap());
    let server = Server::bind(config.clone(), identity, store.clone())
        .await
        .unwrap();
    let addr = server.local_addr().unwrap();
    let server_id = server.server_id();
    let outbound = server.outbound();
    let (admin, setup_code) = lfcp_server::admin::Admin::open(
        store.clone(),
        server_id,
        &config,
        Arc::new(lfcp_server::rng::OsRandom),
        options.setup_ttl.unwrap_or(lfcp_server::admin::SETUP_TTL),
    )
    .await
    .unwrap();
    let server = server.with_admin(admin.clone());
    let mut sessions = Lfcp::new(store.clone(), &config)
        .with_random(options.random)
        .with_hosting(admin.hosting());
    if let Some(hosting) = options.hosting {
        sessions = sessions.with_hosting(hosting);
    }
    if let Some(ingest) = options.ingest {
        sessions = sessions.with_ingest(ingest);
    }
    if let Some(disk) = options.disk {
        sessions = sessions.with_floor(Arc::new(lfcp_server::limits::Floor::new(
            &config.abuse,
            &config.state_dir,
            disk,
        )));
    }
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(server.run(sessions, async {
        let _ = stopped.await;
    }));
    Running {
        addr,
        setup_code: setup_code.map(|c| c.expose().to_owned()),
        store,
        server_id,
        outbound,
        stop: Some(stop),
        task,
    }
}

pub struct Client {
    socket: WebSocketStream<TcpStream>,
    next_id: u8,
}

/// A refused WebSocket upgrade: the HTTP status, `Retry-After` and body.
#[derive(Debug, PartialEq, Eq)]
pub struct Refused {
    pub status: u16,
    pub retry_after: Option<String>,
    pub body: String,
}

impl Client {
    pub async fn connect(addr: SocketAddr) -> Client {
        Client::try_connect(addr, &[]).await.expect("handshake")
    }

    /// Upgrade with extra request headers; the HTTP refusal if any.
    pub async fn try_connect(
        addr: SocketAddr,
        headers: &[(&str, &str)],
    ) -> Result<Client, Refused> {
        let mut request = format!("ws://{addr}/v1/ws").into_client_request().unwrap();
        request
            .headers_mut()
            .insert("sec-websocket-protocol", "lfcp-1".parse().unwrap());
        for (name, value) in headers {
            request.headers_mut().append(
                tokio_tungstenite::tungstenite::http::HeaderName::from_bytes(name.as_bytes())
                    .unwrap(),
                value.parse().unwrap(),
            );
        }
        let stream = TcpStream::connect(addr).await.unwrap();
        match tokio_tungstenite::client_async(request, stream).await {
            Ok((socket, _)) => Ok(Client { socket, next_id: 0 }),
            Err(tokio_tungstenite::tungstenite::Error::Http(response)) => Err(Refused {
                status: response.status().as_u16(),
                retry_after: response
                    .headers()
                    .get("retry-after")
                    .map(|v| v.to_str().unwrap().to_owned()),
                body: String::from_utf8_lossy(response.body().as_deref().unwrap_or_default())
                    .into_owned(),
            }),
            Err(error) => panic!("handshake: {error}"),
        }
    }

    /// A fresh message ID for a request.
    pub fn id(&mut self) -> [u8; 16] {
        self.next_id += 1;
        [self.next_id; 16]
    }

    pub async fn send_bytes(&mut self, bytes: Vec<u8>) {
        self.socket.send(Frame::Binary(bytes.into())).await.unwrap();
    }

    pub async fn send(&mut self, message: &Message) {
        self.send_bytes(message.encode()).await;
    }

    /// Send `body` as a new request; returns its message ID.
    pub async fn request(&mut self, body: Body) -> [u8; 16] {
        let id = self.id();
        self.send(&Message::new(id, body)).await;
        id
    }

    /// The next LFCP message's exact bytes.
    pub async fn recv_bytes(&mut self) -> Vec<u8> {
        loop {
            let frame = tokio::time::timeout(Duration::from_secs(5), self.socket.next())
                .await
                .expect("a frame in time")
                .expect("not closed")
                .expect("frame");
            match frame {
                Frame::Binary(bytes) => return bytes.to_vec(),
                Frame::Ping(_) | Frame::Pong(_) => continue,
                other => panic!("expected a binary LFCP message, got {other:?}"),
            }
        }
    }

    pub async fn recv(&mut self) -> Message {
        Message::decode(&self.recv_bytes().await, &DecodeOptions::default()).expect("decodes")
    }

    /// The next data frame's bytes, or `None` once the connection has
    /// ended (a close frame, EOF or an error).
    pub async fn next_frame(&mut self) -> Option<Vec<u8>> {
        loop {
            match self.socket.next().await {
                Some(Ok(Frame::Binary(bytes))) => return Some(bytes.to_vec()),
                Some(Ok(Frame::Ping(_) | Frame::Pong(_))) => continue,
                _ => return None,
            }
        }
    }

    /// Expect the server to close the connection.
    pub async fn expect_close(&mut self) {
        loop {
            match tokio::time::timeout(Duration::from_secs(5), self.socket.next())
                .await
                .expect("closed in time")
            {
                Some(Ok(Frame::Close(Some(frame)))) => {
                    assert_ne!(frame.code, CloseCode::Away, "closed by shutdown");
                    return;
                }
                Some(Ok(Frame::Close(None))) | None | Some(Err(_)) => return,
                Some(Ok(Frame::Ping(_) | Frame::Pong(_))) => continue,
                Some(Ok(other)) => panic!("expected a close, got {other:?}"),
            }
        }
    }

    /// Read until the server closes; its close code, if it sent one.
    pub async fn close_code(&mut self) -> Option<CloseCode> {
        loop {
            match tokio::time::timeout(Duration::from_secs(5), self.socket.next())
                .await
                .expect("closed in time")
            {
                Some(Ok(Frame::Close(frame))) => return frame.map(|f| f.code),
                None | Some(Err(_)) => return None,
                Some(Ok(_)) => continue,
            }
        }
    }

    /// HELLO, CHALLENGE, AUTH, READY as `keys`. Returns the CHALLENGE and
    /// READY messages.
    pub async fn handshake(&mut self, keys: &PrincipalKeys) -> (Message, Message) {
        let hello = HelloBody {
            wire_profiles: vec![WIRE_PROFILE.into()],
            principal: keys.descriptor().clone(),
            client_nonce: self.id(),
            data_profiles: None,
        };
        self.request(Body::Hello(hello.clone())).await;
        let challenge_message = self.recv().await;
        let Body::Challenge(challenge) = &challenge_message.body else {
            panic!("expected CHALLENGE, got {:?}", challenge_message.body);
        };
        let auth = auth(keys, &hello, challenge, None).unwrap();
        self.request(Body::Auth(auth)).await;
        let ready = self.recv().await;
        assert!(matches!(ready.body, Body::Ready(_)), "{:?}", ready.body);
        (challenge_message, ready)
    }
}

/// The code of an ERROR or NACK.
pub fn code(message: &Message) -> u64 {
    match &message.body {
        Body::Error(e) | Body::Nack(e) => e.code,
        other => panic!("expected ERROR or NACK, got {other:?}"),
    }
}
