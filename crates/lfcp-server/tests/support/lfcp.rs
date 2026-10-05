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
}

impl Default for Options {
    fn default() -> Options {
        Options {
            identity: None,
            random: Arc::new(Script::default()),
            hosting: None,
            public_urls: Vec::new(),
            ingest: None,
        }
    }
}

pub struct Running {
    pub addr: SocketAddr,
    pub store: Arc<Store>,
    pub server_id: ServerId,
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
    let config = Config {
        bind: "127.0.0.1:0".parse().unwrap(),
        state_dir: state.to_owned(),
        public_urls: options.public_urls,
        ..Config::default()
    };
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
    let mut sessions = Lfcp::new(store.clone(), &config).with_random(options.random);
    if let Some(hosting) = options.hosting {
        sessions = sessions.with_hosting(hosting);
    }
    if let Some(ingest) = options.ingest {
        sessions = sessions.with_ingest(ingest);
    }
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(server.run(sessions, async {
        let _ = stopped.await;
    }));
    Running {
        addr,
        store,
        server_id,
        stop: Some(stop),
        task,
    }
}

pub struct Client {
    socket: WebSocketStream<TcpStream>,
    next_id: u8,
}

impl Client {
    pub async fn connect(addr: SocketAddr) -> Client {
        let mut request = format!("ws://{addr}/v1/ws").into_client_request().unwrap();
        request
            .headers_mut()
            .insert("sec-websocket-protocol", "lfcp-1".parse().unwrap());
        let stream = TcpStream::connect(addr).await.unwrap();
        let (socket, _) = tokio_tungstenite::client_async(request, stream)
            .await
            .expect("handshake");
        Client { socket, next_id: 0 }
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
