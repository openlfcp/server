//! The harness of the server fuzz targets: the server's own WebSocket
//! session (`lfcp_server::ws::serve` with `lfcp_server::session::Lfcp`) on
//! an in-memory duplex pipe instead of a socket, a store in a fresh
//! directory (on tmpfs when there is one), and a fingerprint of the store's
//! tables read through a separate read-only SQLite connection.
//!
//! The upgrade path mirrors `lfcp_server::server`'s `route`: hyper's HTTP/1
//! connection with upgrades, `ws::check_upgrade`, a `ConnectionContext`
//! with the configured limits, then `ws::serve`. Nothing listens on a port.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use lfcp::base::{Hash32, ResourceId};
use lfcp::principal::PrincipalKeys;
use lfcp::wire::control::body::{ControlBody, Endpoint, GenesisBody};
use lfcp::wire::control::{ControlRecord, ControlRecordHeader, ReceivedControlRecord};
use lfcp::wire::message::{Body, DecodeOptions, HelloBody, Message};
use lfcp::wire::session::{auth, WIRE_PROFILE};
use lfcp_server::config::Config;
use lfcp_server::identity::ServerId;
use lfcp_server::rng::Random;
use lfcp_server::session::Lfcp;
use lfcp_server::store::Store;
use lfcp_server::ws::{self, ConnectionContext, Limits};
use tokio::io::DuplexStream;
use tokio::sync::watch;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message as Frame;
use tokio_tungstenite::WebSocketStream;

/// Nonces, session IDs and message IDs from a counter: runs replay.
#[derive(Default)]
pub struct Counter(AtomicU64);

impl Random for Counter {
    fn fill(&self, bytes: &mut [u8]) -> Result<(), String> {
        let n = self.0.fetch_add(1, Ordering::SeqCst) + 1;
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (n >> ((i % 8) * 8)) as u8 ^ 0x5a;
        }
        Ok(())
    }
}

/// The session Principal (the owner of [`resource`]).
pub fn owner() -> PrincipalKeys {
    PrincipalKeys::from_secrets(&[1; 32], [2; 32])
}

/// A second Principal.
pub fn bob() -> PrincipalKeys {
    PrincipalKeys::from_secrets(&[3; 32], [4; 32])
}

/// The Resource the harness hosts.
pub fn resource() -> ResourceId {
    ResourceId::from_bytes([0x42; 32])
}

/// The Genesis of `resource`, owned by `owner`.
pub fn genesis(owner: &PrincipalKeys, resource: ResourceId) -> Vec<u8> {
    let url = "wss://sync.example.test/v1/ws".to_owned();
    ControlRecord::sign(
        ControlRecordHeader {
            resource_id: resource,
            sequence: 0,
            previous: None,
            issuer: *owner.descriptor().id(),
        },
        ControlBody::Genesis(GenesisBody {
            data_profile: "org.openlfcp.shared-objects.v1".into(),
            owner: owner.descriptor().clone(),
            dek_commitment: Hash32::from_bytes([3; 32]),
            endpoints: vec![Endpoint {
                url: url.clone(),
                priority: 0,
                flags: None,
            }],
            coordinator: url,
        }),
        owner,
    )
    .expect("a Genesis signs")
    .signed_object()
    .bytes()
    .to_vec()
}

/// The Control Record ID of a record's bytes.
pub fn record_id(record: &[u8]) -> Hash32 {
    Hash32::from_bytes(
        *ReceivedControlRecord::parse(record)
            .expect("a record")
            .id()
            .as_bytes(),
    )
}

/// The server configuration of a run: defaults, the abuse limits of the
/// server's tests (no free-disk floor), `state` as the state directory.
pub fn config(state: &Path) -> Config {
    Config {
        bind: "127.0.0.1:0".parse().expect("an address"),
        state_dir: state.to_owned(),
        // The coordinator URL of [`genesis`]: this server coordinates it.
        public_urls: vec!["wss://sync.example.test/v1/ws".to_owned()],
        abuse: lfcp_server::limits::AbuseLimits {
            min_free_bytes: 0,
            ..Default::default()
        },
        ..Config::default()
    }
}

/// The runtime every run shares.
pub fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("a runtime")
    })
}

/// A fresh, empty directory for one run, on tmpfs when /dev/shm exists.
pub fn fresh_dir() -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let base = if Path::new("/dev/shm").is_dir() {
        PathBuf::from("/dev/shm")
    } else {
        std::env::temp_dir()
    };
    let dir = base.join(format!(
        "lfcp-server-fuzz-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// A client connection to one server session over a duplex pipe.
pub struct Conn {
    pub ws: WebSocketStream<DuplexStream>,
    shutdown: watch::Sender<bool>,
    http: tokio::task::JoinHandle<()>,
}

/// The server side of one connection, as `server::route` builds it.
pub async fn connect(store: Arc<Store>, config: &Config) -> Conn {
    let (client_io, server_io) = tokio::io::duplex(1 << 20);
    let sessions = Lfcp::new(store, config).with_random(Arc::new(Counter::default()));
    let (shutdown, stopping) = watch::channel(false);
    let outbound = lfcp_server::budget::ByteBudget::server(config.max_total_outbound_bytes);
    let ips = lfcp_server::limits::IpTable::new(&config.abuse);
    let config = config.clone();
    let service = service_fn(move |request| {
        let sessions_open = lfcp_server::ws::SessionFactory::open;
        let response = match ws::check_upgrade(&request) {
            ws::Upgrade::Accept(response) => {
                let peer: SocketAddr = "127.0.0.1:40000".parse().expect("an address");
                let connection = ConnectionContext {
                    id: 1,
                    peer,
                    client: lfcp_server::limits::Client::new(peer.ip(), ips.clone()),
                    server_id: ServerId::from_bytes([7; 32]),
                    limits: Limits::new(config.max_message_bytes, config.heartbeat_ms)
                        .with_handshake_timeout(Duration::from_millis(config.handshake_timeout_ms))
                        .with_message_rate(lfcp_server::limits::Rate::new(
                            config.abuse.ws_messages_per_second,
                            Duration::from_secs(1),
                            config.abuse.ws_message_burst,
                        ))
                        .with_outbound(
                            config.max_outbound_bytes,
                            Duration::from_millis(config.write_timeout_ms),
                        ),
                    outbound: outbound.clone(),
                };
                let session = sessions_open(&sessions, &connection);
                let stop = stopping.clone();
                tokio::spawn(ws::serve(request, connection, session, stop));
                response
            }
            ws::Upgrade::Reject(rejection) => rejection,
        };
        async move { Ok::<_, std::convert::Infallible>(response) }
    });
    let http = tokio::spawn(async move {
        let _ = hyper::server::conn::http1::Builder::new()
            .timer(TokioTimer::new())
            .serve_connection(TokioIo::new(server_io), service)
            .with_upgrades()
            .await;
    });
    let mut request = "ws://fuzz.test/v1/ws"
        .into_client_request()
        .expect("a request");
    request.headers_mut().insert(
        "sec-websocket-protocol",
        "lfcp-1".parse().expect("a header"),
    );
    let (ws, _) = tokio_tungstenite::client_async(request, client_io)
        .await
        .expect("the upgrade over the pipe");
    Conn { ws, shutdown, http }
}

/// What the server sent after a request.
#[derive(Debug, PartialEq, Eq)]
pub enum Reply {
    /// The messages up to and including the one correlated to the request.
    Answered(Vec<Message>),
    /// The connection closed first (with what came before).
    Closed(Vec<Message>),
    /// Nothing correlated within the wait (with what came).
    Silent(Vec<Message>),
}

impl Conn {
    pub async fn send_binary(&mut self, bytes: Vec<u8>) -> bool {
        self.ws.send(Frame::Binary(bytes.into())).await.is_ok()
    }

    pub async fn send_text(&mut self, text: String) -> bool {
        self.ws.send(Frame::Text(text.into())).await.is_ok()
    }

    /// Read messages until one correlates to `id`, the connection closes,
    /// or `wait` passes without one.
    pub async fn reply(&mut self, id: Option<[u8; 16]>, wait: Duration) -> Reply {
        let mut got = Vec::new();
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let next = tokio::time::timeout_at(deadline, self.ws.next()).await;
            match next {
                Err(_) => return Reply::Silent(got),
                Ok(None | Some(Err(_)) | Some(Ok(Frame::Close(_)))) => return Reply::Closed(got),
                Ok(Some(Ok(Frame::Binary(bytes)))) => {
                    let Ok(m) = Message::decode(&bytes, &DecodeOptions::default()) else {
                        panic!("the server sent bytes that do not decode as a message");
                    };
                    let answers = id.is_some() && m.correlation_id == id;
                    got.push(m);
                    if answers {
                        return Reply::Answered(got);
                    }
                }
                Ok(Some(Ok(_))) => {}
            }
        }
    }

    /// HELLO, CHALLENGE, AUTH, READY as `keys`; false if any step fails.
    pub async fn handshake(&mut self, keys: &PrincipalKeys) -> bool {
        let hello = HelloBody {
            wire_profiles: vec![WIRE_PROFILE.into()],
            principal: keys.descriptor().clone(),
            client_nonce: [0xc1; 16],
            data_profiles: None,
        };
        let id = [0xa1; 16];
        if !self
            .send_binary(Message::new(id, Body::Hello(hello.clone())).encode())
            .await
        {
            return false;
        }
        let Reply::Answered(got) = self.reply(Some(id), Duration::from_secs(5)).await else {
            return false;
        };
        let Some(Body::Challenge(challenge)) = got.last().map(|m| &m.body) else {
            return false;
        };
        let Ok(proof) = auth(keys, &hello, challenge, None) else {
            return false;
        };
        let id = [0xa2; 16];
        self.send_binary(Message::new(id, Body::Auth(proof)).encode())
            .await
            && matches!(
                self.reply(Some(id), Duration::from_secs(5)).await,
                Reply::Answered(m) if matches!(m.last().map(|m| &m.body), Some(Body::Ready(_)))
            )
    }

    /// Close the connection and wait for the server side to end.
    pub async fn close(mut self) {
        let _ = self.ws.close(None).await;
        let _ = self.shutdown.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(5), &mut self.http).await;
    }
}

/// A fingerprint of every row of every table of the store's database,
/// read through a separate read-only connection (WAL readers see the
/// committed state).
pub fn fingerprint(db: &Path) -> u64 {
    use rusqlite::{Connection, OpenFlags};
    let conn = Connection::open_with_flags(
        db,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("the store's database opens read-only");
    let mut tables: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
        .and_then(|mut s| {
            s.query_map([], |r| r.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()
        })
        .expect("the table list");
    tables.sort();
    let mut hasher = DefaultHasher::new();
    for table in tables {
        let mut stmt = conn
            .prepare(&format!("SELECT * FROM \"{table}\""))
            .expect("a select");
        let n = stmt.column_count();
        let mut rows: Vec<Vec<String>> = stmt
            .query_map([], |r| {
                (0..n)
                    .map(|i| r.get_ref(i).map(|v| format!("{v:?}")))
                    .collect::<Result<Vec<_>, _>>()
            })
            .and_then(|rows| rows.collect::<Result<Vec<_>, _>>())
            .expect("the rows");
        rows.sort();
        (table, rows).hash(&mut hasher);
    }
    hasher.finish()
}
