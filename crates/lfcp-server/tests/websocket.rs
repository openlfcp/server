//! The WebSocket transport over real TCP: subprotocol negotiation, binary
//! round trips through the session hook, text and oversized frames, PING
//! before READY, malformed messages, shutdown draining, backpressure, idle
//! timeout and cleanup.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use lfcp::wire::message::{Body, DecodeOptions, Message};
use lfcp_server::config::Config;
use lfcp_server::identity::FileIdentity;
use lfcp_server::server::Server;
use lfcp_server::store::Store;
use lfcp_server::ws::{ConnectionContext, Flow, Outbound, PingOnly, Session, SessionFactory};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::Message as Frame;
use tokio_tungstenite::WebSocketStream;

type Client = WebSocketStream<TcpStream>;

struct Running {
    addr: SocketAddr,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
    state: std::path::PathBuf,
}

impl Running {
    async fn stop(mut self) {
        let _ = self.stop.take().unwrap().send(());
        tokio::time::timeout(Duration::from_secs(12), &mut self.task)
            .await
            .expect("shut down in time")
            .unwrap();
        std::fs::remove_dir_all(&self.state).unwrap();
    }
}

async fn start<F: SessionFactory>(name: &str, sessions: F, heartbeat_ms: u64) -> Running {
    let state = std::env::temp_dir().join(format!("lfcp-ws-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&state);
    let config = Config {
        bind: "127.0.0.1:0".parse().unwrap(),
        state_dir: state.clone(),
        max_message_bytes: lfcp_server::config::MIN_MESSAGE_BYTES,
        heartbeat_ms,
        ..Config::default()
    };
    let identity = Arc::new(FileIdentity::load_or_create(&state).unwrap());
    let store = Arc::new(Store::open(&state).unwrap());
    let server = Server::bind(config, identity, store).await.unwrap();
    let addr = server.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(server.run(sessions, async {
        let _ = stopped.await;
    }));
    Running {
        addr,
        stop: Some(stop),
        task,
        state,
    }
}

/// Connect, offering `protocol` (or none).
async fn connect(
    addr: SocketAddr,
    protocol: Option<&str>,
) -> Result<(Client, Option<String>), String> {
    let mut request = format!("ws://{addr}/v1/ws").into_client_request().unwrap();
    if let Some(protocol) = protocol {
        request
            .headers_mut()
            .insert("sec-websocket-protocol", protocol.parse().unwrap());
    }
    let stream = TcpStream::connect(addr).await.unwrap();
    match tokio_tungstenite::client_async(request, stream).await {
        Ok((client, response)) => {
            let selected = response
                .headers()
                .get("sec-websocket-protocol")
                .map(|v| v.to_str().unwrap().to_owned());
            Ok((client, selected))
        }
        Err(error) => Err(error.to_string()),
    }
}

async fn lfcp(addr: SocketAddr) -> Client {
    let (client, selected) = connect(addr, Some("lfcp-1")).await.expect("handshake");
    assert_eq!(selected.as_deref(), Some("lfcp-1"));
    client
}

fn ping(id: u8) -> Message {
    Message::new([id; 16], Body::Ping([id; 8]))
}

/// The next frame, with a timeout.
async fn next(client: &mut Client) -> Option<Frame> {
    tokio::time::timeout(Duration::from_secs(5), client.next())
        .await
        .expect("a frame in time")
        .map(|r| r.expect("frame"))
}

async fn next_message(client: &mut Client) -> Message {
    match next(client).await {
        Some(Frame::Binary(bytes)) => {
            Message::decode(&bytes, &DecodeOptions::default()).expect("decodes")
        }
        other => panic!("expected a binary LFCP message, got {other:?}"),
    }
}

fn error_code(message: &Message) -> u64 {
    match &message.body {
        Body::Error(e) => e.code,
        other => panic!("expected ERROR, got {other:?}"),
    }
}

async fn expect_close(client: &mut Client, code: CloseCode) {
    loop {
        match next(client).await {
            Some(Frame::Close(Some(frame))) => {
                assert_eq!(frame.code, code);
                return;
            }
            Some(Frame::Close(None)) | None => panic!("closed without the expected code {code:?}"),
            Some(_) => continue,
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_lfcp_1_subprotocol_is_required() {
    let server = start("subprotocol", PingOnly, 0).await;
    let without = connect(server.addr, None).await.unwrap_err();
    assert!(without.contains("400"), "{without}");
    let wrong = connect(server.addr, Some("chat")).await.unwrap_err();
    assert!(wrong.contains("400"), "{wrong}");
    let (_client, selected) = connect(server.addr, Some("chat, lfcp-1")).await.unwrap();
    assert_eq!(selected.as_deref(), Some("lfcp-1"));
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn ping_is_answered_before_ready() {
    // G-SM4: PING is allowed before READY; the stub session answers it.
    let server = start("ping", PingOnly, 0).await;
    let mut client = lfcp(server.addr).await;
    client
        .send(Frame::Binary(ping(7).encode().into()))
        .await
        .unwrap();
    let pong = next_message(&mut client).await;
    assert_eq!(pong.body, Body::Pong([7; 8]));
    assert_eq!(pong.correlation_id, Some([7; 16]));
    server.stop().await;
}

/// A session that echoes every message back and counts closes.
#[derive(Clone, Default)]
struct Echo {
    closed: Arc<AtomicUsize>,
}

impl Session for Echo {
    async fn handle(&mut self, message: Message, out: &Outbound) -> Flow {
        match out.send(message) {
            Ok(()) => Flow::Continue,
            Err(_) => Flow::Close,
        }
    }
    fn closed(&mut self) {
        self.closed.fetch_add(1, Ordering::SeqCst);
    }
}

impl SessionFactory for Echo {
    type Session = Echo;
    fn open(&self, _: &ConnectionContext) -> Echo {
        self.clone()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn binary_messages_round_trip_through_the_session_hook() {
    let echo = Echo::default();
    let server = start("echo", echo.clone(), 0).await;
    let mut client = lfcp(server.addr).await;
    // Anything decodable reaches the hook unchanged.
    for message in [ping(1), ping(2)] {
        client
            .send(Frame::Binary(message.encode().into()))
            .await
            .unwrap();
        assert_eq!(next_message(&mut client).await, message);
    }
    // Cleanup: closing the socket ends the session.
    client.close(None).await.unwrap();
    for _ in 0..50 {
        if echo.closed.load(Ordering::SeqCst) == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(echo.closed.load(Ordering::SeqCst), 1, "session closed");
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn text_frames_are_malformed_and_close() {
    // §31, G-MSG7: ERROR(MALFORMED_MESSAGE), then close.
    let server = start("text", PingOnly, 0).await;
    let mut client = lfcp(server.addr).await;
    client
        .send(Frame::Text("{\"type\":\"ping\"}".into()))
        .await
        .unwrap();
    assert_eq!(error_code(&next_message(&mut client).await), 2);
    expect_close(&mut client, CloseCode::Protocol).await;
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn oversized_messages_are_rejected_before_decoding() {
    // §31: the limit (64 KiB here) is checked from the frame header; the
    // payload is not decoded.
    let server = start("oversize", PingOnly, 0).await;
    let mut client = lfcp(server.addr).await;
    let too_big = vec![0xa5u8; lfcp_server::config::MIN_MESSAGE_BYTES + 1];
    client.send(Frame::Binary(too_big.into())).await.unwrap();
    assert_eq!(
        error_code(&next_message(&mut client).await),
        19,
        "MESSAGE_TOO_LARGE"
    );
    expect_close(&mut client, CloseCode::Size).await;
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn undecodable_messages_get_an_error_and_the_connection_stays_open() {
    let server = start("malformed", PingOnly, 0).await;
    let mut client = lfcp(server.addr).await;
    // Not CBOR at all.
    client
        .send(Frame::Binary(vec![0xff, 0x00].into()))
        .await
        .unwrap();
    assert_eq!(
        error_code(&next_message(&mut client).await),
        2,
        "MALFORMED_MESSAGE"
    );
    // An unassigned message type (G-MSG1): the PING with type 7.
    let mut bytes = ping(3).encode();
    assert_eq!(&bytes[..3], &[0xa3, 0x00, 0x05]);
    bytes[2] = 0x07;
    client.send(Frame::Binary(bytes.into())).await.unwrap();
    assert_eq!(
        error_code(&next_message(&mut client).await),
        1,
        "PROTOCOL_UNSUPPORTED"
    );
    // Still usable.
    client
        .send(Frame::Binary(ping(4).encode().into()))
        .await
        .unwrap();
    assert_eq!(next_message(&mut client).await.body, Body::Pong([4; 8]));
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn shutdown_drains_open_websockets() {
    let echo = Echo::default();
    let server = start("drain", echo.clone(), 0).await;
    let mut first = lfcp(server.addr).await;
    let mut second = lfcp(server.addr).await;
    let addr = server.addr;
    let stopping = tokio::spawn(server.stop());
    expect_close(&mut first, CloseCode::Away).await;
    expect_close(&mut second, CloseCode::Away).await;
    drop((first, second));
    stopping.await.unwrap();
    assert_eq!(echo.closed.load(Ordering::SeqCst), 2);
    assert!(
        TcpStream::connect(addr).await.is_err(),
        "no longer listening"
    );
}

/// A session that answers every message with far more messages than the
/// outbound queue holds, and records whether it was told to stop.
#[derive(Clone, Default)]
struct Flood {
    overloaded: Arc<AtomicUsize>,
    closed: Arc<AtomicUsize>,
}

impl Session for Flood {
    async fn handle(&mut self, message: Message, out: &Outbound) -> Flow {
        for _ in 0..10_000 {
            if out.send(message.clone()).is_err() {
                self.overloaded.fetch_add(1, Ordering::SeqCst);
                return Flow::Close;
            }
        }
        Flow::Continue
    }
    fn closed(&mut self) {
        self.closed.fetch_add(1, Ordering::SeqCst);
    }
}

impl SessionFactory for Flood {
    type Session = Flood;
    fn open(&self, _: &ConnectionContext) -> Flood {
        self.clone()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_slow_reader_is_disconnected_not_buffered() {
    let flood = Flood::default();
    let server = start("backpressure", flood.clone(), 0).await;
    let mut client = lfcp(server.addr).await;
    client
        .send(Frame::Binary(ping(5).encode().into()))
        .await
        .unwrap();
    // The client reads nothing; the bounded queue fills and the session is
    // told, so the connection ends instead of growing a buffer.
    for _ in 0..100 {
        if flood.closed.load(Ordering::SeqCst) == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(flood.overloaded.load(Ordering::SeqCst), 1);
    assert_eq!(flood.closed.load(Ordering::SeqCst), 1);
    drop(client);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_silent_connection_is_closed_after_three_heartbeats() {
    // §37: heartbeat 1 s, so idle timeout 3 s.
    let server = start("idle", PingOnly, 1000).await;
    let mut client = lfcp(server.addr).await;
    let started = std::time::Instant::now();
    let frame = tokio::time::timeout(Duration::from_secs(6), client.next())
        .await
        .expect("closed in time");
    match frame {
        Some(Ok(Frame::Close(Some(close)))) => assert_eq!(close.code, CloseCode::Away),
        other => panic!("expected an idle close, got {other:?}"),
    }
    assert!(started.elapsed() >= Duration::from_millis(2900));
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn only_lfcp_messages_count_as_liveness() {
    // Heartbeat 1 s, idle timeout 3 s.
    let server = start("liveness", PingOnly, 1000).await;

    // WebSocket-level pings do not keep a connection open.
    let mut client = lfcp(server.addr).await;
    let started = std::time::Instant::now();
    let closed = loop {
        tokio::select! {
            frame = client.next() => match frame {
                Some(Ok(Frame::Pong(_))) => continue,
                other => break other,
            },
            () = tokio::time::sleep(Duration::from_millis(500)) => {
                client.send(Frame::Ping(vec![1].into())).await.unwrap();
            }
        }
    };
    match closed {
        Some(Ok(Frame::Close(Some(close)))) => assert_eq!(close.code, CloseCode::Away),
        other => panic!("expected an idle close, got {other:?}"),
    }
    assert!(started.elapsed() >= Duration::from_millis(2900));
    assert!(started.elapsed() < Duration::from_secs(5));

    // LFCP PINGs do.
    let mut client = lfcp(server.addr).await;
    for n in 0..5u8 {
        tokio::time::sleep(Duration::from_millis(900)).await;
        client
            .send(Frame::Binary(ping(n).encode().into()))
            .await
            .unwrap();
        assert_eq!(next_message(&mut client).await.body, Body::Pong([n; 8]));
    }
    server.stop().await;
}
