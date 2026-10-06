//! The LFCP WebSocket transport (WIRE-01 §30, §31): framing only.
//!
//! | Rule | Behaviour | § |
//! | --- | --- | --- |
//! | subprotocol | the upgrade must offer `lfcp-1`; otherwise HTTP 400, no WebSocket | §30 |
//! | binary only | a text message is `ERROR(MALFORMED_MESSAGE)`, then close | §31, G-MSG7 |
//! | one message per WebSocket message | each binary message is decoded with sdk-rs's codec | §31, §32 |
//! | size limit | checked from the frame header before the payload is read; `ERROR(MESSAGE_TOO_LARGE)`, then close (the unread payload leaves the stream unusable) | §31 |
//! | undecodable message | handed to [`Session::rejected`]; by default `ERROR` with the error's code, closing only for errors that §31/§34/§64 make fatal | §31–§33 |
//!
//! Everything else is the session's: each decoded message goes to a
//! per-connection [`Session`] ([`crate::session`] is the LFCP one), which
//! answers through a bounded [`Outbound`] queue. The transport keeps no
//! application data and logs connection IDs and message types, never
//! payloads.
//!
//! Limits: a slow reader cannot grow memory without bound. Inbound
//! messages are handled one at a time. Outbound messages are queued encoded,
//! and each holds a [`Reservation`] of its size from the connection's
//! [`Limits::max_outbound_bytes`] and from the server-wide budget
//! ([`ConnectionContext::outbound`]), released once it is written
//! ([`crate::budget`], security review H6). [`Outbound::send`] never waits:
//! a live push that does not fit gets [`Overloaded`] and closes its
//! subscriber. [`Outbound::send_wait`] and [`Outbound::reserve`] wait for
//! room, so a session's replies and GET pages are paced by the peer's
//! reading (backpressure). The queue also holds at most
//! [`Limits::outbound_queue`] messages. A write that does not finish within
//! [`Limits::write_timeout`] ends the connection: the queue is dropped, its
//! reservations are released, and a waiting session gets [`Overloaded`], so
//! a peer that stops reading is closed and its memory freed after that
//! timeout. At shutdown a waiting session is released the same way. A connection with no inbound
//! LFCP message for [`Limits::idle_timeout`] (three READY heartbeat
//! intervals, §37) is closed. Only LFCP messages (an LFCP `PING` included)
//! count as liveness; WebSocket-level ping and pong frames do not.
//!
//! Before the session is ready ([`Session::is_ready`]: READY sent, §37)
//! the peer is unauthenticated, so the transport is stricter (security
//! review M2, M5): the connection must become ready within
//! [`Limits::handshake_timeout`] of opening, whatever it sends meanwhile
//! (an LFCP `PING` does not extend it), else it is closed (1008); at most
//! [`Limits::pre_ready_messages`] messages are read, the next gets
//! `ERROR(RATE_LIMITED)` and close 1008; and a message over
//! [`Limits::pre_ready_message_bytes`] gets `ERROR(MESSAGE_TOO_LARGE)` and
//! close 1009 without being decoded.
//!
//! After READY too, a connection may send at most
//! [`Limits::message_rate`] messages (a token bucket, POST-003): the next
//! one gets `ERROR(RATE_LIMITED)` with a diagnostic and close 1008.
//!
//! Closing (lingering close): when the server closes, unread bytes from the
//! peer may still be on their way or in the socket's receive buffer (e.g.
//! the rest of an oversized message). Closing a TCP socket with unread data
//! makes the kernel send RST (always on Linux), and a RST makes the peer
//! discard the ERROR and close frame it has not read yet, so it would never
//! learn why it was dropped. So after the close frame is flushed, the
//! write half is shut down (FIN: the peer reads every frame, then EOF), and
//! incoming bytes are read and discarded until the peer's EOF, for at most
//! [`Limits::linger_timeout`] and [`Limits::linger_bytes`], or until the
//! server shuts down; only then is the socket dropped. A peer that keeps
//! sending past those bounds can still get a RST: the bound keeps a
//! closing connection from holding its slot indefinitely.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::header::{HeaderMap, HeaderValue};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use lfcp::base::Error;
use lfcp::wire::message::{Body, DecodeOptions, ErrorBody, FrameKind, Message};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, watch, Notify};
use tokio_tungstenite::tungstenite::error::{CapacityError, Error as WsError};
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, Role, WebSocketConfig};
use tokio_tungstenite::tungstenite::Message as Frame;
use tokio_tungstenite::WebSocketStream;

use crate::budget::{Budgets, ByteBudget, Reservation};
use crate::identity::ServerId;
use crate::rng;

/// The LFCP WebSocket subprotocol (§30).
pub const SUBPROTOCOL: &str = "lfcp-1";

/// The diagnostic of the `ERROR(RATE_LIMITED)` past
/// [`Limits::message_rate`].
pub const RATE_LIMIT_DIAGNOSTIC: &str = "message rate limit exceeded";

/// Per-connection transport limits.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Limits {
    /// The maximum LFCP message size (§31, advertised in READY §37).
    pub max_message_bytes: usize,
    /// Outbound messages that may wait for the socket.
    pub outbound_queue: usize,
    /// Outbound bytes the connection may hold: queued messages and GET
    /// pages being built.
    pub max_outbound_bytes: usize,
    /// Close a connection with no inbound LFCP message for this long.
    pub idle_timeout: Option<Duration>,
    /// Close a connection whose socket does not take a message this fast.
    pub write_timeout: Duration,
    /// How long a closing connection may take to flush and close.
    pub close_timeout: Duration,
    /// Close a connection that is not ready this long after opening.
    pub handshake_timeout: Duration,
    /// The most messages read before the session is ready.
    pub pre_ready_messages: usize,
    /// The largest message decoded before the session is ready.
    pub pre_ready_message_bytes: usize,
    /// How long a closing connection reads and discards the peer's bytes
    /// before the socket is dropped (lingering close).
    pub linger_timeout: Duration,
    /// How many bytes a closing connection reads and discards at most.
    pub linger_bytes: usize,
    /// Messages per second and burst a connection may send; `None` is no
    /// limit (POST-003).
    pub message_rate: Option<crate::limits::Rate>,
}

impl Limits {
    /// The limits for a configured message size and READY heartbeat
    /// interval in milliseconds (0 disables the idle timeout).
    pub fn new(max_message_bytes: usize, heartbeat_ms: u64) -> Limits {
        Limits {
            max_message_bytes,
            outbound_queue: 256,
            max_outbound_bytes: max_message_bytes.saturating_mul(4),
            idle_timeout: (heartbeat_ms > 0)
                .then(|| Duration::from_millis(heartbeat_ms.saturating_mul(3))),
            write_timeout: Duration::from_secs(10),
            close_timeout: Duration::from_secs(5),
            handshake_timeout: Duration::from_secs(10),
            pre_ready_messages: 16,
            pre_ready_message_bytes: 64 * 1024,
            linger_timeout: Duration::from_secs(2),
            linger_bytes: max_message_bytes.saturating_add(64 * 1024),
            message_rate: None,
        }
    }

    /// The same limits with another message rate.
    pub fn with_message_rate(mut self, rate: Option<crate::limits::Rate>) -> Limits {
        self.message_rate = rate;
        self
    }

    /// The same limits with another handshake deadline.
    pub fn with_handshake_timeout(mut self, timeout: Duration) -> Limits {
        self.handshake_timeout = timeout;
        self
    }

    /// The same limits with another outbound byte cap and write timeout.
    pub fn with_outbound(mut self, max_outbound_bytes: usize, write_timeout: Duration) -> Limits {
        self.max_outbound_bytes = max_outbound_bytes;
        self.write_timeout = write_timeout;
        self
    }
}

/// What the transport knows about a connection, for its session.
#[derive(Clone, Debug)]
pub struct ConnectionContext {
    /// A process-local connection number, for logs.
    pub id: u64,
    /// The peer address.
    pub peer: SocketAddr,
    /// The client: the peer, or the address a trusted proxy reported
    /// (POST-003, [`crate::limits::Proxies`]).
    pub client: crate::limits::Client,
    /// The server ID (§35, §37).
    pub server_id: ServerId,
    /// The transport limits.
    pub limits: Limits,
    /// The server-wide outbound byte budget every connection draws on.
    pub outbound: Arc<ByteBudget>,
}

/// Whether the connection continues after a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flow {
    /// Keep reading.
    Continue,
    /// Close the connection (after the queued messages).
    Close,
}

/// The outbound queue is full: the peer reads too slowly. The session
/// should return [`Flow::Close`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Overloaded;

/// A handle for sending messages on a connection: the session's own, or a
/// clone held elsewhere for live pushes.
#[derive(Clone, Debug)]
pub struct Outbound {
    queue: mpsc::Sender<Out>,
    abort: Arc<Abort>,
    budgets: Budgets,
}

#[derive(Debug, Default)]
struct Abort {
    requested: AtomicBool,
    notify: Notify,
}

impl Outbound {
    fn new(queue: mpsc::Sender<Out>, budgets: Budgets) -> Outbound {
        Outbound {
            queue,
            abort: Arc::default(),
            budgets,
        }
    }

    /// Queue a message without waiting: [`Overloaded`] when its bytes do
    /// not fit the budgets or the queue is full.
    pub fn send(&self, message: Message) -> Result<(), Overloaded> {
        let bytes = message.encode();
        let reservation = self.budgets.try_reserve(bytes.len()).ok_or(Overloaded)?;
        self.queue
            .try_send(Out::Lfcp(bytes, reservation))
            .map_err(|_| Overloaded)
    }

    /// Queue a message, waiting for room in the budgets and the queue;
    /// [`Overloaded`] once the connection is closing.
    pub async fn send_wait(&self, message: Message) -> Result<(), Overloaded> {
        let bytes = message.encode();
        drop(message);
        let reservation = self.reserve(bytes.len()).await?;
        self.send_reserved(bytes, reservation).await
    }

    /// Reserve `bytes` of the budgets, waiting for room, before building
    /// a message of at most that size; [`Overloaded`] once the connection
    /// is closing.
    pub async fn reserve(&self, bytes: usize) -> Result<Reservation, Overloaded> {
        self.budgets.reserve(bytes).await.ok_or(Overloaded)
    }

    /// Queue an encoded message under `reservation`, waiting for a place in
    /// the queue. The reservation shrinks to the message's size; if it is
    /// too small, it is released and the size reserved again.
    pub async fn send_reserved(
        &self,
        bytes: Vec<u8>,
        mut reservation: Reservation,
    ) -> Result<(), Overloaded> {
        if reservation.bytes() < bytes.len() {
            drop(reservation);
            reservation = self.reserve(bytes.len()).await?;
        }
        reservation.shrink_to(bytes.len());
        self.queue
            .send(Out::Lfcp(bytes, reservation))
            .await
            .map_err(|_| Overloaded)
    }

    /// The bytes this connection holds now (queued, being written, or
    /// reserved for a message being built).
    pub fn buffered_bytes(&self) -> usize {
        self.budgets.connection().used()
    }

    /// The most bytes this connection has held at once.
    pub fn peak_bytes(&self) -> usize {
        self.budgets.connection().peak()
    }

    /// Close the connection from outside its session, for example when a
    /// live push finds its queue full: the transport closes it with 1013
    /// (try again later) instead of silently dropping messages.
    pub fn abort(&self) {
        self.abort.requested.store(true, Ordering::SeqCst);
        self.abort.notify.notify_one();
        self.budgets.halt();
    }

    /// Whether [`Outbound::abort`] was called.
    pub fn is_aborted(&self) -> bool {
        self.abort.requested.load(Ordering::SeqCst)
    }
}

/// A queued item: an encoded LFCP message with the bytes it holds, or the
/// close frame.
#[derive(Debug)]
pub(crate) enum Out {
    Lfcp(Vec<u8>, Reservation),
    Close(CloseFrame),
}

/// An [`Outbound`] whose messages a unit test reads back, with budgets of
/// `bytes`.
#[cfg(test)]
pub(crate) fn test_outbound_bytes(
    capacity: usize,
    bytes: usize,
) -> (Outbound, mpsc::Receiver<Out>) {
    let (queue, inbox) = mpsc::channel(capacity);
    let budgets = Budgets::new(bytes, ByteBudget::new(bytes));
    (Outbound::new(queue, budgets), inbox)
}

/// An [`Outbound`] whose messages a unit test reads back.
#[cfg(test)]
pub(crate) fn test_outbound(capacity: usize) -> (Outbound, mpsc::Receiver<Out>) {
    test_outbound_bytes(capacity, 1 << 30)
}

#[cfg(test)]
impl Out {
    /// The LFCP message, if this is one.
    pub(crate) fn into_message(self) -> Option<Message> {
        match self {
            Out::Lfcp(bytes, _) => {
                let options = DecodeOptions {
                    max_message_bytes: usize::MAX,
                    ..DecodeOptions::default()
                };
                Some(Message::decode_frame(FrameKind::Binary, &bytes, &options).unwrap())
            }
            Out::Close(_) => None,
        }
    }
}

/// The per-connection protocol logic the transport hands messages to.
pub trait Session: Send + 'static {
    /// Handle one decoded message.
    fn handle(&mut self, message: Message, out: &Outbound) -> impl Future<Output = Flow> + Send;
    /// A WebSocket message that did not decode (a text frame included).
    /// By default: `ERROR` with the error's wire code, closing the
    /// connection when the error is fatal (§31, §34). A session overrides
    /// this where its state changes the code or the outcome, such as a
    /// malformed descriptor in `HELLO` (`AUTH_FAILED`, §7).
    fn rejected(&mut self, error: Error, out: &Outbound) -> Flow {
        if let Some(message) = error_message(&error) {
            let _ = out.send(message);
        }
        if error.closes_connection() {
            Flow::Close
        } else {
            Flow::Continue
        }
    }
    /// The connection has ended; release whatever the session holds.
    fn closed(&mut self) {}
    /// Whether the handshake is complete (READY sent, §37). Until then the
    /// transport applies the handshake deadline and the pre-READY limits.
    /// By default a session needs no handshake.
    fn is_ready(&self) -> bool {
        true
    }
}

/// Creates a session for each new connection.
pub trait SessionFactory: Send + Sync + 'static {
    /// The session type.
    type Session: Session;
    /// A session for a newly upgraded connection.
    fn open(&self, connection: &ConnectionContext) -> Self::Session;
}

/// A transport-only session: answers PING with PONG (allowed before READY,
/// G-SM4) and ignores everything else. The server runs
/// [`crate::session::Lfcp`]; this one serves transport tests.
#[derive(Clone, Copy, Debug, Default)]
pub struct PingOnly;

impl Session for PingOnly {
    async fn handle(&mut self, message: Message, out: &Outbound) -> Flow {
        let Body::Ping(payload) = message.body else {
            return Flow::Continue;
        };
        let Ok(id) = rng::nonce16() else {
            return Flow::Close;
        };
        let mut pong = Message::new(id, Body::Pong(payload));
        pong.correlation_id = Some(message.message_id);
        match out.send(pong) {
            Ok(()) => Flow::Continue,
            Err(Overloaded) => Flow::Close,
        }
    }
}

impl SessionFactory for PingOnly {
    type Session = PingOnly;
    fn open(&self, _: &ConnectionContext) -> PingOnly {
        PingOnly
    }
}

fn header_has_token(headers: &HeaderMap, name: &str, token: &str) -> bool {
    headers.get_all(name).iter().any(|value| {
        value
            .to_str()
            .map(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case(token)))
            .unwrap_or(false)
    })
}

fn reject(status: StatusCode, reason: &'static str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain")
        .body(Full::new(Bytes::from_static(reason.as_bytes())))
        .expect("a static response is valid")
}

/// The answer to a WebSocket upgrade request.
#[derive(Debug)]
pub enum Upgrade {
    /// The 101 response selecting `lfcp-1`; the connection upgrades.
    Accept(Response<Full<Bytes>>),
    /// The rejection to send instead.
    Reject(Response<Full<Bytes>>),
}

/// Check a WebSocket upgrade request (RFC 6455 §4.2.1, WIRE-01 §30).
pub fn check_upgrade<B>(request: &Request<B>) -> Upgrade {
    let headers = request.headers();
    if request.method() != hyper::Method::GET
        || !header_has_token(headers, "upgrade", "websocket")
        || !header_has_token(headers, "connection", "upgrade")
    {
        return Upgrade::Reject(reject(
            StatusCode::BAD_REQUEST,
            "WebSocket upgrade required\n",
        ));
    }
    if headers
        .get("sec-websocket-version")
        .map(HeaderValue::as_bytes)
        != Some(b"13")
    {
        let mut response = reject(
            StatusCode::UPGRADE_REQUIRED,
            "WebSocket version 13 required\n",
        );
        response
            .headers_mut()
            .insert("sec-websocket-version", HeaderValue::from_static("13"));
        return Upgrade::Reject(response);
    }
    let Some(key) = headers.get("sec-websocket-key") else {
        return Upgrade::Reject(reject(
            StatusCode::BAD_REQUEST,
            "Sec-WebSocket-Key missing\n",
        ));
    };
    if !header_has_token(headers, "sec-websocket-protocol", SUBPROTOCOL) {
        return Upgrade::Reject(reject(
            StatusCode::BAD_REQUEST,
            "the lfcp-1 subprotocol is required\n",
        ));
    }
    let accept = derive_accept_key(key.as_bytes());
    Upgrade::Accept(
        Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header("connection", "upgrade")
            .header("upgrade", "websocket")
            .header("sec-websocket-accept", accept)
            .header("sec-websocket-protocol", SUBPROTOCOL)
            .body(Full::new(Bytes::new()))
            .expect("a valid 101 response"),
    )
}

/// An ERROR message with `code` alone (§61).
fn code_message(code: lfcp::base::WireCode) -> Option<Message> {
    diagnostic_message(code, None)
}

/// An ERROR message with `code` and an optional diagnostic (§61).
fn diagnostic_message(code: lfcp::base::WireCode, diagnostic: Option<&str>) -> Option<Message> {
    let body = ErrorBody {
        code: code.number(),
        diagnostic: diagnostic.map(str::to_owned),
        details: None,
    };
    Some(Message::new(rng::nonce16().ok()?, Body::Error(body)))
}

/// An ERROR message for `error` (§61), if it has a wire code.
fn error_message(error: &Error) -> Option<Message> {
    let body = ErrorBody::for_error(error)?;
    Some(Message::new(rng::nonce16().ok()?, Body::Error(body)))
}

/// Serve one upgraded WebSocket connection until it closes, the session
/// ends it, or `shutdown` turns true.
pub async fn serve<S: Session>(
    request: Request<Incoming>,
    connection: ConnectionContext,
    mut session: S,
    mut shutdown: watch::Receiver<bool>,
) {
    let id = connection.id;
    let limits = connection.limits;
    let upgraded = match hyper::upgrade::on(request).await {
        Ok(upgraded) => upgraded,
        Err(error) => {
            tracing::debug!(conn = id, %error, "upgrade failed");
            return;
        }
    };
    // The frame and message caps make tungstenite reject an oversized
    // message from its frame header, before buffering the payload.
    let config = WebSocketConfig::default()
        .max_message_size(Some(limits.max_message_bytes))
        .max_frame_size(Some(limits.max_message_bytes));
    let socket =
        WebSocketStream::from_raw_socket(TokioIo::new(upgraded), Role::Server, Some(config)).await;
    let (mut sink, mut stream) = socket.split();
    tracing::info!(conn = id, peer = %connection.peer, client = %connection.client.ip(), "websocket open");

    // The writer: the only task touching the sink; bounded queue in front.
    // A message's reservation is released once its frame is written. When
    // the writer gives up, the queue and its reservations are dropped and
    // the budgets halted, so a waiting session stops.
    let budgets = Budgets::new(limits.max_outbound_bytes, connection.outbound.clone());
    let (queue, mut outbox) = mpsc::channel::<Out>(limits.outbound_queue);
    let writer_budgets = budgets.clone();
    let writer = tokio::spawn(async move {
        let halt = |outbox: &mut mpsc::Receiver<Out>| {
            outbox.close();
            while outbox.try_recv().is_ok() {}
            writer_budgets.halt();
        };
        while let Some(item) = outbox.recv().await {
            let (frame, reservation, last) = match item {
                Out::Lfcp(bytes, reservation) => {
                    (Frame::Binary(bytes.into()), Some(reservation), false)
                }
                Out::Close(close) => (Frame::Close(Some(close)), None, true),
            };
            let written = tokio::time::timeout(limits.write_timeout, sink.send(frame)).await;
            drop(reservation);
            match written {
                Ok(Ok(())) if !last => {}
                Ok(Ok(())) => break,
                Ok(Err(error)) => {
                    tracing::debug!(conn = id, %error, "write failed");
                    halt(&mut outbox);
                    return None;
                }
                Err(_) => {
                    tracing::info!(conn = id, "write timed out; closing a slow connection");
                    halt(&mut outbox);
                    return None;
                }
            }
        }
        // Flush and wait briefly for the peer's close.
        let _ = tokio::time::timeout(limits.close_timeout, sink.close()).await;
        // Handed back for the lingering close.
        Some(sink)
    });
    let out = Outbound::new(queue.clone(), budgets.clone());
    let abort = out.abort.clone();
    let close = |code: CloseCode, reason: &'static str| {
        let _ = queue.try_send(Out::Close(CloseFrame {
            code,
            reason: reason.into(),
        }));
    };
    let options = DecodeOptions {
        max_message_bytes: limits.max_message_bytes,
        ..DecodeOptions::default()
    };

    // Liveness: the deadline moves only when an LFCP message arrives.
    let idle_deadline = || {
        limits
            .idle_timeout
            .map(|idle| tokio::time::Instant::now() + idle)
    };
    let mut deadline = idle_deadline();
    // The handshake deadline is fixed when the connection opens.
    let handshake_deadline = tokio::time::Instant::now() + limits.handshake_timeout;
    let mut pre_ready = 0usize;
    let mut rate = limits
        .message_rate
        .map(|rate| crate::limits::Bucket::new(rate, std::time::Instant::now()));
    loop {
        let ready = session.is_ready();
        let wait = match (deadline, ready) {
            (Some(idle), false) => Some(idle.min(handshake_deadline)),
            (None, false) => Some(handshake_deadline),
            (idle, true) => idle,
        };
        let next = async {
            match wait {
                Some(deadline) => tokio::time::timeout_at(deadline, stream.next())
                    .await
                    .map_err(|_| ()),
                None => Ok(stream.next().await),
            }
        };
        let item = tokio::select! {
            item = next => item,
            () = abort.notify.notified() => {
                tracing::info!(conn = id, "aborted: too slow for live pushes");
                close(CloseCode::Again, "too slow");
                break;
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    close(CloseCode::Away, "server shutting down");
                    break;
                }
                continue;
            }
        };
        let frame = match item {
            Err(()) if !ready && tokio::time::Instant::now() >= handshake_deadline => {
                tracing::info!(conn = id, "handshake timeout");
                close(CloseCode::Policy, "handshake timeout");
                break;
            }
            Err(()) => {
                tracing::info!(conn = id, "idle timeout");
                close(CloseCode::Away, "idle timeout");
                break;
            }
            Ok(None) => break,
            Ok(Some(Ok(frame))) => frame,
            Ok(Some(Err(WsError::Capacity(CapacityError::MessageTooLong { size, max_size })))) => {
                let error = Error::MessageTooLarge {
                    size,
                    limit: max_size,
                };
                tracing::info!(conn = id, code = error.code(), "rejected a message");
                if let Some(message) = error_message(&error) {
                    let _ = out.send(message);
                }
                close(CloseCode::Size, "message too large");
                break;
            }
            Ok(Some(Err(error))) => {
                tracing::debug!(conn = id, %error, "websocket error");
                break;
            }
        };
        if !ready && matches!(frame, Frame::Binary(_) | Frame::Text(_)) {
            pre_ready += 1;
            if pre_ready > limits.pre_ready_messages {
                tracing::info!(conn = id, "too many messages before READY");
                if let Some(message) = code_message(lfcp::base::WireCode::RateLimited) {
                    let _ = out.send(message);
                }
                close(CloseCode::Policy, "too many messages before READY");
                break;
            }
            let size = frame.len();
            if size > limits.pre_ready_message_bytes {
                let error = Error::MessageTooLarge {
                    size,
                    limit: limits.pre_ready_message_bytes,
                };
                tracing::info!(
                    conn = id,
                    code = error.code(),
                    "rejected a message before READY"
                );
                if let Some(message) = error_message(&error) {
                    let _ = out.send(message);
                }
                close(CloseCode::Size, "message too large before READY");
                break;
            }
        }
        if matches!(frame, Frame::Binary(_) | Frame::Text(_))
            && rate
                .as_mut()
                .is_some_and(|bucket| bucket.take(std::time::Instant::now()).is_err())
        {
            tracing::info!(conn = id, "message rate limit; closing");
            let diagnostic = Some(RATE_LIMIT_DIAGNOSTIC);
            if let Some(message) = diagnostic_message(lfcp::base::WireCode::RateLimited, diagnostic)
            {
                let _ = out.send(message);
            }
            close(CloseCode::Policy, "message rate limit");
            break;
        }
        let decoded = match frame {
            Frame::Binary(bytes) => Message::decode_frame(FrameKind::Binary, &bytes, &options),
            Frame::Text(text) => Message::decode_frame(FrameKind::Text, text.as_bytes(), &options),
            // Control frames: tungstenite answers pings and close itself.
            // They are not LFCP liveness.
            Frame::Ping(_) | Frame::Pong(_) | Frame::Frame(_) => continue,
            Frame::Close(_) => break,
        };
        match decoded {
            Ok(message) => {
                deadline = idle_deadline();
                tracing::debug!(
                    conn = id,
                    message_type = message.body.message_type(),
                    "message"
                );
                // A session waiting for outbound room is released at
                // shutdown (its sends fail), then the connection closes.
                let handled = session.handle(message, &out);
                tokio::pin!(handled);
                let flow = tokio::select! {
                    flow = &mut handled => flow,
                    () = stopped(&mut shutdown) => {
                        budgets.halt();
                        handled.await;
                        close(CloseCode::Away, "server shutting down");
                        break;
                    }
                };
                if flow == Flow::Close {
                    close(CloseCode::Normal, "");
                    break;
                }
            }
            Err(error) => {
                tracing::info!(conn = id, code = error.code(), "rejected a message");
                if session.rejected(error, &out) == Flow::Close {
                    close(CloseCode::Protocol, "protocol error");
                    break;
                }
            }
        }
    }

    session.closed();
    drop(out);
    drop(queue);
    // The writer drains what is queued (ending with a close frame) or gives
    // up after the write and close timeouts.
    let budget = limits.write_timeout + limits.close_timeout;
    let abort = writer.abort_handle();
    match tokio::time::timeout(budget, writer).await {
        Ok(Ok(Some(sink))) => {
            if let Ok(socket) = stream.reunite(sink) {
                linger(socket.into_inner(), &limits, &mut shutdown).await;
            }
        }
        Ok(_) => {}
        Err(_) => {
            abort.abort();
            tracing::info!(conn = id, "writer did not finish; dropping the connection");
        }
    }
    tracing::info!(conn = id, "websocket closed");
}

/// The lingering close (see the module documentation): shut down the write
/// half, then read and discard the peer's bytes until EOF, within
/// `linger_timeout` and `linger_bytes`, or until the server shuts down.
async fn linger<S: AsyncRead + AsyncWrite + Unpin>(
    mut socket: S,
    limits: &Limits,
    shutdown: &mut watch::Receiver<bool>,
) {
    let drain = async {
        let _ = socket.shutdown().await;
        let mut buffer = [0u8; 16 * 1024];
        let mut left = limits.linger_bytes;
        loop {
            match socket.read(&mut buffer).await {
                Ok(0) | Err(_) => return,
                Ok(n) if n >= left => return,
                Ok(n) => left -= n,
            }
        }
    };
    tokio::select! {
        _ = tokio::time::timeout(limits.linger_timeout, drain) => {}
        () = stopped(shutdown) => {}
    }
}

/// Completes once the server is shutting down (or gone).
async fn stopped(shutdown: &mut watch::Receiver<bool>) {
    let _ = shutdown.wait_for(|stop| *stop).await;
}
