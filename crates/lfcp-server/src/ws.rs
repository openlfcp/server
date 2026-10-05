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
//! messages are handled one at a time; the outbound queue holds
//! [`Limits::outbound_queue`] messages, and a session that finds it full
//! must close the connection; a write that does not finish within
//! [`Limits::write_timeout`] closes it too. A connection with no inbound
//! LFCP message for [`Limits::idle_timeout`] (three READY heartbeat
//! intervals, §37) is closed. Only LFCP messages (an LFCP `PING` included)
//! count as liveness; WebSocket-level ping and pong frames do not.

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
use tokio::sync::{mpsc, watch, Notify};
use tokio_tungstenite::tungstenite::error::{CapacityError, Error as WsError};
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, Role, WebSocketConfig};
use tokio_tungstenite::tungstenite::Message as Frame;
use tokio_tungstenite::WebSocketStream;

use crate::identity::ServerId;
use crate::rng;

/// The LFCP WebSocket subprotocol (§30).
pub const SUBPROTOCOL: &str = "lfcp-1";

/// Per-connection transport limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// The maximum LFCP message size (§31, advertised in READY §37).
    pub max_message_bytes: usize,
    /// Outbound messages that may wait for the socket.
    pub outbound_queue: usize,
    /// Close a connection with no inbound LFCP message for this long.
    pub idle_timeout: Option<Duration>,
    /// Close a connection whose socket does not take a message this fast.
    pub write_timeout: Duration,
    /// How long a closing connection may take to flush and close.
    pub close_timeout: Duration,
}

impl Limits {
    /// The limits for a configured message size and READY heartbeat
    /// interval in milliseconds (0 disables the idle timeout).
    pub fn new(max_message_bytes: usize, heartbeat_ms: u64) -> Limits {
        Limits {
            max_message_bytes,
            outbound_queue: 256,
            idle_timeout: (heartbeat_ms > 0)
                .then(|| Duration::from_millis(heartbeat_ms.saturating_mul(3))),
            write_timeout: Duration::from_secs(10),
            close_timeout: Duration::from_secs(5),
        }
    }
}

/// What the transport knows about a connection, for its session.
#[derive(Clone, Debug)]
pub struct ConnectionContext {
    /// A process-local connection number, for logs.
    pub id: u64,
    /// The peer address.
    pub peer: SocketAddr,
    /// The server ID (§35, §37).
    pub server_id: ServerId,
    /// The transport limits.
    pub limits: Limits,
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
}

#[derive(Debug, Default)]
struct Abort {
    requested: AtomicBool,
    notify: Notify,
}

impl Outbound {
    fn new(queue: mpsc::Sender<Out>) -> Outbound {
        Outbound {
            queue,
            abort: Arc::default(),
        }
    }

    /// Queue a message without waiting.
    pub fn send(&self, message: Message) -> Result<(), Overloaded> {
        self.queue
            .try_send(Out::Lfcp(Box::new(message)))
            .map_err(|_| Overloaded)
    }

    /// Close the connection from outside its session, for example when a
    /// live push finds its queue full: the transport closes it with 1013
    /// (try again later) instead of silently dropping messages.
    pub fn abort(&self) {
        self.abort.requested.store(true, Ordering::SeqCst);
        self.abort.notify.notify_one();
    }

    /// Whether [`Outbound::abort`] was called.
    pub fn is_aborted(&self) -> bool {
        self.abort.requested.load(Ordering::SeqCst)
    }
}

#[derive(Debug)]
pub(crate) enum Out {
    Lfcp(Box<Message>),
    Close(CloseFrame),
}

/// An [`Outbound`] whose messages a unit test reads back.
#[cfg(test)]
pub(crate) fn test_outbound(capacity: usize) -> (Outbound, mpsc::Receiver<Out>) {
    let (queue, inbox) = mpsc::channel(capacity);
    (Outbound::new(queue), inbox)
}

#[cfg(test)]
impl Out {
    /// The LFCP message, if this is one.
    pub(crate) fn into_message(self) -> Option<Message> {
        match self {
            Out::Lfcp(message) => Some(*message),
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
    tracing::info!(conn = id, peer = %connection.peer, "websocket open");

    // The writer: the only task touching the sink; bounded queue in front.
    let (queue, mut outbox) = mpsc::channel::<Out>(limits.outbound_queue);
    let writer = tokio::spawn(async move {
        while let Some(item) = outbox.recv().await {
            let (frame, last) = match item {
                Out::Lfcp(message) => (Frame::Binary(message.encode().into()), false),
                Out::Close(close) => (Frame::Close(Some(close)), true),
            };
            match tokio::time::timeout(limits.write_timeout, sink.send(frame)).await {
                Ok(Ok(())) if !last => {}
                Ok(Ok(())) => break,
                Ok(Err(error)) => {
                    tracing::debug!(conn = id, %error, "write failed");
                    return;
                }
                Err(_) => {
                    tracing::info!(conn = id, "write timed out; closing a slow connection");
                    return;
                }
            }
        }
        // Flush and wait briefly for the peer's close.
        let _ = tokio::time::timeout(limits.close_timeout, sink.close()).await;
    });
    let out = Outbound::new(queue.clone());
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
    loop {
        let next = async {
            match deadline {
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
                if session.handle(message, &out).await == Flow::Close {
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
    if tokio::time::timeout(budget, writer).await.is_err() {
        abort.abort();
        tracing::info!(conn = id, "writer did not finish; dropping the connection");
    }
    tracing::info!(conn = id, "websocket closed");
}
