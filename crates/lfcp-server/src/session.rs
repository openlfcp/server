//! The LFCP session (WIRE-01 §34–§43, §64): the handshake, then Resource
//! hosting and opening, on top of the [`crate::ws`] transport.
//!
//! | Step | Server behaviour | § |
//! | --- | --- | --- |
//! | HELLO | descriptor decoded and its ID recomputed by sdk-rs; a bad descriptor or ID mismatch is `ERROR(AUTH_FAILED)`, close; no common wire profile is `ERROR(PROTOCOL_UNSUPPORTED)`, close | §34, §7, P2/P3, G-MSG7 |
//! | CHALLENGE | selected profile, server nonce and session ID from [`Random`], the stable server ID | §35, §5.4 |
//! | AUTH | sdk-rs `verify_auth` over this session's transcript; any failure is `ERROR(AUTH_FAILED)`, close | §36, G-MSG4 |
//! | READY | profile, server ID, configured max message bytes, the store's durability (2), configured heartbeat, no extensions | §37 |
//! | before READY | Resource, Control, Data, Key and Snapshot messages: `NACK(AUTHORIZATION_FAILED)`, stay open; `PING`/`PONG`/`ERROR` allowed; any other out-of-order message (or an undecodable one) is `ERROR(MALFORMED_MESSAGE)`, close | §64, G-SM4 |
//! | RESOURCE_HOST | Genesis validated by sdk-rs (structure, owner signature, ws/wss URLs), hosting policy, persisted, then `RESOURCE_HOSTED` with durability 2; another Genesis for the Resource is `NACK(CONTROL_CONFLICT)` | §39, §40, §13.2, §15, §16 |
//! | RESOURCE_OPEN | unknown Resource: `NACK(RESOURCE_NOT_HOSTED)`; the session Principal must hold `data/read`, or be an invitation subject, at the accepted Control Head, else `NACK(AUTHORIZATION_FAILED)`; then `RESOURCE_OPENED` with every Control Head the server knows, its Have, a Snapshot summary, route version and coordinator | §41, §42, §84, §73 |
//! | RESOURCE_CLOSE | drops the session's subscription only; `ACK` | §43 |
//!
//! Authority: a successful AUTH proves possession of the session
//! Principal's key and nothing else (§36). The hosting credential and the
//! hosting row are server policy (§36, §39); they never grant an LFCP
//! ability. Resource authority is always evaluated from the stored Control
//! Chain with the sdk-rs capability engine.
//!
//! Server-side read authorization at open (§84 recommends it for
//! production; §41 names its `NACK(AUTHORIZATION_FAILED)`): the server
//! evaluates the chain up to its accepted head. Clients still verify
//! everything themselves.
//!
//! Logs carry the connection number, message types, codes and public
//! identifiers; never credentials, proofs or payloads.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use lfcp::base::{ControlRecordId, Error, PrincipalId, ResourceId, WireCode};
use lfcp::principal::PrincipalDescriptor;
use lfcp::wire::control::authority::{ability, validate_authorized, ControlState};
use lfcp::wire::control::body::ControlBody;
use lfcp::wire::control::chain::ChainOutcome;
use lfcp::wire::control::ControlRecord;
use lfcp::wire::have::HaveVector;
use lfcp::wire::message::{
    AckBody, AuthBody, Body, ChallengeBody, ControlHead, ErrorBody, HelloBody, HostingCredential,
    Message, ReadyBody, SnapshotSummary, WireActorHave,
};
use lfcp::wire::session::{select_wire_profile, verify_auth, WIRE_PROFILE};
use lfcp::wire::snapshot::ReceivedSnapshot;
use lfcp::wire::state::{server_accepts, ServerSession, ServerSessionEvent};

use crate::config::Config;
use crate::identity::ServerId;
use crate::rng::{OsRandom, Random};
use crate::store::{Head, Hosting, Store, StoreError, StoredControlRecord, DURABILITY};
use crate::ws::{ConnectionContext, Flow, Outbound, Session, SessionFactory};

/// Server hosting policy (§36, §39): who may ask this server to host a
/// Resource. Infrastructure only: it is never Resource authority.
pub trait HostingPolicy: Send + Sync + 'static {
    /// Whether `host`, authenticated in this session, may host a new
    /// Resource, given the hosting credential from `RESOURCE_HOST` or else
    /// from `AUTH`. The credential must not be logged.
    fn allows(&self, host: &PrincipalId, credential: Option<&HostingCredential>) -> bool;
}

/// The self-hosted MVP policy: any authenticated Principal may host, with
/// or without a credential.
#[derive(Clone, Copy, Debug, Default)]
pub struct OpenHosting;

impl HostingPolicy for OpenHosting {
    fn allows(&self, _: &PrincipalId, _: Option<&HostingCredential>) -> bool {
        true
    }
}

/// What READY advertises (§37) besides the profile and server ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadyParams {
    /// The maximum LFCP message size.
    pub max_message_bytes: u64,
    /// The heartbeat interval in ms; 0 disables it.
    pub heartbeat_ms: u64,
}

/// The [`SessionFactory`] of LFCP sessions.
#[derive(Clone)]
pub struct Lfcp {
    store: Arc<Store>,
    random: Arc<dyn Random>,
    hosting: Arc<dyn HostingPolicy>,
    ready: ReadyParams,
}

impl Lfcp {
    /// Sessions on `store`, advertising the configured limits, with
    /// operating-system randomness and [`OpenHosting`].
    pub fn new(store: Arc<Store>, config: &Config) -> Lfcp {
        Lfcp {
            store,
            random: Arc::new(OsRandom),
            hosting: Arc::new(OpenHosting),
            ready: ReadyParams {
                max_message_bytes: config.max_message_bytes as u64,
                heartbeat_ms: config.heartbeat_ms,
            },
        }
    }

    /// Use `random` for nonces, session IDs and message IDs.
    pub fn with_random(mut self, random: Arc<dyn Random>) -> Lfcp {
        self.random = random;
        self
    }

    /// Use `hosting` as the hosting policy.
    pub fn with_hosting(mut self, hosting: Arc<dyn HostingPolicy>) -> Lfcp {
        self.hosting = hosting;
        self
    }
}

impl SessionFactory for Lfcp {
    type Session = LfcpSession;

    fn open(&self, connection: &ConnectionContext) -> LfcpSession {
        LfcpSession {
            conn: connection.id,
            server_id: connection.server_id,
            shared: self.clone(),
            state: ServerSession::Accepted
                .transition(ServerSessionEvent::Start)
                .expect("ACCEPTED starts"),
            pending: None,
            authenticated: None,
            subscriptions: HashMap::new(),
        }
    }
}

/// The authenticated session (§36, §37).
#[derive(Debug)]
pub struct Authenticated {
    /// The session Principal, proven by AUTH.
    pub principal: PrincipalDescriptor,
    /// The session ID from CHALLENGE.
    pub session_id: [u8; 16],
    /// The selected wire profile.
    pub wire_profile: String,
    /// The READY parameters sent.
    pub ready: ReadyParams,
    /// The AUTH hosting credential: server policy only.
    hosting_credential: Option<HostingCredential>,
}

/// An open Resource on this session (§41).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Subscription {
    /// The RESOURCE_OPEN flags: live Data (bit 0), Control (bit 1),
    /// presence (bit 2).
    pub flags: u64,
}

/// One connection's LFCP session state.
pub struct LfcpSession {
    conn: u64,
    server_id: ServerId,
    shared: Lfcp,
    state: ServerSession,
    pending: Option<(HelloBody, ChallengeBody)>,
    authenticated: Option<Authenticated>,
    subscriptions: HashMap<ResourceId, Subscription>,
}

impl LfcpSession {
    /// The §64 state.
    pub fn state(&self) -> ServerSession {
        self.state
    }

    /// The authenticated session, after READY.
    pub fn authenticated(&self) -> Option<&Authenticated> {
        self.authenticated.as_ref()
    }

    /// The open Resources.
    pub fn subscriptions(&self) -> &HashMap<ResourceId, Subscription> {
        &self.subscriptions
    }

    fn send(&self, out: &Outbound, correlation: Option<[u8; 16]>, body: Body) -> Flow {
        let id = match self.shared.random.nonce16() {
            Ok(id) => id,
            Err(error) => {
                tracing::error!(conn = self.conn, %error, "no randomness; closing");
                return Flow::Close;
            }
        };
        let mut message = Message::new(id, body);
        message.correlation_id = correlation;
        match out.send(message) {
            Ok(()) => Flow::Continue,
            Err(_) => {
                tracing::info!(conn = self.conn, "outbound queue full; closing");
                Flow::Close
            }
        }
    }

    fn nack(&self, out: &Outbound, request: [u8; 16], code: WireCode) -> Flow {
        tracing::debug!(conn = self.conn, code = code.name(), "NACK");
        self.send(out, Some(request), Body::Nack(code_body(code)))
    }

    fn nack_error(&self, out: &Outbound, request: [u8; 16], error: &Error) -> Flow {
        match ErrorBody::for_error(error) {
            Some(body) => {
                tracing::debug!(conn = self.conn, code = error.code(), "NACK");
                self.send(out, Some(request), Body::Nack(body))
            }
            None => self.nack(out, request, WireCode::InternalError),
        }
    }

    /// `ERROR(code)`, then close (§61).
    fn fatal(&mut self, out: &Outbound, code: WireCode) -> Flow {
        tracing::info!(
            conn = self.conn,
            code = code.name(),
            "session error; closing"
        );
        self.state = ServerSession::Closed;
        self.pending = None;
        let _ = self.send(out, None, Body::Error(code_body(code)));
        Flow::Close
    }

    fn on_hello(&mut self, request: [u8; 16], hello: HelloBody, out: &Outbound) -> Flow {
        let wire_profile = match select_wire_profile(&hello, &[WIRE_PROFILE]) {
            Ok(profile) => profile,
            Err(error) => return self.fatal(out, session_code(&error)),
        };
        let (server_nonce, session_id) =
            match (self.shared.random.nonce16(), self.shared.random.nonce16()) {
                (Ok(nonce), Ok(session)) => (nonce, session),
                _ => return self.fatal(out, WireCode::InternalError),
            };
        let challenge = ChallengeBody {
            wire_profile,
            server_nonce,
            session_id,
            server_id: *self.server_id.as_bytes(),
        };
        self.state = self
            .state
            .transition(ServerSessionEvent::ValidHello)
            .unwrap_or(ServerSession::Closed);
        self.pending = Some((hello, challenge.clone()));
        self.send(out, Some(request), Body::Challenge(challenge))
    }

    fn on_auth(&mut self, request: [u8; 16], auth: AuthBody, out: &Outbound) -> Flow {
        let Some((hello, challenge)) = self.pending.take() else {
            return self.fatal(out, WireCode::MalformedMessage);
        };
        let session = match verify_auth(&hello, &challenge, auth) {
            Ok(session) => session,
            Err(error) => return self.fatal(out, session_code(&error)),
        };
        self.state = self
            .state
            .transition(ServerSessionEvent::ValidAuth)
            .unwrap_or(ServerSession::Closed);
        let ready = self.shared.ready;
        tracing::info!(
            conn = self.conn,
            principal = %session.principal.id().to_hex(),
            "session ready"
        );
        self.authenticated = Some(Authenticated {
            principal: session.principal,
            session_id: session.session_id,
            wire_profile: challenge.wire_profile.clone(),
            ready,
            hosting_credential: session.hosting_credential,
        });
        self.send(
            out,
            Some(request),
            Body::Ready(ReadyBody {
                wire_profile: challenge.wire_profile,
                server_id: challenge.server_id,
                max_message_bytes: ready.max_message_bytes,
                durability: u64::from(DURABILITY),
                heartbeat_ms: ready.heartbeat_ms,
                extensions: Some(Vec::new()),
            }),
        )
    }

    async fn on_host(
        &mut self,
        request: [u8; 16],
        genesis: Vec<u8>,
        credential: Option<HostingCredential>,
        out: &Outbound,
    ) -> Flow {
        let Some(auth) = self.authenticated.as_ref() else {
            return self.nack(out, request, WireCode::AuthorizationFailed);
        };
        // §39 steps 1–3: Genesis structure, Resource ID and signature.
        let resource_id = match validate_genesis(&genesis) {
            Ok(resource_id) => resource_id,
            Err(error) => return self.nack_error(out, request, &error),
        };
        // Step 4: hosting policy, never Resource authority.
        let host = *auth.principal.id();
        let credential = credential.as_ref().or(auth.hosting_credential.as_ref());
        if !self.shared.hosting.allows(&host, credential) {
            return self.nack(out, request, WireCode::HostingDenied);
        }
        // Step 5: persisted (committed, WAL synchronous=FULL) before the
        // reply.
        let hosting = Hosting {
            host,
            durability: DURABILITY,
        };
        match self.shared.store.host_resource(genesis, hosting).await {
            Ok(_) => {
                tracing::info!(conn = self.conn, resource = %resource_id.to_hex(), "hosted");
                self.send(
                    out,
                    Some(request),
                    Body::ResourceHosted {
                        resource_id,
                        durability: u64::from(DURABILITY),
                    },
                )
            }
            // §13.2, G-CP5: a second Genesis is a fork at the root.
            Err(StoreError::GenesisConflict { .. }) => {
                self.nack(out, request, WireCode::ControlConflict)
            }
            Err(error) => self.internal(out, request, &error),
        }
    }

    async fn on_open(
        &mut self,
        request: [u8; 16],
        resource_id: ResourceId,
        flags: Option<u64>,
        out: &Outbound,
    ) -> Flow {
        let Some(auth) = self.authenticated.as_ref() else {
            return self.nack(out, request, WireCode::AuthorizationFailed);
        };
        let principal = *auth.principal.id();
        let store = &self.shared.store;
        let info = match store.resource(resource_id).await {
            Ok(Some(info)) => info,
            Ok(None) => return self.nack(out, request, WireCode::ResourceNotHosted),
            Err(error) => return self.internal(out, request, &error),
        };
        let records = match store.control_records(resource_id, 0, u64::MAX).await {
            Ok(records) => records,
            Err(error) => return self.internal(out, request, &error),
        };
        let view = match ResourceView::build(&records, info.head) {
            Ok(view) => view,
            Err(error) => return self.nack_error(out, request, &error),
        };
        if !view.may_open(&principal) {
            return self.nack(out, request, WireCode::AuthorizationFailed);
        }
        let have = match store.data_sequences(resource_id).await {
            Ok(sequences) => have_of(&sequences),
            Err(error) => return self.internal(out, request, &error),
        };
        let snapshot = match store.snapshots(resource_id).await {
            Ok(snapshots) => snapshots
                .first()
                .and_then(|s| ReceivedSnapshot::parse(&s.bytes).ok())
                .map(|s| SnapshotSummary {
                    snapshot_id: s.id(),
                    data_epoch: s.header().data_epoch,
                    frontier: HaveVector::from_frontier(&s.header().frontier).to_wire(),
                }),
            Err(error) => return self.internal(out, request, &error),
        };
        self.subscriptions.insert(
            resource_id,
            Subscription {
                flags: flags.unwrap_or(0),
            },
        );
        tracing::debug!(conn = self.conn, resource = %resource_id.to_hex(), "opened");
        self.send(
            out,
            Some(request),
            Body::ResourceOpened {
                resource_id,
                control_heads: view.heads,
                have,
                snapshot,
                route_version: Some(view.state.route_version),
                coordinator: Some(view.coordinator),
            },
        )
    }

    fn on_close(&mut self, request: [u8; 16], resource_id: ResourceId, out: &Outbound) -> Flow {
        // §43: session state only; nothing persistent is touched.
        self.subscriptions.remove(&resource_id);
        self.send(
            out,
            Some(request),
            Body::Ack(AckBody {
                request_type: 14,
                object_ids: None,
                durable: None,
            }),
        )
    }

    fn internal(&self, out: &Outbound, request: [u8; 16], error: &StoreError) -> Flow {
        tracing::error!(conn = self.conn, %error, "store failure");
        self.nack(out, request, WireCode::InternalError)
    }
}

impl Session for LfcpSession {
    async fn handle(&mut self, message: Message, out: &Outbound) -> Flow {
        let Message {
            message_id: id,
            body,
            ..
        } = message;
        // §64: Resource, Control, Data, Key and Snapshot messages before
        // READY are rejected; the connection stays open.
        if let Err(error) = server_accepts(self.state, body.message_type()) {
            return self.nack_error(out, id, &error);
        }
        let ready = self.state == ServerSession::Ready;
        match body {
            Body::Ping(payload) => self.send(out, Some(id), Body::Pong(payload)),
            Body::Pong(_) | Body::Ack(_) | Body::Nack(_) => Flow::Continue,
            Body::Error(error) => {
                tracing::info!(conn = self.conn, code = error.code, "peer sent ERROR");
                Flow::Continue
            }
            Body::Hello(hello) if self.state == ServerSession::WaitHello => {
                self.on_hello(id, hello, out)
            }
            Body::Auth(auth) if self.state == ServerSession::WaitAuth => {
                self.on_auth(id, auth, out)
            }
            // A handshake message out of order, or anything else before
            // READY (baseline.4: MALFORMED_MESSAGE, close).
            Body::Hello(_) | Body::Challenge(_) | Body::Auth(_) | Body::Ready(_) => {
                self.fatal(out, WireCode::MalformedMessage)
            }
            _ if !ready => self.fatal(out, WireCode::MalformedMessage),
            Body::ResourceHost {
                genesis,
                hosting_credential,
            } => self.on_host(id, genesis, hosting_credential, out).await,
            Body::ResourceOpen {
                resource_id, flags, ..
            } => self.on_open(id, resource_id, flags, out).await,
            Body::ResourceClose { resource_id } => self.on_close(id, resource_id, out),
            // Server-to-client responses.
            Body::ResourceHosted { .. } | Body::ResourceOpened { .. } => {
                self.nack(out, id, WireCode::MalformedMessage)
            }
            // Control, Data, Key, Snapshot and presence: LFCP-049 onward.
            _ => self.nack(out, id, WireCode::ProtocolUnsupported),
        }
    }

    fn rejected(&mut self, error: Error, out: &Outbound) -> Flow {
        if self.state == ServerSession::Ready {
            let body =
                ErrorBody::for_error(&error).unwrap_or(code_body(WireCode::MalformedMessage));
            let _ = self.send(out, None, Body::Error(body));
            return if error.closes_connection() {
                Flow::Close
            } else {
                Flow::Continue
            };
        }
        // Before READY an undecodable message is a protocol violation
        // (§64); in HELLO a bad descriptor is AUTH_FAILED (§7, P3).
        self.fatal(out, session_code(&error))
    }

    fn closed(&mut self) {
        self.state = ServerSession::Closed;
        self.pending = None;
        self.subscriptions.clear();
    }
}

fn code_body(code: WireCode) -> ErrorBody {
    ErrorBody {
        code: code.number(),
        diagnostic: None,
        details: None,
    }
}

/// The code for a HELLO/AUTH-context error (§7, §36).
fn session_code(error: &Error) -> WireCode {
    error
        .session_wire_code()
        .unwrap_or(WireCode::MalformedMessage)
}

/// §39 steps 1–3 with sdk-rs: a Genesis at sequence 0, signed by the owner
/// in its body (S2: `INVALID_SIGNATURE`), whose URLs are ws/wss (G-CP4:
/// `MALFORMED_MESSAGE`). Returns its Resource ID.
pub fn validate_genesis(genesis: &[u8]) -> Result<ResourceId, Error> {
    match validate_authorized(&[genesis], None) {
        Ok((ChainOutcome::Linear(chain), _)) => Ok(chain.head.resource_id),
        Ok((ChainOutcome::Conflict(_), _)) => Err(Error::ControlConflict),
        Err(failure) => Err(failure.error),
    }
}

/// The server's view of a hosted Resource, from its stored Control Records.
struct ResourceView {
    /// The Control state at the accepted head.
    state: ControlState,
    /// Every Control Head the server knows: the accepted head and the tip
    /// of each competing branch (§13.2, §42: a fork is never hidden).
    heads: Vec<ControlHead>,
    /// The current Control Coordinator URL.
    coordinator: String,
}

impl ResourceView {
    fn build(records: &[StoredControlRecord], head: Head) -> Result<ResourceView, Error> {
        let by_id: HashMap<ControlRecordId, &StoredControlRecord> =
            records.iter().map(|r| (r.id, r)).collect();
        // The accepted chain: from the head back to Genesis.
        let mut path = Vec::new();
        let mut next = Some(head.id);
        while let Some(id) = next {
            let record = by_id.get(&id).ok_or(Error::UnknownControlHead)?;
            path.push(record.bytes.as_slice());
            next = record.previous;
        }
        path.reverse();
        // DV1: a chain with Coordinator Recovery or Tombstone is refused
        // by the engine (PROTOCOL_UNSUPPORTED).
        let (chain, states) = match validate_authorized(&path, None) {
            Ok((ChainOutcome::Linear(chain), states)) => (chain, states),
            Ok((ChainOutcome::Conflict(_), _)) => return Err(Error::ControlConflict),
            Err(failure) => return Err(failure.error),
        };
        let state = states.last().cloned().ok_or(Error::UnknownControlHead)?;
        let coordinator = coordinator_of(&chain.records).ok_or(Error::UnknownControlHead)?;

        let predecessors: HashSet<ControlRecordId> =
            records.iter().filter_map(|r| r.previous).collect();
        let mut heads: Vec<ControlHead> = records
            .iter()
            .filter(|r| !predecessors.contains(&r.id))
            .map(|r| ControlHead {
                sequence: r.seq,
                id: r.id,
            })
            .collect();
        heads.sort_by(|a, b| (a.sequence, a.id.as_bytes()).cmp(&(b.sequence, b.id.as_bytes())));
        Ok(ResourceView {
            state,
            heads,
            coordinator,
        })
    }

    /// §84 read authorization at the accepted head: `data/read`, or the
    /// subject of an invitation grant that still confers `invite/claim`
    /// (§73: the Invitation Principal opens the Resource to claim).
    fn may_open(&self, principal: &PrincipalId) -> bool {
        self.state.holds(principal, ability::DATA_READ)
            || self
                .state
                .grants()
                .any(|g| &g.subject == principal && self.state.confers_invite(g))
    }
}

/// The coordinator of the last Genesis, Route Update or Coordinator
/// Recovery on the chain.
fn coordinator_of(records: &[ControlRecord]) -> Option<String> {
    records.iter().rev().find_map(|r| match r.body() {
        ControlBody::Genesis(b) => Some(b.coordinator.clone()),
        ControlBody::RouteUpdate(b) => Some(b.coordinator.clone()),
        ControlBody::CoordinatorRecovery(b) => Some(b.coordinator.clone()),
        _ => None,
    })
}

/// The canonical wire Have of stored (actor, sequence) pairs.
fn have_of(sequences: &[(PrincipalId, u64)]) -> Vec<WireActorHave> {
    let mut have = HaveVector::new();
    for (actor, sequence) in sequences {
        // Sequences are ≥ 1 by the schema, so insert cannot fail.
        let _ = have.insert(actor, *sequence);
    }
    have.to_wire()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ws::test_outbound;
    use lfcp::base::Hash32;
    use lfcp::principal::PrincipalKeys;
    use lfcp::wire::control::body::{Endpoint, GenesisBody};
    use lfcp::wire::control::ControlRecordHeader;
    use lfcp::wire::session::auth;
    use tokio::sync::mpsc;

    fn genesis(owner: &PrincipalKeys, resource: ResourceId) -> Vec<u8> {
        let url = "wss://sync.example.test/v1/ws".to_owned();
        let record = ControlRecord::sign(
            ControlRecordHeader {
                resource_id: resource,
                sequence: 0,
                previous: None,
                issuer: *owner.descriptor().id(),
            },
            ControlBody::Genesis(GenesisBody {
                data_profile: "org.lfcp.test.raw.v1".into(),
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
        .unwrap();
        record.signed_object().bytes().to_vec()
    }

    async fn reply(
        session: &mut LfcpSession,
        out: &Outbound,
        inbox: &mut mpsc::Receiver<crate::ws::Out>,
        body: Body,
    ) -> Message {
        let flow = session.handle(Message::new([0; 16], body), out).await;
        assert_eq!(flow, Flow::Continue);
        inbox.recv().await.unwrap().into_message().unwrap()
    }

    #[tokio::test]
    async fn subscriptions_live_in_the_session_only() {
        let dir = std::env::temp_dir().join(format!("lfcp-session-unit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Arc::new(Store::open(&dir).unwrap());
        let factory = Lfcp::new(store.clone(), &Config::default());
        let context = ConnectionContext {
            id: 1,
            peer: "127.0.0.1:1".parse().unwrap(),
            server_id: ServerId::from_bytes([9; 32]),
            limits: crate::ws::Limits::new(1 << 20, 0),
        };
        let mut session = factory.open(&context);
        let (out, mut inbox) = test_outbound(8);
        assert_eq!(session.state(), ServerSession::WaitHello);

        let owner = PrincipalKeys::from_secrets(&[1; 32], [2; 32]);
        let hello = HelloBody {
            wire_profiles: vec![WIRE_PROFILE.into()],
            principal: owner.descriptor().clone(),
            client_nonce: [4; 16],
            data_profiles: None,
        };
        let Body::Challenge(challenge) =
            reply(&mut session, &out, &mut inbox, Body::Hello(hello.clone()))
                .await
                .body
        else {
            panic!("CHALLENGE")
        };
        assert_eq!(session.state(), ServerSession::WaitAuth);
        let proof = auth(&owner, &hello, &challenge, None).unwrap();
        let ready = reply(&mut session, &out, &mut inbox, Body::Auth(proof)).await;
        assert!(matches!(ready.body, Body::Ready(_)));
        let authenticated = session.authenticated().unwrap();
        assert_eq!(authenticated.principal.id(), owner.descriptor().id());
        assert_eq!(authenticated.session_id, challenge.session_id);
        assert_eq!(authenticated.wire_profile, WIRE_PROFILE);

        let resource = ResourceId::from_bytes([5; 32]);
        let hosted = reply(
            &mut session,
            &out,
            &mut inbox,
            Body::ResourceHost {
                genesis: genesis(&owner, resource),
                hosting_credential: None,
            },
        )
        .await;
        assert!(matches!(hosted.body, Body::ResourceHosted { .. }));
        let open = Body::ResourceOpen {
            resource_id: resource,
            control_heads: vec![],
            have: vec![],
            grant_ids: None,
            flags: Some(1),
        };
        let opened = reply(&mut session, &out, &mut inbox, open.clone()).await;
        assert!(matches!(opened.body, Body::ResourceOpened { .. }));
        assert_eq!(
            session.subscriptions().get(&resource),
            Some(&Subscription { flags: 1 })
        );

        // RESOURCE_CLOSE removes the subscription and nothing else.
        let ack = reply(
            &mut session,
            &out,
            &mut inbox,
            Body::ResourceClose {
                resource_id: resource,
            },
        )
        .await;
        assert!(matches!(ack.body, Body::Ack(_)));
        assert!(session.subscriptions().is_empty());
        assert!(store.resource(resource).await.unwrap().is_some());

        // Closing the connection clears every subscription.
        reply(&mut session, &out, &mut inbox, open).await;
        assert_eq!(session.subscriptions().len(), 1);
        session.closed();
        assert!(session.subscriptions().is_empty());
        assert_eq!(session.state(), ServerSession::Closed);

        drop((session, factory, store));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
