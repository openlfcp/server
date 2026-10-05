//! The LFCP session (WIRE-01 §34–§47, §64): the handshake, Resource
//! hosting and opening, and the Control Plane, on top of the [`crate::ws`]
//! transport.
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
//! | CONTROL_PUT | [`crate::coordinator::Coordinator::put`]; `ACK` (type 23, the record ID, durable) after the commit | §47, §59 |
//! | CONTROL_HAVE | read authority as for RESOURCE_OPEN; answered with every Control Head the server knows | §44 |
//! | CONTROL_GET | read authority; every stored record in the range, competing ones included, in as many CONTROL_BATCH replies as the size limit needs; a reversed range is `NACK(MALFORMED_MESSAGE)` | §45, §46 |
//! | DATA_PUT / KEY_PACKAGE_PUT / SNAPSHOT_PUT | every object validated by [`crate::ingest`] under the Resource lock (one failure refuses the put, nothing stored, one `NACK` without details), then the ingest policy, then stored, then `ACK` (33/42/52, every object ID, durable) | §51, §54, §57, §60 |
//! | an equivocating Data Unit | only the equivocating units of the request are stored, as evidence; none is accepted or pushed; `NACK(ACTOR_EQUIVOCATION)` | §26.2, §51 |
//! | DATA_HAVE | the client's Have must normalize; answered with the server's | §48 |
//! | DATA_GET / KEY_PACKAGE_GET / SNAPSHOT_GET | more than 256 ranges or 256 distinct epochs is `NACK(MALFORMED_MESSAGE)` before any lookup, and overlapping ranges are merged; read authority; Key Packages only to their recipient; size-limited batches; no stored Snapshot is `NACK(MISSING_DEPENDENCY)` | §49, §52, §55 |
//! | CONTROL/DATA/KEY_PACKAGE_BATCH, SNAPSHOT from a client | `NACK(PROTOCOL_UNSUPPORTED)`: mirror seeding (§46) is not offered | §46 |
//! | live pushes | a committed Control Record (flag bit 1) or newly accepted Data Units (bit 0) to every other subscribed session; after each Control commit, subscribers without read authority are dropped | §41, §69 |
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

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use lfcp::base::{ControlRecordId, Error, Hash32, PrincipalId, ResourceId, WireCode};
use lfcp::cbor::Value;
use lfcp::principal::PrincipalDescriptor;
use lfcp::wire::control::authority::validate_authorized;
use lfcp::wire::control::chain::ChainOutcome;
use lfcp::wire::have::HaveVector;
use lfcp::wire::message::DataRange;
use lfcp::wire::message::{
    AckBody, AuthBody, Body, ChallengeBody, ErrorBody, HelloBody, HostingCredential, Message,
    ReadyBody, SnapshotSummary, WireActorHave,
};
use lfcp::wire::session::{select_wire_profile, verify_auth, WIRE_PROFILE};
use lfcp::wire::snapshot::ReceivedSnapshot;
use lfcp::wire::state::{server_accepts, ServerSession, ServerSessionEvent};

use crate::config::Config;
use crate::coordinator::{Chain, Coordinator, Failure};
use crate::identity::ServerId;
use crate::ingest::{self, IngestPolicy, ObjectKind, Unlimited};
use crate::rng::{OsRandom, Random};
use crate::store::{Hosting, Put, Store, StoreError, StoredObject, DURABILITY};
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
    coordinator: Arc<Coordinator>,
    ingest: Arc<dyn IngestPolicy>,
    random: Arc<dyn Random>,
    hosting: Arc<dyn HostingPolicy>,
    ready: ReadyParams,
}

impl Lfcp {
    /// Sessions on `store`, advertising the configured limits, with
    /// operating-system randomness and [`OpenHosting`].
    pub fn new(store: Arc<Store>, config: &Config) -> Lfcp {
        Lfcp {
            coordinator: Arc::new(Coordinator::new(store, &config.public_urls)),
            ingest: Arc::new(Unlimited),
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

    /// Use `ingest` for quotas and rate limits.
    pub fn with_ingest(mut self, ingest: Arc<dyn IngestPolicy>) -> Lfcp {
        self.ingest = ingest;
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
        match self
            .shared
            .coordinator
            .store()
            .host_resource(genesis, hosting)
            .await
        {
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
        let chain = match self.readable(request, resource_id, &principal, out).await {
            Ok(chain) => chain,
            Err(flow) => return flow,
        };
        let store = self.shared.coordinator.store();
        let heads = match self.shared.coordinator.heads(resource_id).await {
            Ok(heads) => heads,
            Err(error) => return self.internal(out, request, &error),
        };
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
        let flags = flags.unwrap_or(0);
        self.subscriptions
            .insert(resource_id, Subscription { flags });
        self.shared.coordinator.hub().subscribe(
            resource_id,
            self.conn,
            flags,
            principal,
            out.clone(),
        );
        tracing::debug!(conn = self.conn, resource = %resource_id.to_hex(), "opened");
        self.send(
            out,
            Some(request),
            Body::ResourceOpened {
                resource_id,
                control_heads: heads,
                have,
                snapshot,
                route_version: Some(chain.state().route_version),
                coordinator: Some(chain.coordinator),
            },
        )
    }

    fn on_close(&mut self, request: [u8; 16], resource_id: ResourceId, out: &Outbound) -> Flow {
        // §43: session state only; nothing persistent is touched.
        self.subscriptions.remove(&resource_id);
        self.shared
            .coordinator
            .hub()
            .unsubscribe(resource_id, self.conn);
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

    /// The accepted chain of `resource`, if `principal` may read it (§84);
    /// otherwise the NACK already sent.
    async fn readable(
        &self,
        request: [u8; 16],
        resource: ResourceId,
        principal: &PrincipalId,
        out: &Outbound,
    ) -> Result<Chain, Flow> {
        match self.shared.coordinator.chain(resource).await {
            Ok(Some(chain)) if chain.may_read(principal) => Ok(chain),
            Ok(Some(_)) => Err(self.nack(out, request, WireCode::AuthorizationFailed)),
            Ok(None) => Err(self.nack(out, request, WireCode::ResourceNotHosted)),
            Err(failure) => Err(self.nack_failure(out, request, failure)),
        }
    }

    fn nack_failure(&self, out: &Outbound, request: [u8; 16], failure: Failure) -> Flow {
        match failure {
            Failure::NotHosted => self.nack(out, request, WireCode::ResourceNotHosted),
            // §21: and the currently known coordinator URL.
            Failure::NotCoordinator(url) => {
                let mut body = code_body(WireCode::NotControlCoordinator);
                body.details = Some(Value::text(url));
                self.send(out, Some(request), Body::Nack(body))
            }
            // §47: Genesis uses RESOURCE_HOST.
            Failure::Genesis => self.nack(out, request, WireCode::MalformedMessage),
            Failure::Lfcp(error) => self.nack_error(out, request, &error),
            Failure::Store(error) => self.internal(out, request, &error),
        }
    }

    async fn on_control_put(
        &mut self,
        request: [u8; 16],
        resource_id: ResourceId,
        expected: ControlRecordId,
        record: Vec<u8>,
        out: &Outbound,
    ) -> Flow {
        let committed = self
            .shared
            .coordinator
            .put(
                resource_id,
                expected,
                record,
                self.conn,
                &*self.shared.random,
            )
            .await;
        match committed {
            Ok(committed) => {
                tracing::info!(
                    conn = self.conn,
                    resource = %resource_id.to_hex(),
                    record = %committed.id.to_hex(),
                    repeated = committed.repeated,
                    "Control Record committed"
                );
                self.send(
                    out,
                    Some(request),
                    Body::Ack(AckBody {
                        request_type: 23,
                        object_ids: Some(vec![Hash32::from_bytes(*committed.id.as_bytes())]),
                        durable: Some(true),
                    }),
                )
            }
            Err(failure) => self.nack_failure(out, request, failure),
        }
    }

    async fn on_control_have(
        &mut self,
        request: [u8; 16],
        resource_id: ResourceId,
        out: &Outbound,
    ) -> Flow {
        let principal = self.principal();
        if let Err(flow) = self.readable(request, resource_id, &principal, out).await {
            return flow;
        }
        match self.shared.coordinator.heads(resource_id).await {
            Ok(control_heads) => self.send(
                out,
                Some(request),
                Body::ControlHave {
                    resource_id,
                    control_heads,
                },
            ),
            Err(error) => self.internal(out, request, &error),
        }
    }

    /// CONTROL_GET (§45): every stored record in the range, competing ones
    /// included, sorted by sequence then record ID (§46), in as many
    /// CONTROL_BATCH replies as the message size limit needs.
    async fn on_control_get(
        &mut self,
        request: [u8; 16],
        resource_id: ResourceId,
        start: u64,
        end: u64,
        out: &Outbound,
    ) -> Flow {
        if end < start {
            return self.nack(out, request, WireCode::MalformedMessage);
        }
        let principal = self.principal();
        if let Err(flow) = self.readable(request, resource_id, &principal, out).await {
            return flow;
        }
        let records = match self
            .shared
            .coordinator
            .store()
            .control_records(resource_id, start, end)
            .await
        {
            Ok(records) => records,
            Err(error) => return self.internal(out, request, &error),
        };
        let records = records.into_iter().map(|r| r.bytes).collect();
        self.reply_in_batches(out, request, records, |records| Body::ControlBatch {
            resource_id,
            records,
        })
    }

    /// Validate every object first (nothing is stored if one fails), then
    /// the ingest policy; returns the held Resource lock with the chain.
    async fn admit<T>(
        &self,
        request: [u8; 16],
        resource_id: ResourceId,
        kind: ObjectKind,
        objects: &[Vec<u8>],
        validate: impl Fn(&Chain, ResourceId, &[u8]) -> Result<T, Error>,
        out: &Outbound,
    ) -> Result<(crate::coordinator::Locked, Vec<T>), Flow> {
        let locked = match self.shared.coordinator.lock(resource_id).await {
            Ok(locked) => locked,
            Err(failure) => return Err(self.nack_failure(out, request, failure)),
        };
        let Some(chain) = locked.chain.as_ref() else {
            return Err(self.nack(out, request, WireCode::ResourceNotHosted));
        };
        let mut valid = Vec::with_capacity(objects.len());
        for bytes in objects {
            match validate(chain, resource_id, bytes) {
                Ok(object) => valid.push(object),
                Err(error) => return Err(self.nack_error(out, request, &error)),
            }
        }
        let size = objects.iter().map(Vec::len).sum();
        if let Err(refusal) = self
            .shared
            .ingest
            .admit(&resource_id, kind, objects.len(), size)
        {
            return Err(self.nack(out, request, refusal.code()));
        }
        Ok((locked, valid))
    }

    fn ack(&self, out: &Outbound, request: [u8; 16], request_type: u64, ids: Vec<Hash32>) -> Flow {
        self.send(
            out,
            Some(request),
            Body::Ack(AckBody {
                request_type,
                object_ids: Some(ids),
                durable: Some(true),
            }),
        )
    }

    /// DATA_PUT (§51): all-or-nothing. Every unit is validated, then
    /// checked for equivocation (another signature-valid unit at its actor
    /// and sequence, stored or in the same request, §26.2). If any unit
    /// equivocates, only the equivocating units are stored, as evidence,
    /// nothing is pushed and the request is answered
    /// `NACK(ACTOR_EQUIVOCATION)`. Otherwise every unit is stored in one
    /// transaction, `ACK` (type 33, every unit ID, durable) follows, and new
    /// units are pushed to live Data subscribers.
    async fn on_data_put(
        &mut self,
        request: [u8; 16],
        resource_id: ResourceId,
        units: Vec<Vec<u8>>,
        out: &Outbound,
    ) -> Flow {
        let (locked, valid) = match self
            .admit(
                request,
                resource_id,
                ObjectKind::DataUnit,
                &units,
                ingest::data_unit,
                out,
            )
            .await
        {
            Ok(admitted) => admitted,
            Err(flow) => return flow,
        };
        let store = self.shared.coordinator.store();
        // Every unit ID per (actor, sequence) slot: stored, then requested.
        let mut slots: HashMap<(PrincipalId, u64), HashSet<Hash32>> = HashMap::new();
        for unit in &valid {
            let ids = match slots.entry((unit.actor, unit.sequence)) {
                Entry::Occupied(entry) => entry.into_mut(),
                Entry::Vacant(entry) => match store
                    .data_units_at(resource_id, unit.actor, unit.sequence)
                    .await
                {
                    Ok(ids) => entry.insert(ids.into_iter().collect()),
                    Err(error) => return self.internal(out, request, &error),
                },
            };
            ids.insert(Hash32::from_bytes(*unit.id.as_bytes()));
        }
        let equivocates = |unit: &ingest::ValidUnit| slots[&(unit.actor, unit.sequence)].len() > 1;
        if valid.iter().any(equivocates) {
            let evidence: Vec<Vec<u8>> = units
                .into_iter()
                .zip(&valid)
                .filter(|(_, unit)| equivocates(unit))
                .map(|(bytes, _)| bytes)
                .collect();
            for unit in valid.iter().filter(|u| equivocates(u)) {
                tracing::warn!(
                    conn = self.conn,
                    actor = %unit.actor.to_hex(),
                    seq = unit.sequence,
                    "actor equivocation stored as evidence"
                );
            }
            if let Err(error) = store.put_data_units(evidence).await {
                return self.internal(out, request, &error);
            }
            drop(locked);
            return self.nack(out, request, WireCode::ActorEquivocation);
        }
        let puts = match store.put_data_units(units.clone()).await {
            Ok(puts) => puts,
            Err(error) => return self.internal(out, request, &error),
        };
        let fresh: Vec<Vec<u8>> = units
            .into_iter()
            .zip(puts)
            .filter(|(_, put)| *put == Put::Inserted)
            .map(|(bytes, _)| bytes)
            .collect();
        drop(locked);
        self.shared.coordinator.hub().push_data(
            resource_id,
            self.conn,
            &fresh,
            &*self.shared.random,
        );
        let ids = valid
            .iter()
            .map(|u| Hash32::from_bytes(*u.id.as_bytes()))
            .collect();
        self.ack(out, request, 33, ids)
    }

    /// KEY_PACKAGE_PUT (§54): validated, stored, `ACK` (type 42).
    async fn on_key_package_put(
        &mut self,
        request: [u8; 16],
        resource_id: ResourceId,
        packages: Vec<Vec<u8>>,
        out: &Outbound,
    ) -> Flow {
        let (_locked, ids) = match self
            .admit(
                request,
                resource_id,
                ObjectKind::KeyPackage,
                &packages,
                ingest::key_package,
                out,
            )
            .await
        {
            Ok(admitted) => admitted,
            Err(flow) => return flow,
        };
        let store = self.shared.coordinator.store();
        for bytes in packages {
            if let Err(error) = store.put_key_package(bytes).await {
                return self.internal(out, request, &error);
            }
        }
        self.ack(out, request, 42, ids)
    }

    /// SNAPSHOT_PUT (§57): validated, stored, `ACK` (type 52). The
    /// Snapshot never becomes Control state.
    async fn on_snapshot_put(
        &mut self,
        request: [u8; 16],
        resource_id: ResourceId,
        snapshot: Vec<u8>,
        out: &Outbound,
    ) -> Flow {
        let objects = [snapshot];
        let (_locked, ids) = match self
            .admit(
                request,
                resource_id,
                ObjectKind::Snapshot,
                &objects,
                ingest::snapshot,
                out,
            )
            .await
        {
            Ok(admitted) => admitted,
            Err(flow) => return flow,
        };
        let [snapshot] = objects;
        if let Err(error) = self.shared.coordinator.store().put_snapshot(snapshot).await {
            return self.internal(out, request, &error);
        }
        self.ack(out, request, 52, ids)
    }

    /// DATA_HAVE (§48): the client's Have must normalize (a reversed
    /// range or sequence 0 is malformed); answered with the server's.
    async fn on_data_have(
        &mut self,
        request: [u8; 16],
        resource_id: ResourceId,
        have: Vec<WireActorHave>,
        out: &Outbound,
    ) -> Flow {
        if HaveVector::from_wire(&have).is_err() {
            return self.nack(out, request, WireCode::MalformedMessage);
        }
        let principal = self.principal();
        if let Err(flow) = self.readable(request, resource_id, &principal, out).await {
            return flow;
        }
        match self
            .shared
            .coordinator
            .store()
            .data_sequences(resource_id)
            .await
        {
            Ok(sequences) => self.send(
                out,
                Some(request),
                Body::DataHave {
                    resource_id,
                    have: have_of(&sequences),
                },
            ),
            Err(error) => self.internal(out, request, &error),
        }
    }

    /// DATA_GET (§49): every stored unit in the ranges, equivocating ones
    /// included, in size-limited DATA_BATCH replies (§50). More than
    /// [`MAX_GET_RANGES`] ranges is refused before anything is loaded, and
    /// overlapping ranges of one actor are merged, so no unit is read twice.
    async fn on_data_get(
        &mut self,
        request: [u8; 16],
        resource_id: ResourceId,
        ranges: Vec<DataRange>,
        out: &Outbound,
    ) -> Flow {
        if ranges.len() > MAX_GET_RANGES || ranges.iter().any(|r| r.start == 0 || r.start > r.end) {
            return self.nack(out, request, WireCode::MalformedMessage);
        }
        let ranges = merge_ranges(ranges);
        let principal = self.principal();
        if let Err(flow) = self.readable(request, resource_id, &principal, out).await {
            return flow;
        }
        let store = self.shared.coordinator.store();
        let mut units = Vec::new();
        for range in ranges {
            match store
                .data_units_in(resource_id, range.principal, range.start, range.end)
                .await
            {
                Ok(found) => units.extend(found),
                Err(error) => return self.internal(out, request, &error),
            }
        }
        let units = unique(units);
        self.reply_in_batches(out, request, units, |units| Body::DataBatch {
            resource_id,
            units,
        })
    }

    /// KEY_PACKAGE_GET (§52): every stored package for the requested
    /// epochs, served only to their recipient. Each epoch is looked up
    /// once; more than [`MAX_GET_EPOCHS`] distinct epochs is refused before
    /// anything is loaded.
    async fn on_key_package_get(
        &mut self,
        request: [u8; 16],
        resource_id: ResourceId,
        recipient: PrincipalId,
        mut epochs: Vec<u64>,
        out: &Outbound,
    ) -> Flow {
        epochs.sort_unstable();
        epochs.dedup();
        if epochs.len() > MAX_GET_EPOCHS {
            return self.nack(out, request, WireCode::MalformedMessage);
        }
        let principal = self.principal();
        if let Err(flow) = self.readable(request, resource_id, &principal, out).await {
            return flow;
        }
        if recipient != principal {
            return self.nack(out, request, WireCode::AuthorizationFailed);
        }
        let store = self.shared.coordinator.store();
        let mut packages = Vec::new();
        for epoch in epochs {
            match store.key_packages_for(resource_id, epoch, recipient).await {
                Ok(found) => packages.extend(found),
                Err(error) => return self.internal(out, request, &error),
            }
        }
        let packages = unique(packages);
        self.reply_in_batches(out, request, packages, |packages| Body::KeyPackageBatch {
            resource_id,
            packages,
        })
    }

    /// SNAPSHOT_GET (§55): the named Snapshot of this Resource, or the
    /// preferred latest one. None stored is `NACK(MISSING_DEPENDENCY)`.
    async fn on_snapshot_get(
        &mut self,
        request: [u8; 16],
        resource_id: ResourceId,
        snapshot_id: Option<Hash32>,
        out: &Outbound,
    ) -> Flow {
        let principal = self.principal();
        if let Err(flow) = self.readable(request, resource_id, &principal, out).await {
            return flow;
        }
        let store = self.shared.coordinator.store();
        let found = match snapshot_id {
            Some(id) => store.snapshot(id).await.map(|bytes| {
                bytes.filter(|b| {
                    ReceivedSnapshot::parse(b).is_ok_and(|s| s.header().resource_id == resource_id)
                })
            }),
            None => store
                .snapshots(resource_id)
                .await
                .map(|all| all.into_iter().next().map(|s| s.bytes)),
        };
        match found {
            Ok(Some(snapshot)) => self.send(
                out,
                Some(request),
                Body::Snapshot {
                    resource_id,
                    snapshot,
                },
            ),
            Ok(None) => self.nack(out, request, WireCode::MissingDependency),
            Err(error) => self.internal(out, request, &error),
        }
    }

    /// Send `objects` as correlated batches within the message size limit.
    fn reply_in_batches(
        &self,
        out: &Outbound,
        request: [u8; 16],
        objects: Vec<Vec<u8>>,
        body: impl Fn(Vec<Vec<u8>>) -> Body,
    ) -> Flow {
        let budget = usize::try_from(self.shared.ready.max_message_bytes)
            .unwrap_or(usize::MAX)
            .saturating_sub(BATCH_OVERHEAD);
        for batch in batches(objects, budget) {
            if self.send(out, Some(request), body(batch)) == Flow::Close {
                return Flow::Close;
            }
        }
        Flow::Continue
    }

    fn principal(&self) -> PrincipalId {
        self.authenticated
            .as_ref()
            .map(|a| *a.principal.id())
            .expect("Control messages pass server_accepts only after READY")
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
            // READY (§64: MALFORMED_MESSAGE, close; a server never accepts
            // CHALLENGE or READY from a client).
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
            Body::ControlPut {
                resource_id,
                expected_head,
                record,
            } => {
                self.on_control_put(id, resource_id, expected_head, record, out)
                    .await
            }
            Body::ControlHave { resource_id, .. } => {
                self.on_control_have(id, resource_id, out).await
            }
            Body::ControlGet {
                resource_id,
                start,
                end,
            } => self.on_control_get(id, resource_id, start, end, out).await,
            Body::DataPut { resource_id, units } => {
                self.on_data_put(id, resource_id, units, out).await
            }
            Body::DataHave { resource_id, have } => {
                self.on_data_have(id, resource_id, have, out).await
            }
            Body::DataGet {
                resource_id,
                ranges,
            } => self.on_data_get(id, resource_id, ranges, out).await,
            Body::KeyPackagePut {
                resource_id,
                packages,
            } => {
                self.on_key_package_put(id, resource_id, packages, out)
                    .await
            }
            Body::KeyPackageGet {
                resource_id,
                recipient,
                epochs,
            } => {
                self.on_key_package_get(id, resource_id, recipient, epochs, out)
                    .await
            }
            Body::SnapshotPut {
                resource_id,
                snapshot,
            } => self.on_snapshot_put(id, resource_id, snapshot, out).await,
            Body::SnapshotGet {
                resource_id,
                snapshot_id,
            } => {
                self.on_snapshot_get(id, resource_id, snapshot_id, out)
                    .await
            }
            // Server-to-client responses.
            Body::ResourceHosted { .. } | Body::ResourceOpened { .. } => {
                self.nack(out, id, WireCode::MalformedMessage)
            }
            // Mirror seeding (client CONTROL/DATA/KEY_PACKAGE_BATCH and
            // SNAPSHOT, §46) and presence (§58) are not offered.
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
        let hub = self.shared.coordinator.hub();
        for (resource, _) in self.subscriptions.drain() {
            hub.unsubscribe(resource, self.conn);
        }
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

/// The most ranges a DATA_GET may carry: §49 says a request SHOULD carry
/// no more than 256; a longer one is `NACK(MALFORMED_MESSAGE)` (§62 code 2).
pub const MAX_GET_RANGES: usize = 256;

/// The most distinct Data Epochs a KEY_PACKAGE_GET may name. §52 sets no
/// count; the server applies the §49 range limit, with the same
/// `NACK(MALFORMED_MESSAGE)`.
pub const MAX_GET_EPOCHS: usize = 256;

/// Each actor's ranges merged where they overlap or touch, actors in order
/// of first appearance, ranges ascending.
fn merge_ranges(ranges: Vec<DataRange>) -> Vec<DataRange> {
    let mut by_actor: Vec<(PrincipalId, Vec<(u64, u64)>)> = Vec::new();
    for range in ranges {
        match by_actor
            .iter_mut()
            .find(|(actor, _)| *actor == range.principal)
        {
            Some((_, spans)) => spans.push((range.start, range.end)),
            None => by_actor.push((range.principal, vec![(range.start, range.end)])),
        }
    }
    let mut merged = Vec::new();
    for (principal, mut spans) in by_actor {
        spans.sort_unstable();
        let mut current = spans[0];
        for (start, end) in spans.into_iter().skip(1) {
            if start <= current.1.saturating_add(1) {
                current.1 = current.1.max(end);
            } else {
                merged.push(DataRange {
                    principal,
                    start: current.0,
                    end: current.1,
                });
                current = (start, end);
            }
        }
        merged.push(DataRange {
            principal,
            start: current.0,
            end: current.1,
        });
    }
    merged
}

/// Room for the envelope and the CONTROL_BATCH body around the records.
const BATCH_OVERHEAD: usize = 1024;

/// Split `items` into batches whose total size (with a few bytes of CBOR
/// framing each) stays within `budget`; an item is never split, and there
/// is always at least one batch, possibly empty.
fn batches(items: impl IntoIterator<Item = Vec<u8>>, budget: usize) -> Vec<Vec<Vec<u8>>> {
    let mut batches = vec![Vec::new()];
    let mut size = 0;
    for item in items {
        let cost = item.len() + 9;
        let current = batches.last_mut().expect("never empty");
        if !current.is_empty() && size + cost > budget {
            batches.push(Vec::new());
            size = 0;
        }
        size += cost;
        batches.last_mut().expect("never empty").push(item);
    }
    batches
}

/// The objects' bytes, each object once, in order.
fn unique(objects: Vec<StoredObject>) -> Vec<Vec<u8>> {
    let mut seen = HashSet::new();
    objects
        .into_iter()
        .filter(|o| seen.insert(o.id))
        .map(|o| o.bytes)
        .collect()
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
    use lfcp::wire::control::body::{ControlBody, Endpoint, GenesisBody};
    use lfcp::wire::control::{ControlRecord, ControlRecordHeader};
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

    #[test]
    fn data_ranges_merge_per_actor() {
        let (a, b) = (
            PrincipalId::from_bytes([1; 32]),
            PrincipalId::from_bytes([2; 32]),
        );
        let r = |principal, start, end| DataRange {
            principal,
            start,
            end,
        };
        let spans = |ranges: Vec<DataRange>| -> Vec<(PrincipalId, u64, u64)> {
            merge_ranges(ranges)
                .into_iter()
                .map(|r| (r.principal, r.start, r.end))
                .collect()
        };
        assert_eq!(
            spans(vec![
                r(b, 5, 9),
                r(a, 10, 20),
                r(a, 1, 3),
                r(b, 1, 2),
                r(a, 4, 4),
                r(a, 15, 30),
                r(b, 5, 9),
                r(a, 40, u64::MAX),
                r(a, 32, 39),
            ]),
            vec![
                (b, 1, 2),
                (b, 5, 9),
                (a, 1, 4),
                (a, 10, 30),
                (a, 32, u64::MAX),
            ]
        );
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
