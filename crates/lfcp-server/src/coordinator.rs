//! The Control Coordinator (WIRE-01 §21, §47): durable compare-and-swap of
//! each hosted Resource's Control Head, the cached Control state the
//! session authorizes against, and live pushes to subscribed sessions.
//!
//! `CONTROL_PUT`, in order:
//!
//! | Step | Failure | § |
//! | --- | --- | --- |
//! | the Resource is hosted here | `RESOURCE_NOT_HOSTED` | §41, §62 |
//! | this server is its current coordinator ([`Coordinator::is_me`]) | `NOT_CONTROL_COORDINATOR`, details = the coordinator URL | §21 |
//! | the record parses and is not Genesis | `MALFORMED_MESSAGE` (Genesis uses RESOURCE_HOST) | §47 |
//! | the record is already on the accepted chain | none: the same `ACK` again (at-least-once delivery) | §70 |
//! | sdk-rs `propose_transition`: expected head, placement, signature, authority, one-time claims | `CONTROL_HEAD_MISMATCH` (details = current head), `INVALID_CONTROL_CHAIN`, `INVALID_SIGNATURE`, `AUTHORIZATION_FAILED`, `PROTOCOL_UNSUPPORTED` (types 7/8, DV1), … | §13, §17–§23, §47 |
//! | the store's compare-and-set commit (one SQLite transaction) | `CONTROL_HEAD_MISMATCH` if the head moved | §47 |
//!
//! Atomicity: puts for one Resource are serialized by a per-Resource lock,
//! and the commit itself re-checks the expected head inside one SQLite
//! transaction ([`Store::commit_control_record`]). The record is validated
//! against the state at the expected head; the commit succeeds only if the
//! head is still that one, so a validation can never be applied to a head
//! that moved. The `ACK` is sent only after the commit returned (WAL,
//! `synchronous = FULL`).
//!
//! A put that loses the compare-and-swap is not stored. §13.2 fork evidence
//! is two validly signed records on one predecessor that both exist in the
//! world; a losing put is a proposal the coordinator refused, never a
//! committed record, and storing it would make RESOURCE_OPENED report a
//! fork that the coordinator prevented. Fork evidence enters the store only
//! through its own ingest path.
//!
//! Coordinator recovery (§22) is deferred in MVP 0.1; its records are
//! refused by the capability engine (DV1).

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use lfcp::base::{ChainRule, ControlRecordId, Error, PrincipalId, ResourceId};
use lfcp::wire::control::authority::{
    ability, propose_transition, validate_authorized, ControlState,
};
use lfcp::wire::control::body::ControlBody;
use lfcp::wire::control::chain::ChainOutcome;
use lfcp::wire::control::{ControlRecord, ReceivedControlRecord};
use lfcp::wire::message::{Body, ControlHead, Message};

use crate::rng::Random;
use crate::store::{CasOutcome, Store, StoreError, StoredControlRecord};
use crate::ws::Outbound;

/// The RESOURCE_OPEN flag for live Data Plane pushes (§41, bit 0).
pub const LIVE_DATA: u64 = 1;

/// The RESOURCE_OPEN flag for live Control Plane pushes (§41, bit 1).
pub const LIVE_CONTROL: u64 = 1 << 1;

/// A WebSocket URL in comparable form: lower-case `ws` or `wss` scheme and
/// host, the default port (80, 443) dropped, an empty path as `/`, the path
/// and query otherwise exact. `None` for anything else, including user
/// info and fragments.
///
/// This is how the server decides whether a Resource's Control Coordinator
/// URL (§15, §20) names it: one of the configured `public_urls` must
/// normalize to the same string. Host names are not resolved, so a server
/// reachable under several names lists each of them.
pub fn normalize_url(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    let default_port = match scheme.as_str() {
        "ws" => "80",
        "wss" => "443",
        _ => return None,
    };
    if rest.contains('#') {
        return None;
    }
    let split = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, path) = rest.split_at(split);
    if authority.is_empty() || authority.contains('@') || authority.contains(char::is_whitespace) {
        return None;
    }
    // The port is after the last ':' outside an IPv6 literal.
    let (host, port) = match authority.rfind(':') {
        Some(i) if !authority[i..].contains(']') => (&authority[..i], Some(&authority[i + 1..])),
        _ => (authority, None),
    };
    if host.is_empty() {
        return None;
    }
    let port = match port {
        Some(p) if p.is_empty() || !p.chars().all(|c| c.is_ascii_digit()) => return None,
        Some(p) if p == default_port => String::new(),
        Some(p) => format!(":{p}"),
        None => String::new(),
    };
    let path = if path.is_empty() || path.starts_with('?') {
        format!("/{path}")
    } else {
        path.to_owned()
    };
    Some(format!(
        "{scheme}://{}{port}{path}",
        host.to_ascii_lowercase()
    ))
}

/// The accepted Control Chain of a hosted Resource, at the stored head.
#[derive(Clone, Debug)]
pub struct Chain {
    /// The Control state after every accepted record, Genesis first: the
    /// sdk-rs ingest policies evaluate objects at their referenced head.
    history: Vec<ControlState>,
    /// The current Control Coordinator URL.
    pub coordinator: String,
    accepted: HashSet<ControlRecordId>,
}

impl Chain {
    fn build(records: &[StoredControlRecord], head: ControlRecordId) -> Result<Chain, Error> {
        let by_id: HashMap<ControlRecordId, &StoredControlRecord> =
            records.iter().map(|r| (r.id, r)).collect();
        // The accepted chain: from the head back to Genesis.
        let mut path = Vec::new();
        let mut next = Some(head);
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
        if states.is_empty() {
            return Err(Error::UnknownControlHead);
        }
        let coordinator = coordinator_of(&chain.records).ok_or(Error::UnknownControlHead)?;
        Ok(Chain {
            history: states,
            coordinator,
            accepted: chain.records.iter().map(ControlRecord::id).collect(),
        })
    }

    /// The Control state at the accepted head.
    pub fn state(&self) -> &ControlState {
        self.history.last().expect("a chain has at least Genesis")
    }

    /// The state after every accepted record.
    pub fn history(&self) -> &[ControlState] {
        &self.history
    }

    /// The accepted head.
    pub fn head(&self) -> ControlHead {
        let head = self.state().head;
        ControlHead {
            sequence: head.sequence,
            id: head.id,
        }
    }

    /// The descriptor of a Principal the chain names, else
    /// `MISSING_DEPENDENCY` (§13.1).
    pub fn principal(
        &self,
        id: &PrincipalId,
    ) -> Result<&lfcp::principal::PrincipalDescriptor, Error> {
        self.state().principal(id).ok_or(Error::IssuerUnknown(*id))
    }

    /// Whether `record` is on the accepted chain.
    pub fn contains(&self, record: &ControlRecordId) -> bool {
        self.accepted.contains(record)
    }

    /// §84 read authorization at the accepted head: `data/read`, or the
    /// subject of an invitation grant that still confers `invite/claim`
    /// (§73: the Invitation Principal opens the Resource to claim).
    pub fn may_read(&self, principal: &PrincipalId) -> bool {
        let state = self.state();
        state.holds(principal, ability::DATA_READ)
            || state
                .grants()
                .any(|g| &g.subject == principal && state.confers_invite(g))
    }
}

/// The coordinator of the last Genesis, Route Update or Coordinator
/// Recovery on the chain.
fn coordinator_of(records: &[ControlRecord]) -> Option<String> {
    records.iter().rev().find_map(|r| coordinator_in(r.body()))
}

/// The coordinator URL a record sets, if it sets one.
fn coordinator_in(body: &ControlBody) -> Option<String> {
    match body {
        ControlBody::Genesis(b) => Some(b.coordinator.clone()),
        ControlBody::RouteUpdate(b) => Some(b.coordinator.clone()),
        ControlBody::CoordinatorRecovery(b) => Some(b.coordinator.clone()),
        _ => None,
    }
}

/// Why a Coordinator operation failed.
#[derive(Debug)]
pub enum Failure {
    /// The Resource is not hosted here.
    NotHosted,
    /// This server is not the Resource's coordinator; the current one.
    NotCoordinator(String),
    /// A Genesis was sent with CONTROL_PUT.
    Genesis,
    /// An LFCP error with its wire code.
    Lfcp(Error),
    /// The store failed.
    Store(StoreError),
}

impl From<StoreError> for Failure {
    fn from(error: StoreError) -> Failure {
        Failure::Store(error)
    }
}

/// A committed CONTROL_PUT.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Committed {
    /// The record ID.
    pub id: ControlRecordId,
    /// Whether the record was already on the chain (a repeated put).
    pub repeated: bool,
}

/// A held Resource lock ([`Coordinator::lock`]).
pub struct Locked {
    _guard: tokio::sync::OwnedMutexGuard<Option<Chain>>,
    /// The accepted chain, if the Resource is hosted.
    pub chain: Option<Chain>,
}

/// One Resource's cached chain; its lock serializes the Resource's puts.
type Slot = Arc<tokio::sync::Mutex<Option<Chain>>>;

/// The server's Control Coordinator, shared by every session.
pub struct Coordinator {
    store: Arc<Store>,
    public_urls: Vec<String>,
    slots: Mutex<HashMap<ResourceId, Slot>>,
    hub: Hub,
}

impl Coordinator {
    /// A coordinator on `store` for the Resources whose coordinator URL is
    /// one of `public_urls`.
    pub fn new(store: Arc<Store>, public_urls: &[String]) -> Coordinator {
        Coordinator {
            store,
            public_urls: public_urls
                .iter()
                .filter_map(|u| normalize_url(u))
                .collect(),
            slots: Mutex::new(HashMap::new()),
            hub: Hub::default(),
        }
    }

    /// The store.
    pub fn store(&self) -> &Arc<Store> {
        &self.store
    }

    /// The live-push subscriptions.
    pub fn hub(&self) -> &Hub {
        &self.hub
    }

    /// Whether `coordinator_url` names this server.
    pub fn is_me(&self, coordinator_url: &str) -> bool {
        normalize_url(coordinator_url).is_some_and(|url| self.public_urls.contains(&url))
    }

    fn slot(&self, resource: ResourceId) -> Slot {
        self.slots
            .lock()
            .expect("the slot map is never poisoned")
            .entry(resource)
            .or_default()
            .clone()
    }

    /// The chain at the stored head, from the cache unless the head moved.
    async fn load(
        &self,
        cached: &mut Option<Chain>,
        resource: ResourceId,
    ) -> Result<Option<Chain>, Failure> {
        let Some(head) = self.store.head(resource).await? else {
            return Ok(None);
        };
        if let Some(chain) = cached.as_ref().filter(|c| c.state().head.id == head.id) {
            return Ok(Some(chain.clone()));
        }
        let records = self.store.control_records(resource, 0, head.seq).await?;
        let chain = Chain::build(&records, head.id).map_err(Failure::Lfcp)?;
        *cached = Some(chain.clone());
        Ok(Some(chain))
    }

    /// Take `resource`'s lock and its accepted chain (`None` if not
    /// hosted). Control commits and object ingest for the Resource wait
    /// while it is held, so an object is never validated against a head
    /// that a concurrent commit (a Key Epoch, a Revoke) has superseded.
    pub async fn lock(&self, resource: ResourceId) -> Result<Locked, Failure> {
        let mut guard = self.slot(resource).lock_owned().await;
        let chain = self.load(&mut guard, resource).await?;
        Ok(Locked {
            _guard: guard,
            chain,
        })
    }

    /// The accepted chain of a hosted Resource.
    pub async fn chain(&self, resource: ResourceId) -> Result<Option<Chain>, Failure> {
        let slot = self.slot(resource);
        let mut cached = slot.lock().await;
        self.load(&mut cached, resource).await
    }

    /// Every Control Head the server knows: the accepted head and the tip
    /// of each competing branch it stores as evidence (§13.2, §42, §44).
    pub async fn heads(&self, resource: ResourceId) -> Result<Vec<ControlHead>, StoreError> {
        let records = self.store.control_records(resource, 0, u64::MAX).await?;
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
        Ok(heads)
    }

    /// CONTROL_PUT (§47): validate `record` against the state at `expected`
    /// and commit it as the new head, then push it to the Resource's live
    /// Control subscribers other than connection `origin`.
    pub async fn put(
        &self,
        resource: ResourceId,
        expected: ControlRecordId,
        record: Vec<u8>,
        origin: u64,
        random: &dyn Random,
    ) -> Result<Committed, Failure> {
        let slot = self.slot(resource);
        let mut cached = slot.lock().await;
        let Some(chain) = self.load(&mut cached, resource).await? else {
            return Err(Failure::NotHosted);
        };
        if !self.is_me(&chain.coordinator) {
            return Err(Failure::NotCoordinator(chain.coordinator));
        }
        let parsed = ReceivedControlRecord::parse(&record).map_err(Failure::Lfcp)?;
        if matches!(parsed.body(), ControlBody::Genesis(_)) {
            return Err(Failure::Genesis);
        }
        let id = parsed.id();
        if chain.contains(&id) {
            return Ok(Committed { id, repeated: true });
        }
        let next = propose_transition(chain.state(), expected, &record).map_err(Failure::Lfcp)?;
        match self
            .store
            .commit_control_record(record.clone(), expected)
            .await?
        {
            CasOutcome::Committed(_) => {
                let mut chain = chain;
                chain.history.push(next);
                chain.accepted.insert(id);
                // Verified by propose_transition above.
                if let Some(url) = coordinator_in(parsed.body()) {
                    chain.coordinator = url;
                }
                // Stop pushing to subscribers that just lost read
                // authority, then push the record to the others.
                self.hub.revalidate(resource, &chain);
                *cached = Some(chain);
                self.hub.push_control(resource, origin, &record, random);
                Ok(Committed {
                    id,
                    repeated: false,
                })
            }
            // Another writer moved the head outside this lock (the store is
            // shared); nothing was committed.
            CasOutcome::HeadMismatch { current } => {
                *cached = None;
                Err(Failure::Lfcp(Error::ControlHeadMismatch {
                    current: current.id,
                }))
            }
            CasOutcome::NotSuccessor => {
                *cached = None;
                Err(Failure::Lfcp(Error::InvalidControlChain(
                    ChainRule::PreviousMismatch,
                )))
            }
        }
    }
}

/// A session subscribed to a Resource's live pushes.
struct Subscriber {
    flags: u64,
    principal: PrincipalId,
    out: Outbound,
}

/// Per Resource, per connection.
type Subscribers = HashMap<ResourceId, HashMap<u64, Subscriber>>;

/// Live-push subscriptions: per Resource, the connections that opened it
/// with their RESOURCE_OPEN flags, session Principal and outbound handle
/// (§41, §69).
///
/// Revalidation: after every committed Control Record the subscribers'
/// read authority is checked again at the new head; a subscriber that lost
/// it is dropped silently. §43 has no server-initiated close, so its
/// session stays open and its next request for the Resource is refused
/// with `AUTHORIZATION_FAILED`.
#[derive(Default)]
pub struct Hub {
    subscribers: Mutex<Subscribers>,
}

impl Hub {
    /// Connection `conn`, authenticated as `principal`, opened `resource`
    /// with `flags`.
    pub fn subscribe(
        &self,
        resource: ResourceId,
        conn: u64,
        flags: u64,
        principal: PrincipalId,
        out: Outbound,
    ) {
        self.lock().entry(resource).or_default().insert(
            conn,
            Subscriber {
                flags,
                principal,
                out,
            },
        );
    }

    /// Connection `conn` closed `resource`, or the connection ended.
    pub fn unsubscribe(&self, resource: ResourceId, conn: u64) {
        let mut subscribers = self.lock();
        if let Some(by_conn) = subscribers.get_mut(&resource) {
            by_conn.remove(&conn);
            if by_conn.is_empty() {
                subscribers.remove(&resource);
            }
        }
    }

    /// Whether connection `conn` receives pushes for `resource`.
    pub fn is_subscribed(&self, resource: ResourceId, conn: u64) -> bool {
        self.lock()
            .get(&resource)
            .is_some_and(|by_conn| by_conn.contains_key(&conn))
    }

    /// The number of connections subscribed to `resource`.
    pub fn subscribers(&self, resource: ResourceId) -> usize {
        self.lock().get(&resource).map_or(0, HashMap::len)
    }

    /// Drop the subscribers of `resource` that no longer have read
    /// authority in `chain`. Returns their connections.
    pub fn revalidate(&self, resource: ResourceId, chain: &Chain) -> Vec<u64> {
        let mut subscribers = self.lock();
        let Some(by_conn) = subscribers.get_mut(&resource) else {
            return Vec::new();
        };
        let lost: Vec<u64> = by_conn
            .iter()
            .filter(|(_, s)| !chain.may_read(&s.principal))
            .map(|(&conn, _)| conn)
            .collect();
        for conn in &lost {
            tracing::info!(conn, "read authority lost; live pushes stop");
            by_conn.remove(conn);
        }
        lost
    }

    /// Push a committed Control Record as a one-record CONTROL_BATCH to the
    /// live Control subscribers (flag bit 1) of `resource` except `origin`.
    pub fn push_control(
        &self,
        resource: ResourceId,
        origin: u64,
        record: &[u8],
        random: &dyn Random,
    ) -> usize {
        self.push(resource, origin, LIVE_CONTROL, random, || {
            Body::ControlBatch {
                resource_id: resource,
                records: vec![record.to_vec()],
            }
        })
    }

    /// Push accepted Data Units as one DATA_BATCH to the live Data
    /// subscribers (flag bit 0) of `resource` except `origin` (§50, §69).
    pub fn push_data(
        &self,
        resource: ResourceId,
        origin: u64,
        units: &[Vec<u8>],
        random: &dyn Random,
    ) -> usize {
        if units.is_empty() {
            return 0;
        }
        self.push(resource, origin, LIVE_DATA, random, || Body::DataBatch {
            resource_id: resource,
            units: units.to_vec(),
        })
    }

    /// Never waits: a subscriber whose queue is full is aborted (closed)
    /// and removed rather than skipped silently. Returns the number of
    /// pushes.
    fn push(
        &self,
        resource: ResourceId,
        origin: u64,
        flag: u64,
        random: &dyn Random,
        body: impl Fn() -> Body,
    ) -> usize {
        let mut subscribers = self.lock();
        let Some(by_conn) = subscribers.get_mut(&resource) else {
            return 0;
        };
        let mut pushed = 0;
        let mut dropped = Vec::new();
        for (&conn, subscriber) in by_conn.iter() {
            if conn == origin || subscriber.flags & flag == 0 {
                continue;
            }
            let Ok(id) = random.nonce16() else {
                continue;
            };
            match subscriber.out.send(Message::new(id, body())) {
                Ok(()) => pushed += 1,
                Err(_) => {
                    tracing::info!(conn, "live push overflow; closing the subscriber");
                    subscriber.out.abort();
                    dropped.push(conn);
                }
            }
        }
        for conn in dropped {
            by_conn.remove(&conn);
        }
        pushed
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Subscribers> {
        self.subscribers.lock().expect("the hub is never poisoned")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::OsRandom;
    use crate::ws::test_outbound;

    #[test]
    fn urls_normalize() {
        let n = |u: &str| normalize_url(u);
        assert_eq!(
            n("wss://Sync.Example.TEST/v1/ws").as_deref(),
            Some("wss://sync.example.test/v1/ws")
        );
        assert_eq!(
            n("WSS://sync.example.test:443/v1/ws"),
            n("wss://sync.example.test/v1/ws")
        );
        assert_eq!(n("ws://127.0.0.1:80"), Some("ws://127.0.0.1/".into()));
        assert_eq!(
            n("ws://127.0.0.1:7820/v1/ws").as_deref(),
            Some("ws://127.0.0.1:7820/v1/ws")
        );
        assert_eq!(
            n("ws://[::1]:7820/v1/ws").as_deref(),
            Some("ws://[::1]:7820/v1/ws")
        );
        assert_eq!(n("ws://[::1]/v1/ws").as_deref(), Some("ws://[::1]/v1/ws"));
        assert_ne!(
            n("wss://sync.example.test/v1/ws"),
            n("wss://sync.example.test/v1/WS")
        );
        assert_ne!(
            n("wss://sync.example.test/v1/ws"),
            n("ws://sync.example.test/v1/ws")
        );
        for bad in [
            "https://sync.example.test/v1/ws",
            "wss://user@sync.example.test/v1/ws",
            "wss://sync.example.test/v1/ws#x",
            "wss:///v1/ws",
            "wss://host:port/v1/ws",
            "sync.example.test/v1/ws",
        ] {
            assert_eq!(n(bad), None, "{bad}");
        }
    }

    #[test]
    fn a_full_subscriber_is_aborted_and_dropped() {
        let hub = Hub::default();
        let resource = ResourceId::from_bytes([1; 32]);
        let (slow, _slow_inbox) = test_outbound(1);
        let (fast, mut fast_inbox) = test_outbound(8);
        let (origin, mut origin_inbox) = test_outbound(8);
        let (quiet, mut quiet_inbox) = test_outbound(8);
        let p = PrincipalId::from_bytes([2; 32]);
        hub.subscribe(resource, 1, LIVE_CONTROL, p, slow.clone());
        hub.subscribe(resource, 2, LIVE_CONTROL | LIVE_DATA, p, fast);
        hub.subscribe(resource, 3, LIVE_CONTROL, p, origin);
        hub.subscribe(resource, 4, LIVE_DATA, p, quiet);

        assert_eq!(hub.push_control(resource, 3, b"r1", &OsRandom), 2);
        assert!(!slow.is_aborted());
        // The slow subscriber's queue (1) is full now.
        assert_eq!(hub.push_control(resource, 3, b"r2", &OsRandom), 1);
        assert!(slow.is_aborted());
        assert_eq!(hub.subscribers(resource), 3);

        let mut got = Vec::new();
        while let Ok(out) = fast_inbox.try_recv() {
            match out.into_message().unwrap().body {
                Body::ControlBatch { records, .. } => got.extend(records),
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(got, vec![b"r1".to_vec(), b"r2".to_vec()]);
        assert!(origin_inbox.try_recv().is_err(), "not pushed to its origin");
        assert!(quiet_inbox.try_recv().is_err(), "no live Control flag");

        hub.unsubscribe(resource, 2);
        hub.unsubscribe(resource, 3);
        hub.unsubscribe(resource, 4);
        assert_eq!(hub.subscribers(resource), 0);
    }
}
