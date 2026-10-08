//! Ingest validation of persistent objects (WIRE-01 §25, §26, §29, §51,
//! §54, §57), with sdk-rs, against the Resource's accepted Control Chain.
//! The server never decrypts and never holds a DEK: Data Unit, Key Package
//! and Snapshot ciphertexts stay opaque.
//!
//! | Object | Checks | Failure |
//! | --- | --- | --- |
//! | every object | canonical COSE and closed payload (sdk-rs parse); the Resource ID is the request's | `MALFORMED_MESSAGE` |
//! | | the signer (actor, sender, publisher) is a Principal the chain names | `MISSING_DEPENDENCY` (§13.1) |
//! | | `kid` = signer, strict Ed25519 (§10.5.1) | `INVALID_SIGNATURE` |
//! | | the referenced Control Head is on the accepted chain, its epoch known there | `MISSING_DEPENDENCY` |
//! | Data Unit | `data/write` at the unit's referenced head (an older head is fine) | `AUTHORIZATION_FAILED` (§26.3) |
//! | | closed epoch: within the actor's cutoff in the latest state (G-EP1) | `STALE_DATA_EPOCH` (§19.1, §75) |
//! | Key Package | sender `key/distribute`; recipient `data/read` or an invitation subject (G-CAP9), at its head | `AUTHORIZATION_FAILED` (§25.2) |
//! | Snapshot | publisher `snapshot/publish` at its head; sequence ≥ 1 | `AUTHORIZATION_FAILED` (§29.2), `MALFORMED_MESSAGE` |
//! | | closed epoch: the frontier within the epoch's cutoff, in the latest state | `STALE_DATA_EPOCH` (§29, G-EP4) |
//!
//! Not checked here, by design: AEAD (§26.3 step 6, client-local, N3), the
//! HPKE recipient binding (N5) and the Data Profile (step 7). Actor hash
//! chain gaps (§26.2) are the sync engine's; equivocation is detected, and
//! a `previous` the server does not hold refused (§51.1,
//! `UNKNOWN_PREVIOUS`), against the store under the Resource lock
//! ([`crate::session`]).
//!
//! Server-local limits ([`IngestPolicy`]: quotas, rate limits) are not LFCP
//! capabilities and fail with their own codes.

use lfcp::base::{DataUnitId, Error, Hash32, PrincipalId, ResourceId, WireCode};
use lfcp::wire::control::authority::{data_unit_policy, key_package_policy, snapshot_policy};
use lfcp::wire::data_unit::{DataUnitHeader, ReceivedDataUnit};
use lfcp::wire::key_package::ReceivedKeyPackage;
use lfcp::wire::snapshot::ReceivedSnapshot;

use crate::coordinator::Chain;

/// A validated Data Unit: what storing and equivocation detection need.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidUnit {
    /// The Data Unit ID.
    pub id: DataUnitId,
    /// The actor.
    pub actor: PrincipalId,
    /// The actor sequence.
    pub sequence: u64,
    /// The unit's authenticated header, for the `previous` link check
    /// (§51.1).
    pub header: DataUnitHeader,
}

/// Validate a Data Unit of `resource` (§26.3 steps 1–5, §51).
pub fn data_unit(chain: &Chain, resource: ResourceId, bytes: &[u8]) -> Result<ValidUnit, Error> {
    let unit = ReceivedDataUnit::parse(bytes)?;
    let header = unit.header().clone();
    if header.resource_id != resource {
        return Err(Error::MessageMalformed);
    }
    let actor = chain.principal(&header.actor)?.clone();
    let id = unit.id();
    // data/write at the referenced head, then the epoch: known at that
    // head, and within the cutoff of the latest state if since closed (the
    // classification server_accepts_data_put applies).
    unit.verify_with(&actor, data_unit_policy(chain.history()))?;
    Ok(ValidUnit {
        id,
        actor: header.actor,
        sequence: header.sequence,
        header,
    })
}

/// Validate a Key Package of `resource` (§25.2, §54). Returns its ID.
pub fn key_package(chain: &Chain, resource: ResourceId, bytes: &[u8]) -> Result<Hash32, Error> {
    let package = ReceivedKeyPackage::parse(bytes)?;
    if package.header().resource_id != resource {
        return Err(Error::MessageMalformed);
    }
    let sender = chain.principal(&package.header().sender)?.clone();
    let id = package.id();
    package.verify(&sender, key_package_policy(chain.history()))?;
    Ok(id)
}

/// Validate a Snapshot of `resource` (§29, §29.2, §57, G-EP4). Returns its
/// ID.
pub fn snapshot(chain: &Chain, resource: ResourceId, bytes: &[u8]) -> Result<Hash32, Error> {
    let snapshot = ReceivedSnapshot::parse(bytes)?;
    if snapshot.header().resource_id != resource {
        return Err(Error::MessageMalformed);
    }
    let publisher = chain.principal(&snapshot.header().publisher)?.clone();
    let id = snapshot.id();
    // §29.2 publish authority and the §29 (G-EP4) cutoff, both in sdk-rs.
    snapshot.verify_with(&publisher, snapshot_policy(chain.history()))?;
    Ok(id)
}

/// The kind of object a put carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectKind {
    /// Data Units (DATA_PUT).
    DataUnit,
    /// Key Packages (KEY_PACKAGE_PUT).
    KeyPackage,
    /// A Snapshot (SNAPSHOT_PUT).
    Snapshot,
}

/// Server-local admission (quotas, rate limits): infrastructure, never an
/// LFCP capability. Consulted after validation, before storing.
pub trait IngestPolicy: Send + Sync + 'static {
    /// Whether `count` objects of `kind` totalling `bytes` may be stored
    /// for `resource`. A refusal is `QUOTA_EXCEEDED` or `RATE_LIMITED`.
    fn admit(
        &self,
        resource: &ResourceId,
        kind: ObjectKind,
        count: usize,
        bytes: usize,
    ) -> Result<(), Refusal>;
}

/// Why [`IngestPolicy`] refused a put.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// `QUOTA_EXCEEDED` (§62).
    Quota,
    /// `RATE_LIMITED` (§62).
    RateLimited,
}

impl Refusal {
    /// The §62 code.
    pub fn code(self) -> WireCode {
        match self {
            Refusal::Quota => WireCode::QuotaExceeded,
            Refusal::RateLimited => WireCode::RateLimited,
        }
    }
}

/// No limits beyond the message size: the self-hosted MVP default.
#[derive(Clone, Copy, Debug, Default)]
pub struct Unlimited;

impl IngestPolicy for Unlimited {
    fn admit(&self, _: &ResourceId, _: ObjectKind, _: usize, _: usize) -> Result<(), Refusal> {
        Ok(())
    }
}
