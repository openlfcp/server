//! Server setup and administration over HTTP (LFCP-046; WIRE-01 §92,
//! narrative §27): infrastructure only. Nothing here is LFCP Resource
//! authority, and HTTP is never an alternate LFCP data protocol: Resources
//! are synchronized over the WebSocket only.
//!
//! First run (§92): while no administrator is paired, the server creates a
//! one-time setup code (8 symbols, `XXXX-XXXX`, from the operating system's
//! random source). It is written to [`SETUP_CODE_FILE`] in the state
//! directory, mode 0600, and never to stdout or the log, which container
//! runtimes keep (security review M6); the store keeps only its hash.
//! The operator pairs one LFCP Principal as server administrator by
//! presenting the code together with a signature of a server challenge by
//! that Principal's key: no password. Pairing destroys the code. A code
//! expires after its TTL and is destroyed after [`SETUP_ATTEMPTS`] wrong
//! attempts; restarting an unpaired server creates a new one.
//!
//! Later administration authenticates with the paired Principal: a signed
//! challenge opens a short session whose bearer token the server keeps only
//! as a hash, in memory.
//!
//! Challenges are stateless (POST-003; security review M3): a challenge is
//! its expiry, a random nonce and a MAC under a key drawn at start, so
//! issuing one stores nothing and no flood of `POST /admin/challenge` can
//! exhaust them for the administrator. A challenge is valid until it
//! expires or the server restarts. A session proof is single use: only a
//! proof that opened a session is remembered (until its challenge
//! expires), so the memory is bounded by the administrators' own logins.
//! A refused proof leaves nothing behind; the pairing is single use
//! through its code. Floods are further bounded by the per-IP admin rate
//! limit ([`crate::server`]).
//!
//! | Request | Answer |
//! | --- | --- |
//! | `GET /setup` | `{"paired", "server_id"}` |
//! | `POST /admin/challenge` | `{"challenge", "expires_in_s"}`: stateless; a session proof over it is single use |
//! | `POST /setup/pair` `{"code", "principal", "challenge", "proof"}` | `{"admin"}`; 403 wrong code, 410 no code or expired, 401 bad proof |
//! | `POST /admin/session` `{"principal", "challenge", "proof"}` | `{"token", "expires_in_s"}`; 403 not an administrator |
//! | `GET /admin/status` | server ID, limits, public URLs, durability, administrators, hosted Resource count |
//! | `GET /admin/hosting`, `PUT /admin/hosting` | the hosting policy: `{"mode": "quota"}` (the default), `{"mode": "open"}` or `{"mode": "allow_list", "principals", "credentials"}` |
//! | `GET /admin/quotas` | the mode, the default quota and every per-Principal override |
//! | `GET /admin/quotas/<principal>` | a Principal's override, effective quota and usage (Resources, bytes) |
//! | `PUT /admin/quotas/<principal>` `{"resources", "bytes", "resource_bytes"}` | set its override (each optional; `null` or absent keeps the default) |
//! | `DELETE /admin/quotas/<principal>` | remove its override |
//! | `GET /admin/resources` | per Resource: ID, Control Head sequence, object counts, bytes; never contents |
//!
//! Binary values are lowercase hex: `principal` is the encoded Principal
//! Descriptor, `proof` a COSE_Sign1 object by that Principal over the
//! deterministic CBOR `["LFCP-ADMIN-v1", purpose, server_id, challenge]`
//! with purpose `"pair"` or `"session"`, verified with strict Ed25519
//! (WIRE-01 §10.5.1). `/admin/*` other than `challenge` and `session` needs
//! `Authorization: Bearer <token>`.
//!
//! Being an administrator grants no LFCP ability: no Resource ownership,
//! no `data/read`, nothing in a Control Chain. An administrator is not even
//! allowed to host unless the hosting policy allows it. The setup code,
//! proofs and tokens are never logged.

use std::collections::{BTreeSet, HashMap};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::{Method, Request, Response, StatusCode};
use lfcp::base::{from_hex, to_hex, PrincipalId};
use lfcp::cbor::{self, Value};
use lfcp::cose;
use lfcp::crypto::sha256;
use lfcp::principal::PrincipalDescriptor;
use lfcp::wire::message::HostingCredential;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::config::Config;
use crate::identity::ServerId;
use crate::limits::Quota;
use crate::rng::Random;
use crate::session::HostingPolicy;
use crate::store::{Pairing, QuotaOverride, Store, StoreError, DURABILITY};

pub use crate::store::SETUP_ATTEMPTS;

/// The file in the state directory holding the current setup code, mode
/// 0600. It is removed by the pairing, and at a start when an
/// administrator is paired.
pub const SETUP_CODE_FILE: &str = "setup-code";

/// How long a setup code lasts by default.
pub const SETUP_TTL: Duration = Duration::from_secs(60 * 60);
/// How long a challenge may be answered.
pub const CHALLENGE_TTL: Duration = Duration::from_secs(5 * 60);
/// How long an admin session lasts.
pub const SESSION_TTL: Duration = Duration::from_secs(15 * 60);
/// The largest request body the API reads.
pub const MAX_BODY: usize = 16 * 1024;

const SETUP_ALPHABET: &[u8; 32] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
const PROOF_LABEL: &str = "LFCP-ADMIN-v1";
const HOSTING_SETTING: &str = "hosting_policy";

/// The one-time setup code, also written to [`SETUP_CODE_FILE`]. It
/// redacts itself in `Debug`.
pub struct SetupCode(String);

impl SetupCode {
    /// The code, `XXXX-XXXX`.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SetupCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SetupCode(<redacted>)")
    }
}

/// A code's comparable form: upper case, without separators or spaces.
fn normalize(code: &str) -> String {
    code.chars()
        .filter(|c| !matches!(c, '-' | ' '))
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

fn code_hash(code: &str) -> [u8; 32] {
    *sha256(format!("LFCP-ADMIN-SETUP-v1:{}", normalize(code)).as_bytes()).as_bytes()
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// The hosting policy, as the admin API sets it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum HostingRule {
    /// Any authenticated Principal may host, within the storage quota of
    /// its Principal (POST-003): the default of a server that never set a
    /// policy.
    Quota,
    /// Any authenticated Principal may host, without quotas.
    Open,
    /// Only these Principals (IDs, hex), or a session presenting one of
    /// these hosting credentials (stored as SHA-256 hashes, hex).
    AllowList {
        /// Allowed Principal IDs.
        #[serde(default)]
        principals: BTreeSet<String>,
        /// SHA-256 of allowed credentials.
        #[serde(default)]
        credential_hashes: BTreeSet<String>,
    },
}

/// The live hosting policy: a [`HostingPolicy`] the admin API changes,
/// with the configured default quota and the per-Principal overrides.
pub struct ManagedHosting {
    rule: RwLock<HostingRule>,
    defaults: Quota,
    overrides: RwLock<HashMap<PrincipalId, QuotaOverride>>,
}

impl ManagedHosting {
    /// A policy with `rule`, the default quota `defaults` and no override.
    pub fn new(rule: HostingRule, defaults: Quota) -> ManagedHosting {
        ManagedHosting {
            rule: RwLock::new(rule),
            defaults,
            overrides: RwLock::default(),
        }
    }

    /// The current rule.
    pub fn rule(&self) -> HostingRule {
        self.rule.read().expect("never poisoned").clone()
    }

    /// The quota of `host` in quota mode: the default with its override.
    pub fn quota_of(&self, host: &PrincipalId) -> Quota {
        match self.overrides.read().expect("never poisoned").get(host) {
            Some(o) => self.defaults.with(o),
            None => self.defaults,
        }
    }
}

impl HostingPolicy for ManagedHosting {
    fn has_quotas(&self) -> bool {
        *self.rule.read().expect("never poisoned") == HostingRule::Quota
    }

    fn quota(&self, host: &PrincipalId) -> Option<Quota> {
        self.has_quotas().then(|| self.quota_of(host))
    }

    fn allows(&self, host: &PrincipalId, credential: Option<&HostingCredential>) -> bool {
        match &*self.rule.read().expect("never poisoned") {
            HostingRule::Quota | HostingRule::Open => true,
            HostingRule::AllowList {
                principals,
                credential_hashes,
            } => {
                principals.contains(&host.to_hex())
                    || credential.is_some_and(|c| {
                        credential_hashes.contains(&sha256(c.expose_secret()).to_hex())
                    })
            }
        }
    }
}

/// What `GET /admin/status` reports besides live counts.
#[derive(Clone, Debug)]
struct StatusInfo {
    ws_path: String,
    max_message_bytes: usize,
    heartbeat_ms: u64,
    public_urls: Vec<String>,
}

struct Session {
    principal: PrincipalId,
    expires: Instant,
}

/// Stateless challenges (see the module documentation): 8 bytes of
/// expiry (whole seconds since `epoch`, big-endian), an 8-byte nonce, and
/// the first 16 bytes of HMAC-SHA256 under `key` over those 16 bytes.
struct Challenges {
    key: [u8; 32],
    epoch: Instant,
    /// Challenges whose proof opened a session, until they expire.
    used: Mutex<HashMap<[u8; 32], Instant>>,
}

impl Challenges {
    fn new(key: [u8; 32], epoch: Instant) -> Challenges {
        Challenges {
            key,
            epoch,
            used: Mutex::default(),
        }
    }

    fn seconds(&self, now: Instant) -> u64 {
        now.saturating_duration_since(self.epoch).as_secs()
    }

    fn mac(&self, head: &[u8]) -> [u8; 16] {
        let mac = hmac_sha256(&self.key, head);
        mac[..16].try_into().expect("16 bytes")
    }

    /// A challenge issued at `now` with `nonce`; nothing is stored.
    fn issue(&self, nonce: [u8; 8], now: Instant) -> [u8; 32] {
        let expires = self.seconds(now) + CHALLENGE_TTL.as_secs();
        let mut challenge = [0u8; 32];
        challenge[..8].copy_from_slice(&expires.to_be_bytes());
        challenge[8..16].copy_from_slice(&nonce);
        let mac = self.mac(&challenge[..16]);
        challenge[16..].copy_from_slice(&mac);
        challenge
    }

    /// When `challenge`, issued by this server and unexpired at `now`,
    /// expires.
    fn valid(&self, challenge: &[u8; 32], now: Instant) -> Option<Instant> {
        let expected = self.mac(&challenge[..16]);
        let differs = expected
            .iter()
            .zip(&challenge[16..])
            .fold(0u8, |acc, (a, b)| acc | (a ^ b));
        let expires = u64::from_be_bytes(challenge[..8].try_into().expect("8 bytes"));
        (differs == 0 && self.seconds(now) < expires)
            .then(|| self.epoch + Duration::from_secs(expires))
    }

    /// Mark `challenge` used by an accepted proof: `false` if it already
    /// was (a replay). Expired marks are dropped first.
    fn spend(&self, challenge: &[u8; 32], now: Instant) -> bool {
        let Some(expires) = self.valid(challenge, now) else {
            return false;
        };
        let mut used = self.used.lock().expect("never poisoned");
        used.retain(|_, until| *until > now);
        used.insert(*challenge, expires).is_none()
    }
}

/// HMAC-SHA256 (RFC 2104) of `message` under a 32-byte `key`.
fn hmac_sha256(key: &[u8; 32], message: &[u8]) -> [u8; 32] {
    let mut inner = [0x36u8; 64];
    let mut outer = [0x5cu8; 64];
    for (i, byte) in key.iter().enumerate() {
        inner[i] ^= byte;
        outer[i] ^= byte;
    }
    let inner = lfcp::crypto::sha256_parts(&[&inner, message]);
    *lfcp::crypto::sha256_parts(&[&outer, inner.as_bytes()]).as_bytes()
}

/// The setup/admin HTTP surface.
pub struct Admin {
    store: Arc<Store>,
    setup_file: PathBuf,
    server_id: ServerId,
    random: Arc<dyn Random>,
    hosting: Arc<ManagedHosting>,
    status: StatusInfo,
    challenges: Challenges,
    sessions: Mutex<HashMap<[u8; 32], Session>>,
}

/// Why the admin surface could not start.
#[derive(Debug)]
pub enum AdminError {
    /// The store failed.
    Store(StoreError),
    /// No randomness.
    Random(String),
    /// The stored hosting policy does not parse.
    Setting(String),
    /// The setup code file could not be written or removed.
    SetupFile(std::io::Error),
}

impl std::fmt::Display for AdminError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdminError::Store(e) => write!(f, "store: {e}"),
            AdminError::Random(e) => write!(f, "randomness: {e}"),
            AdminError::Setting(e) => write!(f, "stored hosting policy: {e}"),
            AdminError::SetupFile(e) => write!(f, "setup code file: {e}"),
        }
    }
}

impl std::error::Error for AdminError {}

impl From<StoreError> for AdminError {
    fn from(e: StoreError) -> AdminError {
        AdminError::Store(e)
    }
}

impl Admin {
    /// Open the admin surface: load the hosting policy, and, while no
    /// administrator is paired, create a new setup code valid for
    /// `setup_ttl`, written to [`SETUP_CODE_FILE`] in the state directory
    /// (replacing an older one) and returned. Once paired, a leftover file
    /// is removed.
    pub async fn open(
        store: Arc<Store>,
        server_id: ServerId,
        config: &Config,
        random: Arc<dyn Random>,
        setup_ttl: Duration,
    ) -> Result<(Arc<Admin>, Option<SetupCode>), AdminError> {
        let rule = match store.setting(HOSTING_SETTING).await? {
            Some(json) => {
                serde_json::from_str(&json).map_err(|e| AdminError::Setting(e.to_string()))?
            }
            None => HostingRule::Quota,
        };
        let hosting = ManagedHosting::new(rule, Quota::defaults(&config.abuse));
        *hosting.overrides.write().expect("never poisoned") =
            store.quota_overrides().await?.into_iter().collect();
        let setup_file = config.state_dir.join(SETUP_CODE_FILE);
        let mut challenge_key = [0u8; 32];
        random
            .fill(&mut challenge_key)
            .map_err(AdminError::Random)?;
        let code = if store.admins().await?.is_empty() {
            let mut bytes = [0u8; 8];
            random.fill(&mut bytes).map_err(AdminError::Random)?;
            let symbols: String = bytes
                .iter()
                .map(|b| char::from(SETUP_ALPHABET[usize::from(b & 31)]))
                .collect();
            let code = format!("{}-{}", &symbols[..4], &symbols[4..]);
            let expires = unix_now() + setup_ttl.as_secs().max(1) as i64;
            store.set_setup_code(code_hash(&code), expires).await?;
            write_setup_file(&setup_file, &code).map_err(AdminError::SetupFile)?;
            Some(SetupCode(code))
        } else {
            remove_setup_file(&setup_file).map_err(AdminError::SetupFile)?;
            None
        };
        let admin = Admin {
            store,
            setup_file,
            server_id,
            random,
            hosting: Arc::new(hosting),
            status: StatusInfo {
                ws_path: config.ws_path.clone(),
                max_message_bytes: config.max_message_bytes,
                heartbeat_ms: config.heartbeat_ms,
                public_urls: config.public_urls.clone(),
            },
            challenges: Challenges::new(challenge_key, Instant::now()),
            sessions: Mutex::new(HashMap::new()),
        };
        Ok((Arc::new(admin), code))
    }

    /// The live hosting policy, for the LFCP sessions.
    pub fn hosting(&self) -> Arc<ManagedHosting> {
        self.hosting.clone()
    }

    /// Whether this surface answers `path`.
    pub fn handles(path: &str) -> bool {
        path == "/setup"
            || path.starts_with("/setup/")
            || path == "/admin"
            || path.starts_with("/admin/")
    }

    /// Answer one request.
    pub async fn handle(&self, request: Request<Incoming>) -> Response<Full<Bytes>> {
        let method = request.method().clone();
        let path = request.uri().path().to_owned();
        let bearer = request
            .headers()
            .get(hyper::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::to_owned);
        let body = match Limited::new(request.into_body(), MAX_BODY).collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(_) => return error(StatusCode::PAYLOAD_TOO_LARGE, "body too large"),
        };
        match self.route(&method, &path, bearer.as_deref(), &body).await {
            Ok(response) => response,
            Err(Failure(status, message)) => error(status, message),
        }
    }

    async fn route(
        &self,
        method: &Method,
        path: &str,
        bearer: Option<&str>,
        body: &[u8],
    ) -> Result<Response<Full<Bytes>>, Failure> {
        let admin_only = matches!(
            path,
            "/admin/status" | "/admin/hosting" | "/admin/resources" | "/admin/quotas"
        ) || path.starts_with("/admin/quotas/");
        if admin_only {
            self.authenticate(bearer)?;
        }
        if let Some(principal) = path.strip_prefix("/admin/quotas/") {
            return self.principal_quota(method, principal, body).await;
        }
        match (method, path) {
            (&Method::GET, "/setup") => {
                let paired = !self.store.admins().await.map_err(internal)?.is_empty();
                Ok(ok(
                    json!({ "paired": paired, "server_id": self.server_id.to_hex() }),
                ))
            }
            (&Method::POST, "/admin/challenge") => {
                let mut nonce = [0u8; 8];
                self.random.fill(&mut nonce).map_err(|_| internal_msg())?;
                let challenge = self.challenges.issue(nonce, Instant::now());
                Ok(ok(json!({
                    "challenge": to_hex(&challenge),
                    "expires_in_s": CHALLENGE_TTL.as_secs(),
                })))
            }
            (&Method::POST, "/setup/pair") => self.pair(body).await,
            (&Method::POST, "/admin/session") => self.session(body).await,
            (&Method::GET, "/admin/status") => self.status().await,
            (&Method::GET, "/admin/hosting") => Ok(ok(rule_json(&self.hosting.rule()))),
            (&Method::PUT, "/admin/hosting") => self.set_hosting(body).await,
            (&Method::GET, "/admin/resources") => self.resources().await,
            (&Method::GET, "/admin/quotas") => Ok(ok(self.quotas_json())),
            (
                _,
                "/setup" | "/admin/challenge" | "/setup/pair" | "/admin/session" | "/admin/status"
                | "/admin/hosting" | "/admin/resources" | "/admin/quotas",
            ) => Err(Failure(
                StatusCode::METHOD_NOT_ALLOWED,
                "method not allowed",
            )),
            _ => Err(Failure(StatusCode::NOT_FOUND, "not found")),
        }
    }

    /// A proof of `purpose` by the Principal in `request`, for an
    /// unexpired challenge this server issued. Returns the Principal and
    /// the challenge.
    fn verify(
        &self,
        purpose: &str,
        request: &ProofRequest,
    ) -> Result<(PrincipalDescriptor, [u8; 32]), Failure> {
        let bad = |message| Failure(StatusCode::BAD_REQUEST, message);
        let descriptor = from_hex(&request.principal)
            .ok()
            .and_then(|b| PrincipalDescriptor::decode(&b).ok())
            .ok_or_else(|| bad("principal is not a hex Principal Descriptor"))?;
        let challenge: [u8; 32] = from_hex(&request.challenge)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| bad("challenge is not 32 hex bytes"))?;
        let proof = from_hex(&request.proof).map_err(|_| bad("proof is not hex"))?;
        let refused = Failure(StatusCode::UNAUTHORIZED, "proof refused");
        if self.challenges.valid(&challenge, Instant::now()).is_none() {
            return Err(refused);
        }
        let transcript = cbor::encode(&Value::Array(vec![
            Value::text(PROOF_LABEL),
            Value::text(purpose),
            Value::bytes(self.server_id.as_bytes().to_vec()),
            Value::bytes(challenge.to_vec()),
        ]))
        .expect("the transcript encodes");
        let object = cose::parse(&proof).map_err(|_| refused.clone())?;
        if object.kid() != descriptor.id() || object.payload_bytes() != transcript {
            return Err(refused);
        }
        cose::verify(&object, &descriptor).map_err(|_| refused)?;
        Ok((descriptor, challenge))
    }

    async fn pair(&self, body: &[u8]) -> Result<Response<Full<Bytes>>, Failure> {
        let request: PairRequest = parse(body)?;
        // Single use through the code: a pairing destroys it.
        let (descriptor, _) = self.verify("pair", &request.proof)?;
        let outcome = self
            .store
            .pair_admin(
                code_hash(&request.code),
                *descriptor.id(),
                descriptor.encode(),
                unix_now(),
            )
            .await
            .map_err(internal)?;
        match outcome {
            Pairing::Paired => {
                tracing::info!(admin = %descriptor.id().to_hex(), "server administrator paired");
                // The code is destroyed; so is its file.
                if let Err(error) = remove_setup_file(&self.setup_file) {
                    tracing::warn!(%error, "cannot remove the setup code file");
                }
                Ok(ok(json!({ "admin": descriptor.id().to_hex() })))
            }
            Pairing::WrongCode { .. } => Err(Failure(StatusCode::FORBIDDEN, "wrong setup code")),
            Pairing::Expired => Err(Failure(
                StatusCode::GONE,
                "the setup code expired; restart the server for a new one",
            )),
            Pairing::NoCode => Err(Failure(
                StatusCode::GONE,
                "no setup code: already paired, or destroyed",
            )),
        }
    }

    async fn session(&self, body: &[u8]) -> Result<Response<Full<Bytes>>, Failure> {
        let request: ProofRequest = parse(body)?;
        let (descriptor, challenge) = self.verify("session", &request)?;
        let admins = self.store.admins().await.map_err(internal)?;
        if !admins.contains(descriptor.id()) {
            return Err(Failure(StatusCode::FORBIDDEN, "not a server administrator"));
        }
        // A proof opens one session: a replay is refused.
        if !self.challenges.spend(&challenge, Instant::now()) {
            return Err(Failure(StatusCode::UNAUTHORIZED, "proof refused"));
        }
        let mut token = [0u8; 32];
        self.random.fill(&mut token).map_err(|_| internal_msg())?;
        let mut sessions = self.sessions.lock().expect("never poisoned");
        let now = Instant::now();
        sessions.retain(|_, s| s.expires > now);
        sessions.insert(
            *sha256(&token).as_bytes(),
            Session {
                principal: *descriptor.id(),
                expires: now + SESSION_TTL,
            },
        );
        tracing::info!(admin = %descriptor.id().to_hex(), "admin session opened");
        Ok(ok(
            json!({ "token": to_hex(&token), "expires_in_s": SESSION_TTL.as_secs() }),
        ))
    }

    /// The administrator a bearer token belongs to.
    fn authenticate(&self, bearer: Option<&str>) -> Result<PrincipalId, Failure> {
        let unauthorized = Failure(
            StatusCode::UNAUTHORIZED,
            "an admin session token is required",
        );
        let token = bearer
            .and_then(|t| from_hex(t).ok())
            .ok_or_else(|| unauthorized.clone())?;
        let sessions = self.sessions.lock().expect("never poisoned");
        match sessions.get(sha256(&token).as_bytes()) {
            Some(session) if session.expires > Instant::now() => Ok(session.principal),
            _ => Err(unauthorized),
        }
    }

    async fn status(&self) -> Result<Response<Full<Bytes>>, Failure> {
        let admins: Vec<String> = self
            .store
            .admins()
            .await
            .map_err(internal)?
            .iter()
            .map(PrincipalId::to_hex)
            .collect();
        let hosted = self.store.resource_sizes().await.map_err(internal)?.len();
        Ok(ok(json!({
            "server_id": self.server_id.to_hex(),
            "version": env!("CARGO_PKG_VERSION"),
            "ws_path": self.status.ws_path,
            "public_urls": self.status.public_urls,
            "max_message_bytes": self.status.max_message_bytes,
            "heartbeat_ms": self.status.heartbeat_ms,
            "durability": DURABILITY,
            "admins": admins,
            "hosted_resources": hosted,
        })))
    }

    async fn set_hosting(&self, body: &[u8]) -> Result<Response<Full<Bytes>>, Failure> {
        let request: HostingRequest = parse(body)?;
        let bad = |message| Failure(StatusCode::BAD_REQUEST, message);
        let rule = match request {
            HostingRequest::Quota => HostingRule::Quota,
            HostingRequest::Open => HostingRule::Open,
            HostingRequest::AllowList {
                principals,
                credentials,
            } => {
                let principals = principals
                    .iter()
                    .map(|p| {
                        PrincipalId::from_hex(p)
                            .map(|id| id.to_hex())
                            .map_err(|_| bad("principals are 32-byte hex Principal IDs"))
                    })
                    .collect::<Result<_, _>>()?;
                let credential_hashes = credentials
                    .iter()
                    .map(|c| {
                        from_hex(c)
                            .map(|bytes| sha256(&bytes).to_hex())
                            .map_err(|_| bad("credentials are hex"))
                    })
                    .collect::<Result<_, _>>()?;
                HostingRule::AllowList {
                    principals,
                    credential_hashes,
                }
            }
        };
        let json = serde_json::to_string(&rule).expect("a rule serializes");
        self.store
            .set_setting(HOSTING_SETTING, json)
            .await
            .map_err(internal)?;
        *self.hosting.rule.write().expect("never poisoned") = rule.clone();
        tracing::info!("hosting policy changed");
        Ok(ok(rule_json(&rule)))
    }

    /// `GET /admin/quotas`.
    fn quotas_json(&self) -> serde_json::Value {
        let overrides: Vec<serde_json::Value> = self
            .hosting
            .overrides
            .read()
            .expect("never poisoned")
            .iter()
            .map(|(principal, o)| {
                let mut entry = override_json(o);
                entry["principal"] = json!(principal.to_hex());
                entry
            })
            .collect();
        json!({
            "mode": rule_json(&self.hosting.rule())["mode"],
            "defaults": quota_json(&self.hosting.defaults),
            "overrides": overrides,
        })
    }

    /// `GET`, `PUT` and `DELETE /admin/quotas/<principal>`.
    async fn principal_quota(
        &self,
        method: &Method,
        principal: &str,
        body: &[u8],
    ) -> Result<Response<Full<Bytes>>, Failure> {
        let principal = PrincipalId::from_hex(principal).map_err(|_| {
            Failure(
                StatusCode::BAD_REQUEST,
                "the path ends with a 32-byte hex Principal ID",
            )
        })?;
        match *method {
            Method::GET => {}
            Method::PUT => {
                let request: QuotaRequest = parse(body)?;
                let quota = QuotaOverride {
                    resources: request.resources,
                    bytes: request.bytes,
                    resource_bytes: request.resource_bytes,
                };
                if [quota.resources, quota.bytes, quota.resource_bytes]
                    .iter()
                    .flatten()
                    .any(|n| *n > i64::MAX as u64)
                {
                    return Err(Failure(
                        StatusCode::BAD_REQUEST,
                        "a quota is at most 2^63-1",
                    ));
                }
                self.store
                    .set_quota_override(principal, quota)
                    .await
                    .map_err(internal)?;
                self.hosting
                    .overrides
                    .write()
                    .expect("never poisoned")
                    .insert(principal, quota);
                tracing::info!(principal = %principal.to_hex(), "quota override set");
            }
            Method::DELETE => {
                self.store
                    .delete_quota_override(principal)
                    .await
                    .map_err(internal)?;
                self.hosting
                    .overrides
                    .write()
                    .expect("never poisoned")
                    .remove(&principal);
                tracing::info!(principal = %principal.to_hex(), "quota override removed");
            }
            _ => {
                return Err(Failure(
                    StatusCode::METHOD_NOT_ALLOWED,
                    "method not allowed",
                ))
            }
        }
        let (resources, bytes) = self
            .store
            .principal_usage(principal)
            .await
            .map_err(internal)?;
        let o = self
            .hosting
            .overrides
            .read()
            .expect("never poisoned")
            .get(&principal)
            .copied();
        Ok(ok(json!({
            "principal": principal.to_hex(),
            "override": o.as_ref().map(override_json),
            "quota": quota_json(&self.hosting.quota_of(&principal)),
            "usage": { "resources": resources, "bytes": bytes },
        })))
    }

    async fn resources(&self) -> Result<Response<Full<Bytes>>, Failure> {
        let sizes = self.store.resource_sizes().await.map_err(internal)?;
        let list: Vec<serde_json::Value> = sizes
            .iter()
            .map(|r| {
                json!({
                    "resource_id": r.resource_id.to_hex(),
                    "control_head_seq": r.control_head_seq,
                    "control_records": r.control_records,
                    "data_units": r.data_units,
                    "key_packages": r.key_packages,
                    "snapshots": r.snapshots,
                    "bytes": r.bytes,
                })
            })
            .collect();
        Ok(ok(json!({ "resources": list })))
    }
}

fn quota_json(quota: &Quota) -> serde_json::Value {
    json!({
        "resources": quota.resources,
        "bytes": quota.bytes,
        "resource_bytes": quota.resource_bytes,
    })
}

fn override_json(o: &QuotaOverride) -> serde_json::Value {
    json!({
        "resources": o.resources,
        "bytes": o.bytes,
        "resource_bytes": o.resource_bytes,
    })
}

/// The hosting rule as the API shows it: credential hashes are counted,
/// not listed.
fn rule_json(rule: &HostingRule) -> serde_json::Value {
    match rule {
        HostingRule::Quota => json!({ "mode": "quota" }),
        HostingRule::Open => json!({ "mode": "open" }),
        HostingRule::AllowList {
            principals,
            credential_hashes,
        } => json!({
            "mode": "allow_list",
            "principals": principals,
            "credentials": credential_hashes.len(),
        }),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProofRequest {
    principal: String,
    challenge: String,
    proof: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PairRequest {
    code: String,
    #[serde(flatten)]
    proof: ProofRequest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QuotaRequest {
    #[serde(default)]
    resources: Option<u64>,
    #[serde(default)]
    bytes: Option<u64>,
    #[serde(default)]
    resource_bytes: Option<u64>,
}

#[derive(Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
enum HostingRequest {
    Quota,
    Open,
    AllowList {
        #[serde(default)]
        principals: Vec<String>,
        /// Hosting credentials, hex; stored only as SHA-256 hashes.
        #[serde(default)]
        credentials: Vec<String>,
    },
}

/// Write `code` to `path` with mode 0600: any previous file is removed
/// first, so the new one is created with that mode.
fn write_setup_file(path: &Path, code: &str) -> std::io::Result<()> {
    remove_setup_file(path)?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(path)?;
    file.write_all(format!("{code}\n").as_bytes())?;
    file.sync_all()
}

fn remove_setup_file(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Err(error) if error.kind() != ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

#[derive(Clone, Debug)]
struct Failure(StatusCode, &'static str);

fn internal(error: StoreError) -> Failure {
    tracing::error!(%error, "admin store failure");
    internal_msg()
}

fn internal_msg() -> Failure {
    Failure(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
}

fn parse<T: for<'de> Deserialize<'de>>(body: &[u8]) -> Result<T, Failure> {
    serde_json::from_slice(body)
        .map_err(|_| Failure(StatusCode::BAD_REQUEST, "malformed JSON request"))
}

fn json_response(status: StatusCode, value: &serde_json::Value) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .body(Full::new(Bytes::from(value.to_string())))
        .expect("a valid response")
}

fn ok(value: serde_json::Value) -> Response<Full<Bytes>> {
    json_response(StatusCode::OK, &value)
}

fn error(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    json_response(status, &json!({ "error": message }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_normalize_and_hash() {
        assert_eq!(normalize("x7km-p9la"), "X7KMP9LA");
        assert_eq!(code_hash("X7KM-P9LA"), code_hash("x7km p9la"));
        assert_ne!(code_hash("X7KM-P9LA"), code_hash("X7KM-P9LB"));
        assert_eq!(
            format!("{:?}", SetupCode("X7KM-P9LA".into())),
            "SetupCode(<redacted>)"
        );
    }

    #[test]
    fn hmac_matches_rfc_4231() {
        // RFC 4231 test case 2 has a 4-byte key; its zero-padded 32-byte
        // form is the same HMAC key (RFC 2104 pads short keys with zeros).
        let mut key = [0u8; 32];
        key[..4].copy_from_slice(b"Jefe");
        assert_eq!(
            to_hex(&hmac_sha256(&key, b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn challenges_are_stateless_unforgeable_and_expire() {
        let now = Instant::now();
        let challenges = Challenges::new([7; 32], now);
        // Issuing stores nothing, however many.
        for i in 0..100_000u64 {
            challenges.issue(i.to_le_bytes(), now);
        }
        assert!(challenges.used.lock().unwrap().is_empty());
        let c = challenges.issue([1; 8], now);
        assert!(challenges.valid(&c, now).is_some());
        // Another key, a changed byte, or expiry: refused.
        assert!(Challenges::new([8; 32], now).valid(&c, now).is_none());
        for i in [0, 9, 20, 31] {
            let mut forged = c;
            forged[i] ^= 1;
            assert!(challenges.valid(&forged, now).is_none(), "byte {i}");
        }
        assert!(challenges.valid(&c, now + CHALLENGE_TTL).is_none());
        // Spending is single use, and the mark expires with the challenge.
        assert!(challenges.spend(&c, now));
        assert!(!challenges.spend(&c, now));
        let d = challenges.issue([2; 8], now + CHALLENGE_TTL);
        assert!(challenges.spend(&d, now + CHALLENGE_TTL));
        assert_eq!(challenges.used.lock().unwrap().len(), 1, "c was dropped");
    }

    #[test]
    fn allow_lists_admit_principals_or_credentials() {
        let p = PrincipalId::from_bytes([1; 32]);
        let q = PrincipalId::from_bytes([2; 32]);
        let quota = Quota::defaults(&crate::limits::AbuseLimits::default());
        let hosting = ManagedHosting::new(
            HostingRule::AllowList {
                principals: [p.to_hex()].into(),
                credential_hashes: [sha256(b"secret").to_hex()].into(),
            },
            quota,
        );
        assert!(!hosting.has_quotas() && hosting.quota(&p).is_none());
        assert!(hosting.allows(&p, None));
        assert!(!hosting.allows(&q, None));
        assert!(hosting.allows(&q, Some(&HostingCredential::new(b"secret".to_vec()))));
        assert!(!hosting.allows(&q, Some(&HostingCredential::new(b"other".to_vec()))));
    }

    #[test]
    fn quota_mode_admits_anyone_within_their_quota() {
        let p = PrincipalId::from_bytes([1; 32]);
        let q = PrincipalId::from_bytes([2; 32]);
        let defaults = Quota::defaults(&crate::limits::AbuseLimits::default());
        let hosting = ManagedHosting::new(HostingRule::Quota, defaults);
        assert!(hosting.allows(&p, None) && hosting.has_quotas());
        hosting.overrides.write().unwrap().insert(
            p,
            QuotaOverride {
                resources: Some(100),
                ..QuotaOverride::default()
            },
        );
        assert_eq!(
            hosting.quota(&p),
            Some(Quota {
                resources: 100,
                ..defaults
            })
        );
        assert_eq!(hosting.quota(&q), Some(defaults));
        *hosting.rule.write().unwrap() = HostingRule::Open;
        assert!(!hosting.has_quotas() && hosting.quota(&p).is_none());
    }
}
