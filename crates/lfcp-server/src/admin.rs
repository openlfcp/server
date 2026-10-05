//! Server setup and administration over HTTP (LFCP-046; WIRE-01 §92,
//! narrative §27): infrastructure only. Nothing here is LFCP Resource
//! authority, and HTTP is never an alternate LFCP data protocol: Resources
//! are synchronized over the WebSocket only.
//!
//! First run (§92): while no administrator is paired, the server creates a
//! one-time setup code (8 symbols, `XXXX-XXXX`, from the operating system's
//! random source), which `main` prints once; the store keeps only its hash.
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
//! | Request | Answer |
//! | --- | --- |
//! | `GET /setup` | `{"paired", "server_id"}` |
//! | `POST /admin/challenge` | `{"challenge", "expires_in_s"}`: single use |
//! | `POST /setup/pair` `{"code", "principal", "challenge", "proof"}` | `{"admin"}`; 403 wrong code, 410 no code or expired, 401 bad proof |
//! | `POST /admin/session` `{"principal", "challenge", "proof"}` | `{"token", "expires_in_s"}`; 403 not an administrator |
//! | `GET /admin/status` | server ID, limits, public URLs, durability, administrators, hosted Resource count |
//! | `GET /admin/hosting`, `PUT /admin/hosting` | the hosting policy: `{"mode": "open"}` or `{"mode": "allow_list", "principals", "credentials"}` |
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
use crate::rng::Random;
use crate::session::HostingPolicy;
use crate::store::{Pairing, Store, StoreError, DURABILITY};

pub use crate::store::SETUP_ATTEMPTS;

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

/// The one-time setup code, for `main` to print once. It redacts itself
/// in `Debug`.
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
    /// Any authenticated Principal may host (the self-hosted default).
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

/// The live hosting policy: a [`HostingPolicy`] the admin API changes.
pub struct ManagedHosting(RwLock<HostingRule>);

impl ManagedHosting {
    /// The current rule.
    pub fn rule(&self) -> HostingRule {
        self.0.read().expect("never poisoned").clone()
    }
}

impl HostingPolicy for ManagedHosting {
    fn allows(&self, host: &PrincipalId, credential: Option<&HostingCredential>) -> bool {
        match &*self.0.read().expect("never poisoned") {
            HostingRule::Open => true,
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

/// The setup/admin HTTP surface.
pub struct Admin {
    store: Arc<Store>,
    server_id: ServerId,
    random: Arc<dyn Random>,
    hosting: Arc<ManagedHosting>,
    status: StatusInfo,
    challenges: Mutex<HashMap<[u8; 32], Instant>>,
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
}

impl std::fmt::Display for AdminError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdminError::Store(e) => write!(f, "store: {e}"),
            AdminError::Random(e) => write!(f, "randomness: {e}"),
            AdminError::Setting(e) => write!(f, "stored hosting policy: {e}"),
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
    /// `setup_ttl`, returned for the caller to print once.
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
            None => HostingRule::Open,
        };
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
            Some(SetupCode(code))
        } else {
            None
        };
        let admin = Admin {
            store,
            server_id,
            random,
            hosting: Arc::new(ManagedHosting(RwLock::new(rule))),
            status: StatusInfo {
                ws_path: config.ws_path.clone(),
                max_message_bytes: config.max_message_bytes,
                heartbeat_ms: config.heartbeat_ms,
                public_urls: config.public_urls.clone(),
            },
            challenges: Mutex::new(HashMap::new()),
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
            "/admin/status" | "/admin/hosting" | "/admin/resources"
        );
        if admin_only {
            self.authenticate(bearer)?;
        }
        match (method, path) {
            (&Method::GET, "/setup") => {
                let paired = !self.store.admins().await.map_err(internal)?.is_empty();
                Ok(ok(
                    json!({ "paired": paired, "server_id": self.server_id.to_hex() }),
                ))
            }
            (&Method::POST, "/admin/challenge") => {
                let mut challenge = [0u8; 32];
                self.random
                    .fill(&mut challenge)
                    .map_err(|_| internal_msg())?;
                let mut challenges = self.challenges.lock().expect("never poisoned");
                let now = Instant::now();
                challenges.retain(|_, expires| *expires > now);
                challenges.insert(challenge, now + CHALLENGE_TTL);
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
            (
                _,
                "/setup" | "/admin/challenge" | "/setup/pair" | "/admin/session" | "/admin/status"
                | "/admin/hosting" | "/admin/resources",
            ) => Err(Failure(
                StatusCode::METHOD_NOT_ALLOWED,
                "method not allowed",
            )),
            _ => Err(Failure(StatusCode::NOT_FOUND, "not found")),
        }
    }

    /// A proof of `purpose` by the Principal in `request`, for a challenge
    /// this server issued (and now consumes).
    fn verify(
        &self,
        purpose: &str,
        request: &ProofRequest,
    ) -> Result<PrincipalDescriptor, Failure> {
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
        // The challenge is consumed whatever the outcome.
        let issued = self
            .challenges
            .lock()
            .expect("never poisoned")
            .remove(&challenge)
            .is_some_and(|expires| expires > Instant::now());
        let refused = Failure(StatusCode::UNAUTHORIZED, "proof refused");
        if !issued {
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
        Ok(descriptor)
    }

    async fn pair(&self, body: &[u8]) -> Result<Response<Full<Bytes>>, Failure> {
        let request: PairRequest = parse(body)?;
        let descriptor = self.verify("pair", &request.proof)?;
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
        let descriptor = self.verify("session", &request)?;
        let admins = self.store.admins().await.map_err(internal)?;
        if !admins.contains(descriptor.id()) {
            return Err(Failure(StatusCode::FORBIDDEN, "not a server administrator"));
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
        *self.hosting.0.write().expect("never poisoned") = rule.clone();
        tracing::info!("hosting policy changed");
        Ok(ok(rule_json(&rule)))
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

/// The hosting rule as the API shows it: credential hashes are counted,
/// not listed.
fn rule_json(rule: &HostingRule) -> serde_json::Value {
    match rule {
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
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
enum HostingRequest {
    Open,
    AllowList {
        #[serde(default)]
        principals: Vec<String>,
        /// Hosting credentials, hex; stored only as SHA-256 hashes.
        #[serde(default)]
        credentials: Vec<String>,
    },
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
    fn allow_lists_admit_principals_or_credentials() {
        let p = PrincipalId::from_bytes([1; 32]);
        let q = PrincipalId::from_bytes([2; 32]);
        let hosting = ManagedHosting(RwLock::new(HostingRule::AllowList {
            principals: [p.to_hex()].into(),
            credential_hashes: [sha256(b"secret").to_hex()].into(),
        }));
        assert!(hosting.allows(&p, None));
        assert!(!hosting.allows(&q, None));
        assert!(hosting.allows(&q, Some(&HostingCredential::new(b"secret".to_vec()))));
        assert!(!hosting.allows(&q, Some(&HostingCredential::new(b"other".to_vec()))));
    }
}
