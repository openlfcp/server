//! The admin API calls (server README "Administration"), each signed by
//! the admin key.
//!
//! Every proof is over a fresh challenge from `POST /admin/challenge` and
//! the server ID from `GET /setup`, with the server's own transcript and
//! signer ([`lfcp_server::admin::sign_proof`]). Pairing sends the setup
//! code with a `pair` proof; every other call first opens a session with a
//! `session` proof, then sends its request with that bearer token. Tokens
//! live only in memory, for the one command.

use lfcp::base::{from_hex, to_hex, PrincipalId};
use lfcp::principal::PrincipalKeys;
use lfcp_server::admin::{sign_proof, PURPOSE_PAIR, PURPOSE_SESSION};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::http::{request, Answer, Url};
use crate::Error;

/// The hosting policy to set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Hosting {
    /// Anyone, within quotas (the server's default).
    Quota,
    /// Anyone, without quotas.
    Open,
    /// Only these Principals or holders of these hosting credentials.
    AllowList {
        /// Principal IDs.
        principals: Vec<PrincipalId>,
        /// Hosting credentials (secret; sent once, stored hashed).
        credentials: Vec<Zeroizing<Vec<u8>>>,
    },
}

/// A Principal's quota override; `None` keeps the server's default.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QuotaOverride {
    /// Resources it may host.
    pub resources: Option<u64>,
    /// Stored bytes across its Resources.
    pub bytes: Option<u64>,
    /// Stored bytes of each of its Resources.
    pub resource_bytes: Option<u64>,
}

/// An admin client of one server, signing with one key.
pub struct Admin {
    url: Url,
    keys: PrincipalKeys,
}

/// A proof request body: `{"principal", "challenge", "proof"}`.
pub fn proof_body(
    keys: &PrincipalKeys,
    purpose: &str,
    server_id: &[u8; 32],
    challenge: &[u8; 32],
) -> Value {
    json!({
        "principal": to_hex(&keys.descriptor().encode()),
        "challenge": to_hex(challenge),
        "proof": to_hex(&sign_proof(keys, purpose, server_id, challenge)),
    })
}

/// The answer's body if it is a success, otherwise the refusal.
fn success(answer: Answer) -> Result<Value, Error> {
    if (200..300).contains(&answer.status) {
        return Ok(answer.body);
    }
    let message = answer.body["error"]
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| "no error message".into());
    Err(Error::Refused {
        status: answer.status,
        message,
        retry_after: answer.retry_after,
    })
}

fn hex32(value: &Value, field: &str) -> Result<[u8; 32], Error> {
    value[field]
        .as_str()
        .and_then(|h| from_hex(h).ok())
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| Error::Protocol(format!("{field} is not 32 hex bytes")))
}

impl Admin {
    /// A client of the server at `url`, signing with `keys`.
    pub fn new(url: Url, keys: PrincipalKeys) -> Admin {
        Admin { url, keys }
    }

    /// The admin Principal.
    pub fn principal(&self) -> PrincipalId {
        *self.keys.descriptor().id()
    }

    fn call(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
    ) -> Result<Value, Error> {
        success(request(&self.url, method, path, token, body)?)
    }

    /// `GET /setup`: whether the server is paired, and its ID.
    pub fn setup(&self) -> Result<Value, Error> {
        self.call("GET", "/setup", None, None)
    }

    /// The server ID and a fresh challenge.
    pub fn challenge(&self) -> Result<([u8; 32], [u8; 32]), Error> {
        let server_id = hex32(&self.setup()?, "server_id")?;
        let challenge = hex32(
            &self.call("POST", "/admin/challenge", None, None)?,
            "challenge",
        )?;
        Ok((server_id, challenge))
    }

    /// Pair this key as the server's administrator with the one-time setup
    /// `code` (`POST /setup/pair`).
    pub fn pair(&self, code: &str) -> Result<Value, Error> {
        let (server_id, challenge) = self.challenge()?;
        let mut body = proof_body(&self.keys, PURPOSE_PAIR, &server_id, &challenge);
        body["code"] = json!(code);
        self.call("POST", "/setup/pair", None, Some(&body))
    }

    /// Open an admin session; its bearer token.
    pub fn session(&self) -> Result<Zeroizing<String>, Error> {
        let (server_id, challenge) = self.challenge()?;
        let body = proof_body(&self.keys, PURPOSE_SESSION, &server_id, &challenge);
        let answer = self.call("POST", "/admin/session", None, Some(&body))?;
        answer["token"]
            .as_str()
            .map(|t| Zeroizing::new(t.to_owned()))
            .ok_or_else(|| Error::Protocol("no session token".into()))
    }

    /// A signed admin call: a session, then `method` `path` with `body`.
    pub fn admin(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Value, Error> {
        let token = self.session()?;
        self.call(method, path, Some(&token), body)
    }

    /// `GET /admin/status`.
    pub fn status(&self) -> Result<Value, Error> {
        self.admin("GET", "/admin/status", None)
    }

    /// `GET /admin/hosting`.
    pub fn hosting(&self) -> Result<Value, Error> {
        self.admin("GET", "/admin/hosting", None)
    }

    /// `PUT /admin/hosting`.
    pub fn set_hosting(&self, hosting: &Hosting) -> Result<Value, Error> {
        let body = match hosting {
            Hosting::Quota => json!({ "mode": "quota" }),
            Hosting::Open => json!({ "mode": "open" }),
            Hosting::AllowList {
                principals,
                credentials,
            } => json!({
                "mode": "allow_list",
                "principals": principals.iter().map(PrincipalId::to_hex).collect::<Vec<_>>(),
                "credentials": credentials.iter().map(|c| to_hex(c)).collect::<Vec<_>>(),
            }),
        };
        self.admin("PUT", "/admin/hosting", Some(&body))
    }

    /// `GET /admin/quotas`.
    pub fn quotas(&self) -> Result<Value, Error> {
        self.admin("GET", "/admin/quotas", None)
    }

    /// `GET /admin/quotas/<principal>`.
    pub fn quota(&self, principal: &PrincipalId) -> Result<Value, Error> {
        self.admin(
            "GET",
            &format!("/admin/quotas/{}", principal.to_hex()),
            None,
        )
    }

    /// `PUT /admin/quotas/<principal>`.
    pub fn set_quota(&self, principal: &PrincipalId, quota: QuotaOverride) -> Result<Value, Error> {
        let body = json!({
            "resources": quota.resources,
            "bytes": quota.bytes,
            "resource_bytes": quota.resource_bytes,
        });
        self.admin(
            "PUT",
            &format!("/admin/quotas/{}", principal.to_hex()),
            Some(&body),
        )
    }

    /// `DELETE /admin/quotas/<principal>`.
    pub fn clear_quota(&self, principal: &PrincipalId) -> Result<Value, Error> {
        self.admin(
            "DELETE",
            &format!("/admin/quotas/{}", principal.to_hex()),
            None,
        )
    }
}
