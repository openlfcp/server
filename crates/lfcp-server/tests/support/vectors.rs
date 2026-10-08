//! LFCP-TEST-VECTORS-01 at the spec.lock pin.

use lfcp::base::{ControlRecordId, ResourceId};
use lfcp::principal::PrincipalKeys;
use serde_json::Value as Json;

use super::spec::Spec;

pub struct Vectors(Json);

impl Vectors {
    pub fn load() -> Vectors {
        Vectors(Spec::open().read_json("test-vectors/lfcp-wire-01/LFCP-TEST-VECTORS-01.json"))
    }
    /// The whole suite.
    #[allow(dead_code)]
    pub fn json(&self) -> &Json {
        &self.0
    }

    pub fn case(&self, id: &str) -> &Json {
        self.0["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == id)
            .unwrap_or_else(|| panic!("{id}"))
    }
    pub fn hex(&self, id: &str, part: &str, field: &str) -> Vec<u8> {
        lfcp::base::from_hex(
            self.case(id)[part][field]["hex"]
                .as_str()
                .unwrap_or_else(|| panic!("{id}.{field}")),
        )
        .unwrap()
    }
    /// A published wire message's exact bytes.
    pub fn message(&self, id: &str) -> Vec<u8> {
        self.hex(id, "expected", "message_cbor")
    }
    /// A published Control Record, Data Unit or Snapshot.
    pub fn cose(&self, id: &str) -> Vec<u8> {
        self.hex(id, "expected", "cose_sign1")
    }
    /// A published negative object.
    pub fn negative(&self, id: &str) -> Vec<u8> {
        self.hex(id, "inputs", "cose_sign1")
    }
    pub fn session(&self, field: &str) -> Vec<u8> {
        lfcp::base::from_hex(
            self.0["fixtures"]["session"][field]["hex"]
                .as_str()
                .unwrap(),
        )
        .unwrap()
    }
    pub fn principal(&self, name: &str) -> PrincipalKeys {
        let inputs = &self.case(&format!("principal_{name}"))["inputs"];
        let h = |f: &str| -> [u8; 32] {
            lfcp::base::from_hex(inputs[f]["hex"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap()
        };
        PrincipalKeys::from_secrets(&h("ed25519_seed"), h("x25519_private"))
    }
    pub fn resource(&self) -> ResourceId {
        ResourceId::from_slice(
            &lfcp::base::from_hex(
                self.0["fixtures"]["resource"]["id"]["hex"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap(),
        )
        .unwrap()
    }
    pub fn record_id(&self, id: &str) -> ControlRecordId {
        ControlRecordId::from_slice(&self.hex(id, "expected", "record_id")).unwrap()
    }

    /// The §62 code a negative case expects, if it names one.
    pub fn expected_code(&self, id: &str) -> Option<u64> {
        let name = self.case(id)["expected"]["error"]["code"].as_str()?;
        (1..=22).find(|&n| lfcp::base::WireCode::from_number(n).unwrap().name() == name)
    }

    /// A resource fixture's bytes, such as `dek0`.
    pub fn resource_fixture(&self, name: &str) -> Vec<u8> {
        lfcp::base::from_hex(
            self.0["fixtures"]["resource"][name]["hex"]
                .as_str()
                .unwrap(),
        )
        .unwrap()
    }
}

/// The published Control Chain, in order.
pub const CHAIN: [&str; 11] = [
    "C0_genesis",
    "C1_grant_bob",
    "C2_invite_grant",
    "C3_invite_claim_carol",
    "C4_owner_transfer_commit",
    "C5_route_update",
    "C6_key_epoch_1",
    "C7_grant_carol_delegator",
    "C8_grant_owner_delegated",
    "C9_grant_invite_grandchild",
    "C10_revoke_grandchild",
];

/// Host the published Resource in `store` and commit `CHAIN[1..=last]`.
pub async fn host_chain(store: &lfcp_server::store::Store, v: &Vectors, last: usize) {
    store
        .host_resource(
            v.cose(CHAIN[0]),
            lfcp_server::store::Hosting {
                host: *v.principal("owner").descriptor().id(),
                durability: 2,
            },
        )
        .await
        .unwrap();
    for i in 1..=last {
        store
            .commit_control_record(v.cose(CHAIN[i]), v.record_id(CHAIN[i - 1]))
            .await
            .unwrap();
    }
}
