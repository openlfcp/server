//! LFCP-IDENTITY-TEST-VECTORS-01 at the spec.lock pin (spec#3, task
//! LFCP-04-403): Device Certificates, `DEVICE_GRANT` / `DEVICE_REVOKE`,
//! Genesis field 5, objects by devices and the session reads of an
//! `identity-01` server.
//!
//! Every case names the Control Chain it is evaluated on in `context`:
//! `records` (other cases' `inputs.cose_sign1`), optionally a fixture
//! `record_set` and `records_after_set`, the referenced `head` and, for
//! session cases, the `latest` accepted head. [`Identity::chain`] resolves
//! that list to exact bytes, in order.

use lfcp::base::{ControlRecordId, PrincipalId, ResourceId};
use lfcp::principal::PrincipalKeys;
use serde_json::Value as Json;

use super::spec::Spec;

/// The identity corpus path in the spec repository.
pub const SUITE: &str = "test-vectors/lfcp-wire-01/LFCP-IDENTITY-TEST-VECTORS-01.json";

pub struct Identity(Json);

/// One Control Record of a context chain.
#[derive(Clone, Debug)]
pub struct Record {
    /// The case that publishes it, or `<set>[i]` for a fixture record set.
    pub name: String,
    pub bytes: Vec<u8>,
}

impl Identity {
    pub fn load() -> Identity {
        Identity(Spec::open().read_json(SUITE))
    }

    pub fn json(&self) -> &Json {
        &self.0
    }

    pub fn cases(&self) -> impl Iterator<Item = &Json> {
        self.0["cases"].as_array().unwrap().iter()
    }

    pub fn case(&self, id: &str) -> &Json {
        self.cases()
            .find(|c| c["id"] == id)
            .unwrap_or_else(|| panic!("no identity case {id}"))
    }

    /// `inputs.<field>.hex` of case `id`.
    pub fn input(&self, id: &str, field: &str) -> Vec<u8> {
        hex(&self.case(id)["inputs"][field])
            .unwrap_or_else(|| panic!("{id}.inputs.{field} is not hex"))
    }

    /// The exact COSE bytes of a published object (in `inputs` for this
    /// suite, positive and negative cases alike).
    pub fn cose(&self, id: &str) -> Vec<u8> {
        self.input(id, "cose_sign1")
    }

    /// A Control Record case's record ID.
    pub fn record_id(&self, id: &str) -> ControlRecordId {
        ControlRecordId::from_slice(&self.input(id, "record_id")).unwrap()
    }

    /// The keys of a fixture Principal by label (`OWNER`, `DEV_A`, ...).
    pub fn principal(&self, label: &str) -> PrincipalKeys {
        let inputs = &self.case(&format!("principal_{}", label.to_ascii_lowercase()))["inputs"];
        let key = |f: &str| -> [u8; 32] { hex(&inputs[f]).unwrap().try_into().unwrap() };
        PrincipalKeys::from_secrets(&key("ed25519_seed"), key("x25519_private"))
    }

    pub fn principal_id(&self, label: &str) -> PrincipalId {
        *self.principal(label).descriptor().id()
    }

    /// The Resource ID of a fixture Resource (`X`, `Y`, `I`, ...).
    pub fn resource(&self, name: &str) -> ResourceId {
        ResourceId::from_slice(&hex(&self.0["fixtures"]["resources"][name]["id"]).unwrap()).unwrap()
    }

    /// The Resource a case's context names.
    pub fn context_resource(&self, id: &str) -> Option<ResourceId> {
        hex(&self.case(id)["context"]["resource_id"]).map(|b| ResourceId::from_slice(&b).unwrap())
    }

    /// The context chain of case `id`, in order: `records`, then the
    /// fixture `record_set`, then `records_after_set`.
    pub fn chain(&self, id: &str) -> Vec<Record> {
        let context = &self.case(id)["context"];
        let mut out = Vec::new();
        let mut refs = |list: &Json| {
            for r in list.as_array().into_iter().flatten() {
                let name = r["case"].as_str().unwrap();
                assert_eq!(r["in"], "inputs", "{id}: {r}");
                let field = r["field"].as_str().unwrap();
                out.push(Record {
                    name: name.to_owned(),
                    bytes: self.input(name, field),
                });
            }
        };
        refs(&context["records"]);
        if let Some(set) = context["record_set"].as_str() {
            let records = self.0["fixtures"]["record_sets"][set]["records"]
                .as_array()
                .unwrap_or_else(|| panic!("record set {set}"));
            for (i, r) in records.iter().enumerate() {
                out.push(Record {
                    name: format!("{set}[{i}]"),
                    bytes: hex(r).unwrap(),
                });
            }
        }
        let after = context["records_after_set"].clone();
        let mut refs = |list: &Json| {
            for r in list.as_array().into_iter().flatten() {
                let name = r["case"].as_str().unwrap();
                out.push(Record {
                    name: name.to_owned(),
                    bytes: self.input(name, r["field"].as_str().unwrap()),
                });
            }
        };
        refs(&after);
        out
    }

    /// The record ID of a context's `head` (the referenced head of the
    /// case's object), if it names one.
    pub fn head(&self, id: &str) -> Option<ControlRecordId> {
        let context = &self.case(id)["context"];
        if let Some(bytes) = hex(&context["head_record_id"]) {
            return Some(ControlRecordId::from_slice(&bytes).unwrap());
        }
        context["head"]["case"]
            .as_str()
            .map(|case| self.record_id(case))
    }

    /// The `latest` accepted head of a session case.
    pub fn latest(&self, id: &str) -> Option<ControlRecordId> {
        self.case(id)["context"]["latest"]["case"]
            .as_str()
            .map(|case| self.record_id(case))
    }

    /// The §62 code a case expects, `None` for an accepted one.
    pub fn expected_code(&self, id: &str) -> Option<u64> {
        let expected = &self.case(id)["expected"];
        if expected["valid"] == true {
            return None;
        }
        let name = expected["error"]["code"]
            .as_str()
            .unwrap_or_else(|| panic!("{id}: no expected code"));
        Some(code_number(name))
    }
}

/// The number of a §62 code name.
pub fn code_number(name: &str) -> u64 {
    (1..=64)
        .find(|&n| lfcp::base::WireCode::from_number(n).is_some_and(|c| c.name() == name))
        .unwrap_or_else(|| panic!("unknown code {name}"))
}

fn hex(value: &Json) -> Option<Vec<u8>> {
    let text = value["hex"].as_str().or_else(|| value.as_str())?;
    lfcp::base::from_hex(text).ok()
}
