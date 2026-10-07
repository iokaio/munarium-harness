// SPDX-License-Identifier: Apache-2.0
use munarium_harness::decision::{
    Client, Error, Outcome, Proposal, Transport, canonical, request_digest,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[test]
fn unchanged_contracts_and_canonical_vectors() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("contracts/stage1");
    let lock: Value =
        serde_json::from_slice(&std::fs::read(root.join("vendor-lock.json")).unwrap()).unwrap();
    for (name, pin) in lock["files"].as_object().unwrap() {
        let raw = std::fs::read_to_string(root.join(name))
            .unwrap()
            .replace("\r\n", "\n");
        assert_eq!(
            format!("{:x}", Sha256::digest(raw.as_bytes())),
            pin["sha256"]
        );
    }
    let v: Value = serde_json::from_str(include_str!(
        "../contracts/stage1/decision-json-v1-vectors.json"
    ))
    .unwrap();
    for c in v["cases"].as_array().unwrap() {
        let raw = c["input"].as_str().unwrap().as_bytes();
        if c["result"] == "reject" {
            assert!(canonical(raw).is_err(), "{}", c["id"]);
        } else {
            assert_eq!(
                canonical(raw).unwrap(),
                c["canonical"].as_str().unwrap().as_bytes()
            );
            assert_eq!(request_digest(raw).unwrap(), c["digest"]);
        }
    }
}

#[test]
fn response_loss_only_allows_lookup_and_preserves_bindings() {
    let v: Value =
        serde_json::from_str(include_str!("../contracts/stage1/record-vectors.json")).unwrap();
    let p = Proposal::parse(&serde_json::to_vec(&v["examples"]["request"]).unwrap()).unwrap();
    struct Wire {
        submits: usize,
        response: Value,
    }
    impl Transport for Wire {
        fn submit(&mut self, _: &Proposal) -> Result<Value, Error> {
            self.submits += 1;
            Err(Error::Unresolved)
        }
        fn lookup(&mut self, _: &str, _: &str) -> Result<Value, Error> {
            Ok(self.response.clone())
        }
    }
    let mut c = Client(Wire {
        submits: 0,
        response: json!({"tenant":p.tenant(),"operation_id":p.operation_id(),"request_digest":p.digest(),"outcome":"unresolved"}),
    });
    assert_eq!(c.submit(&p), Err(Error::Unresolved));
    for name in [
        "denied",
        "approval-required",
        "decision-only-allow",
        "accepted-for-execution",
        "completed",
        "failed-before-dispatch",
        "unresolved",
    ] {
        c.0.response["outcome"] = json!(name);
        let expected: Outcome = serde_json::from_value(json!(name)).unwrap();
        assert_eq!(c.lookup(&p), Ok(expected));
    }
    c.0.response["tenant"] = json!("other");
    assert_eq!(c.lookup(&p), Err(Error::Binding));
    assert_eq!(c.0.submits, 1);
    c.0.response = json!({"schema_version":1,"tenant":p.tenant(),"operation_id":p.operation_id(),"request_digest":p.digest(),"reasons":["lineage-unavailable"]});
    assert_eq!(c.lookup(&p), Err(Error::Refused));
    c.0.response["reasons"] = json!([]);
    assert_eq!(c.lookup(&p), Err(Error::InvalidInput));
}
