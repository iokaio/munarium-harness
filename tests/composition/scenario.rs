// SPDX-License-Identifier: Apache-2.0
//! Executed only by scripts/run_stage1.py with actual component sources and its own lock.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ed25519_dalek::{Signer, SigningKey};
use munarium_core::{
    platform::{EventLedger, RecorderContext, record_digest, verify_ack},
    storage::StorageBackend,
};
use munarium_gate::{
    decision::{self, Engine, Error, Evidence, Host, Principal, Snapshot},
    opa::Opa,
};
use munarium_harness::decision::Proposal;
use munarium_harness::decision::{Client, Error as ClientError, Outcome, Transport};
use munarium_registry::{
    candidate::{Permission, Query, Registry, Submission, TrustSnapshot},
    identity as ri,
};
use munarium_store_mem::MemStore;
use munarium_warden::principal::{self, Trust, TrustedKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::PathBuf};

fn bytes(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).unwrap()
}
fn hash(raw: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(raw))
}
fn pin(domain: &str, v: &Value) -> String {
    decision::digest(domain, &bytes(v))
}
fn load(path: impl AsRef<std::path::Path>) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}
fn sign(k: &SigningKey, typ: &str, kid: &str, p: &Value) -> String {
    let h = json!({"alg":"Ed25519","kid":kid,"typ":typ});
    let input = format!("{}.{}", B64.encode(bytes(&h)), B64.encode(bytes(p)));
    format!(
        "{input}.{}",
        B64.encode(k.sign(input.as_bytes()).to_bytes())
    )
}
fn assertion(
    k: &SigningKey,
    audience: &str,
    service: &str,
    scopes: Value,
    resources: Value,
) -> String {
    sign(
        k,
        "munarium-principal+jws",
        "test-issuer",
        &json!({"schema_version":1,"deployment":"stage1","tenant":"alpha","issuer":"stage1-issuer",
        "audience":audience,"origin":service,"actor":service,"origin_kind":"service","service":service,"purpose":"decision",
        "scopes":scopes,"resources":resources,"iat":980,"nbf":980,"exp":1040,"parent_digest":null,"bootstrap":null}),
    )
}
fn trust(k: &SigningKey, audience: &str, peer: &str, policy: &str) -> Trust {
    Trust {
        deployment: "stage1".into(),
        tenant: "alpha".into(),
        audience: audience.into(),
        peer_service: peer.into(),
        now: 1000,
        available: true,
        keys: BTreeMap::from([(
            "test-issuer".into(),
            TrustedKey {
                public_key: k.verifying_key().to_bytes(),
                issuer: "stage1-issuer".into(),
                decision: true,
            },
        )]),
        delegations: vec![],
        task_digest: hash(b"stage1-task"),
        policy_digest: policy.into(),
        not_before: 900,
        expires: 1100,
        scopes: vec!["read".into(), "evaluate".into(), "propose".into()],
        resources: vec!["sandbox-release".into(), "catalog".into(), "events".into()],
        maximum_depth: 4,
    }
}
fn registry_context(k: &SigningKey, policy: &str) -> ri::Context {
    let authority = ri::Authority {
        digest: policy.into(),
        not_before: 900,
        expires: 1100,
        scopes: vec!["read".into(), "propose".into()],
        resources: vec!["catalog".into()],
    };
    ri::Context {
        deployment: "stage1".into(),
        tenant: "alpha".into(),
        audience: "svc-registry".into(),
        peer_service: "svc-gate".into(),
        now: 1000,
        available: true,
        restore_quarantined: false,
        keys: BTreeMap::from([(
            "test-issuer".into(),
            ri::IssuerKey {
                public_key: B64.encode(k.verifying_key().to_bytes()),
                issuer: "stage1-issuer".into(),
                decision: true,
            },
        )]),
        task: authority.clone(),
        policy: authority,
        maximum_depth: 4,
        registrations: vec![],
        access: [Permission::Submit, Permission::Read, Permission::List]
            .into_iter()
            .map(|permission| ri::AccessRule {
                permission,
                resource: "catalog".into(),
            })
            .collect(),
    }
}
struct Composition {
    registry: Registry,
    registry_context: ri::Context,
    registry_chain: Vec<String>,
    gate_trust: Trust,
    server_trust: Trust,
    server_chain: Vec<String>,
    snapshot: Snapshot,
    runtime: tokio::runtime::Runtime,
    store: Box<dyn StorageBackend>,
    version: String,
    sequence: u64,
    prior: Option<String>,
    recording: bool,
}
impl Host for Composition {
    fn principal(&mut self, chain: &[String]) -> Result<Principal, Error> {
        let p = principal::verify(chain, &self.gate_trust).map_err(|_| Error::Identity)?;
        Ok(Principal {
            origin:p.origin().into(),actor:p.actor().into(),origin_kind:p.origin_kind().into(),
            tenant: p.tenant().into(),
            digest: p.fingerprint().into(),
            scopes: p.scopes().to_vec(),
            resources: p.resources().to_vec(),
        })
    }
    fn snapshot(&mut self, tenant: &str, r: &Value) -> Result<Snapshot, Error> {
        if tenant != self.registry_context.tenant {
            return Err(Error::Identity);
        }
        let query = Query {
            manifest_digest: r["manifest_digest"].as_str().ok_or(Error::Manifest)?.into(),
            artifact_digest: Some(self.snapshot.artifact_digest.clone()),
        };
        let candidate = ri::resolve(
            &self.registry,
            &self.registry_chain,
            &self.registry_context,
            &query,
        )
        .map_err(|_| Error::Manifest)?;
        let mut snapshot = self.snapshot.clone();
        snapshot.manifest = candidate.manifest().clone();
        for evidence in &mut snapshot.evidence {
            let source: Value =
                serde_json::from_slice(&evidence.source).map_err(|_| Error::Lineage)?;
            if source["artifact_digest"] != r["parameters"]["artifact_digest"]
                || !source["tests.passed"].is_boolean()
            {
                return Err(Error::Lineage);
            }
            evidence.value = source["tests.passed"].clone();
        }
        Ok(snapshot)
    }
    fn record(&mut self, r: &Value, d: &Value, replay: &[u8]) -> Result<(), Error> {
        if !self.recording {
            return Err(Error::Recording);
        }
        let peer = principal::verify(&self.server_chain, &self.server_trust)
            .map_err(|_| Error::Identity)?;
        let context = RecorderContext {
            identity: recorder_identity(&peer),
            tenant: peer.tenant().into(),
            service: peer.service().into(),
            source: "svc-gate".into(),
            epoch: 1,
            can_record: peer.permits("propose", "events"),
            can_read: peer.permits("read", "events"),
        };
        let ledger = EventLedger::new(self.store.as_ref(), "alpha", &self.version);
        for (kind, payload) in [
            ("proposal", r),
            (
                if d.get("outcome").is_some() {
                    "decision"
                } else {
                    "refusal"
                },
                d,
            ),
        ] {
            let next = self.sequence + 1;
            let event = json!({"schema_version":1,"convention":"decision-events-v1","tenant":"alpha","source_service":"svc-gate","source_epoch":1,
                "event_id":format!("event-{next}"),"sequence":next,"prior_event_digest":self.prior,"operation_id":r["operation_id"],
                "request_digest":pin("munarium:decision-request:v1",r),"kind":kind,"recorded_at":1000,
                "payload_digest":record_digest("munarium:decision-event-payload:v1",payload).map_err(|_|Error::Recording)?,"causation":[],"correlation":[],"payload":payload});
            let ack = self
                .runtime
                .block_on(ledger.append(&context, &bytes(&event)))
                .map_err(|_| Error::Recording)?;
            verify_ack(&event, &ack).map_err(|_| Error::Recording)?;
            self.sequence = next;
            self.prior = Some(
                record_digest("munarium:decision-event:v1", &event)
                    .map_err(|_| Error::Recording)?,
            );
        }
        self.runtime
            .block_on(ledger.archive_replay(&context, replay))
            .map_err(|_| Error::Recording)?;
        Ok(())
    }
}

struct LocalTransport<'a> {
    host: &'a mut Composition,
    engine: &'a mut Opa,
    chain: &'a [String],
    submits: usize,
}
impl Transport for LocalTransport<'_> {
    fn submit(&mut self, proposal: &Proposal) -> Result<Value, ClientError> {
        self.submits += 1;
        decision::decide(proposal.bytes(), self.chain, self.host, self.engine)
            .map_err(|_| ClientError::Unresolved)?;
        // Deliberately lose the acknowledged response; recovery must only read.
        Err(ClientError::Unresolved)
    }
    fn lookup(&mut self, tenant: &str, operation: &str) -> Result<Value, ClientError> {
        let caller = principal::verify(self.chain, &self.host.gate_trust)
            .map_err(|_| ClientError::Binding)?;
        if caller.tenant() != tenant {
            return Err(ClientError::Binding);
        }
        let recorder = principal::verify(&self.host.server_chain, &self.host.server_trust)
            .map_err(|_| ClientError::Binding)?;
        let context = RecorderContext {
            identity: recorder_identity(&recorder),
            tenant: caller.tenant().into(),
            service: recorder.service().into(),
            source: "svc-gate".into(),
            epoch: 1,
            can_record: false,
            can_read: recorder.permits("read", "events"),
        };
        let ledger = EventLedger::new(self.host.store.as_ref(), "alpha", &self.host.version);
        let events = self
            .host
            .runtime
            .block_on(ledger.lookup(&context, operation))
            .map_err(|_| ClientError::Binding)?;
        events
            .iter()
            .find(|e| e["kind"] == "decision")
            .map(|e| e["payload"].clone())
            .ok_or(ClientError::Unresolved)
    }
}

fn main() {
    let root = PathBuf::from(std::env::var("STAGE1_WORKSPACE").unwrap());
    let gate = root.join("munarium-gate");
    let executable = PathBuf::from(std::env::var("STAGE1_OPA").unwrap());
    let worker = gate.join("scripts/opa_worker.py");
    let mut engine = Opa {
        python: PathBuf::from(std::env::var("STAGE1_PYTHON").unwrap()),
        worker_digest: hash(&std::fs::read(&worker).unwrap()),
        worker,
        executable_digest: hash(&std::fs::read(&executable).unwrap()),
        executable,
        version: "1.21.1".into(),
        capabilities: load(std::env::var("STAGE1_CAPABILITIES").unwrap()),
    };
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).unwrap();
    let key = SigningKey::from_bytes(&seed);
    seed.fill(0);
    let artifact = b"munarium reference artifact A\n";
    let schema = json!({"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","properties":{"artifact_digest":{"type":"string","minLength":71,"maxLength":71}},"required":["artifact_digest"],"additionalProperties":false});
    let spec = json!({"field_path":"tests.passed","source_id":"build-receipt","derivation_id":"test-result","derivation_version":"1","permitted_use":"decision"});
    let policy = json!({"engine":"opa","version":engine.version(),"engine_digest":engine.digest(),"worker_digest":engine.worker_digest,
        "capabilities_digest":pin("munarium:opa-capabilities:v1",&engine.capabilities),
        "rules":{"permit":null,"approval":{"kind":"distinct-approval","approver_scope":"council:ratify"}},"inputs":[spec],
        "code":"package munarium\nimport rego.v1\ndecision := {\"allow\": input.evidence[\"tests.passed\"] == true, \"forbid\": false, \"rules\": [\"permit\"], \"predicates\": {}, \"diagnostics\": []}\n"});
    let policy_digest = pin("munarium:decision-policy:v1", &policy);
    let mut inventory = load(root.join("munarium-registry/contracts/registry-v2/trust.json"));
    inventory["tenants"].as_array_mut().unwrap().truncate(1);
    let tenant = &mut inventory["tenants"][0];
    let schema_digest = pin("munarium:capability-schema:v1", &schema);
    tenant["schemas"][0] =
        json!({"digest":schema_digest,"canonical":String::from_utf8(bytes(&schema)).unwrap()});
    let mut operation = tenant["operations"][0].clone();
    operation["target_id"] = json!("sandbox-release");
    operation["capability_id"] = json!("release.publish_approved_artifact");
    operation["operation_id"] = json!("release.publish_approved_artifact");
    operation["parameter_schema_digest"] = json!(schema_digest);
    tenant["operations"] = json!([operation]);
    tenant["publishers"].as_array_mut().unwrap().truncate(1);
    tenant["publishers"][0]["public_key"] = json!(B64.encode(key.verifying_key().to_bytes()));
    tenant["publishers"][0]["operations"] = tenant["operations"].clone();
    let vectors = load(root.join("munarium-registry/contracts/registry-v2/signed-vectors.json"));
    let mut manifest: Value =
        serde_json::from_str(vectors["cases"][0]["payload"].as_str().unwrap()).unwrap();
    for f in [
        "target_id",
        "capability_id",
        "operation_id",
        "parameter_schema_digest",
    ] {
        manifest[f] = operation[f].clone();
    }
    manifest["required_inputs"] = json!([spec]);
    manifest["effect"] = json!("external-effect");
    let envelope = sign(&key, "munarium-manifest+jws", "key-1", &manifest);
    let mut registry = Registry::new(
        TrustSnapshot::from_canonical_json(&bytes(&inventory)).unwrap(),
        32,
    );
    let registry_context = registry_context(&key, &policy_digest);
    let registry_chain = vec![assertion(
        &key,
        "svc-registry",
        "svc-gate",
        json!(["read", "propose"]),
        json!(["catalog"]),
    )];
    let candidate = ri::submit(
        &mut registry,
        &registry_chain,
        &registry_context,
        &Submission {
            envelope: envelope.clone(),
        },
    )
    .unwrap();
    assert_eq!(
        ri::list(&registry, &registry_chain, &registry_context)
            .unwrap()
            .len(),
        1
    );
    let chain = vec![assertion(
        &key,
        "svc-gate",
        "svc-harness",
        json!(["evaluate"]),
        json!(["sandbox-release"]),
    )];
    let request = json!({"schema_version":1,"profile":"decision-json-v1","tenant":"alpha","operation_id":"ref01-allow","principal_digest":hash(chain[0].as_bytes()),
        "target_id":"sandbox-release","environment":"test","capability_id":"release.publish_approved_artifact","manifest_digest":candidate.manifest_digest(),
        "policy_digest":policy_digest,"activation_epoch":1,"mode":"enforce","parameters":{"artifact_digest":hash(artifact)},"attachments":[]});
    let binding = json!({"available":true,"tenant":"alpha","target_id":"sandbox-release","environment":"test","manifest_digest":candidate.manifest_digest(),
        "artifact_digest":candidate.artifact_digest(),"policy_digest":policy_digest,"activation_epoch":1,"mode":"enforce"});
    let source = bytes(&json!({"tests.passed":true,"artifact_digest":hash(artifact)}));
    let lineage = json!({"tenant":"alpha","source_id":"build-receipt","revision":"1","content_digest":hash(&source),"derivation_id":"test-result","derivation_version":"1",
        "field_path":"tests.passed","observed_at":1000,"evidence_ref":"receipt-a","trust":"verified","verifier_ref":"fixture-build-verifier","policy_digest":policy_digest});
    let snapshot = Snapshot {
        manifest: manifest.clone(),
        artifact_digest: candidate.artifact_digest().into(),
        binding,
        policy,
        parameter_schema: schema,
        evidence: vec![Evidence {
            lineage,
            source: source.to_vec(),
            value: json!(true),
        }],
        attachments: vec![],
    };
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let store: Box<dyn StorageBackend> =
        if let Ok(url) = std::env::var("MUNARIUM_TEST_DATABASE_URL") {
            Box::new(
                runtime
                    .block_on(munarium_store_pg::PgStore::connect(&url, "alpha"))
                    .expect("isolated PostgreSQL unavailable"),
            )
        } else {
            Box::new(MemStore::new())
        };
    let version = runtime.block_on(store.create_version(None, None)).unwrap();
    let mut host = Composition {
        registry,
        registry_context,
        registry_chain,
        gate_trust: trust(&key, "svc-gate", "svc-harness", &policy_digest),
        server_trust: trust(&key, "svc-server", "svc-gate", &policy_digest),
        server_chain: vec![assertion(
            &key,
            "svc-server",
            "svc-gate",
            json!(["read", "propose"]),
            json!(["events"]),
        )],
        snapshot,
        runtime,
        store,
        version,
        sequence: 0,
        prior: None,
        recording: true,
    };
    let proposal = Proposal::parse(&bytes(&request)).unwrap();
    let receipt = decision::decide(proposal.bytes(), &chain, &mut host, &mut engine).unwrap();
    assert_eq!(receipt.decision()["outcome"], "decision-only-allow");
    assert_eq!(receipt.replay(&mut engine).unwrap(), *receipt.decision());
    assert_eq!(host.sequence, 2);
    let baseline = host.snapshot.clone();
    let mut cases = vec![
        json!({"id":"REF-01-allow-replay","result":"passed","execution":"not linked; no independent network-isolation claim"}),
    ];
    for (i, name) in [
        "policy-deny",
        "inactive-candidate",
        "unknown-manifest",
        "missing-lineage",
        "untrusted-lineage",
        "tenant-substitution",
        "recording-outage",
        "retired-identity",
    ]
    .iter()
    .enumerate()
    {
        host.snapshot = baseline.clone();
        host.recording = true;
        host.gate_trust.available = true;
        let mut r = request.clone();
        r["operation_id"] = json!(format!("case-{i}"));
        match i {
            0 => {
                let source = bytes(&json!({"tests.passed":false,"artifact_digest":hash(artifact)}));
                host.snapshot.evidence[0].lineage["content_digest"] = json!(hash(&source));
                host.snapshot.evidence[0].source = source;
            }
            1 => host.snapshot.binding["available"] = json!(false),
            2 => r["manifest_digest"] = json!(hash(b"missing")),
            3 => host.snapshot.evidence.clear(),
            4 => host.snapshot.evidence[0].lineage["trust"] = json!("untrusted"),
            5 => r["tenant"] = json!("beta"),
            6 => host.recording = false,
            _ => host.gate_trust.available = false,
        }
        let result = decision::decide(&bytes(&r), &chain, &mut host, &mut engine);
        if matches!(i, 5..=7) {
            assert!(result.is_err(), "{name}");
        } else {
            let receipt = result.unwrap();
            if i == 0 {
                assert_eq!(receipt.decision()["outcome"], "denied");
                assert_eq!(receipt.replay(&mut engine).unwrap(), *receipt.decision());
            } else {
                assert!(receipt.decision().get("outcome").is_none(), "{name}");
            }
        }
        cases.push(json!({"id":name,"result":"passed","execution":"not linked; no independent network-isolation claim"}));
    }
    host.gate_trust.available = true;
    host.recording = true;
    host.snapshot = baseline;
    let mut lost = request.clone();
    lost["operation_id"] = json!("lost-response");
    let p = Proposal::parse(&bytes(&lost)).unwrap();
    let mut client = Client(LocalTransport {
        host: &mut host,
        engine: &mut engine,
        chain: &chain,
        submits: 0,
    });
    assert_eq!(client.submit(&p), Err(ClientError::Unresolved));
    assert_eq!(client.lookup(&p), Ok(Outcome::DecisionOnlyAllow));
    assert_eq!(client.0.submits, 1);
    drop(client);
    cases.push(json!({"id":"response-loss-read-only-recovery","result":"passed"}));
    let head = host
        .runtime
        .block_on(host.store.head(&host.version))
        .unwrap();
    let mut changed = request.clone();
    changed["parameters"]["artifact_digest"] = json!(hash(b"artifact B"));
    assert!(decision::decide(&bytes(&changed), &chain, &mut host, &mut engine).is_err());
    assert_eq!(
        host.runtime
            .block_on(host.store.head(&host.version))
            .unwrap(),
        head
    );
    cases.push(json!({"id":"changed-operation-content","result":"passed"}));
    assert_eq!(
        ri::list(&host.registry, &host.registry_chain, &host.registry_context)
            .unwrap()
            .len(),
        1
    );
    let context = RecorderContext {
        identity: recorder_identity(&principal::verify(&host.server_chain, &host.server_trust).unwrap()),
        tenant: "alpha".into(),
        service: "svc-gate".into(),
        source: "svc-gate".into(),
        epoch: 1,
        can_record: true,
        can_read: true,
    };
    let ledger = EventLedger::new(host.store.as_ref(), "alpha", &host.version);
    assert_eq!(
        host.runtime
            .block_on(ledger.lookup(&context, "ref01-allow"))
            .unwrap()
            .len(),
        2
    );
    let (archived, digest) = host
        .runtime
        .block_on(ledger.replay(&context, "ref01-allow"))
        .unwrap()
        .unwrap();
    drop(receipt);
    let recovered = decision::Receipt::restore(&archived, &digest).unwrap();
    assert_eq!(
        recovered.replay(&mut engine).unwrap(),
        *recovered.decision()
    );
    cases.push(json!({"id":"durable-replay-bundle","result":"passed"}));
    println!(
        "STAGE1_EVIDENCE {}",
        json!({"ledger_id":host.version,"head":host.runtime.block_on(host.store.head(&host.version)).unwrap(),
        "source_service":"svc-gate","source_epoch":1,"source_sequence_start":1,"source_sequence_end":host.sequence,
        "last_event_digest":host.prior,"operation_id":"ref01-allow","replay_digest":digest,
        "manifest_digest":request["manifest_digest"],"policy_digest":policy_digest,"mode":"enforce","activation_epoch":1,
        "grants":"not exercised: no grant issuer in composition","sends":"not exercised: no connector in composition","effects":"not exercised: no target provisioned",
        "restore":"not exercised; reconnect tested separately","checkpoints":"not part of Stage 1"})
    );
    println!("STAGE1_RESULT {}", serde_json::to_string(&cases).unwrap());
}

fn recorder_identity(p: &principal::Principal) -> munarium_core::platform::RecorderIdentity {
    munarium_core::platform::RecorderIdentity { origin:p.origin().into(), actor:p.actor().into(), origin_kind:p.origin_kind().into(), principal_digest:p.fingerprint().into() }
}
