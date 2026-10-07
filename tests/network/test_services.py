# SPDX-License-Identifier: Apache-2.0
"""PYTEST_DONT_REWRITE
Separate-process Stage 1 acceptance with ephemeral operator/provider/service keys.

Requires STAGE1_WORKSPACE, STAGE1_OPA, and MUNARIUM_PLATFORM_TEST_BINARY.
The optional MUNARIUM_PLATFORM_TEST_DATABASE_URL must name a disposable database.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import ssl
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
import subprocess
import sys
import time

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "python"))
from munarium_harness.decision import Client, Outcome, Proposal, Unresolved  # noqa: E402
from munarium_harness.https import HttpsTransport  # noqa: E402


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize("database", ["memory", "postgres"])
def test_separate_services(database):
    if not os.environ.get("STAGE1_WORKSPACE"):
        pytest.skip("explicit Stage 1 workspace required")
    if database == "postgres" and not os.environ.get("MUNARIUM_PLATFORM_TEST_DATABASE_URL"):
        pytest.skip("isolated PostgreSQL required")
    workspace = Path(os.environ["STAGE1_WORKSPACE"])
    fixture = load_module("platform_fixture", workspace / "munarium/clients/python/tests/test_platform_authority_live.py")
    evaluator = load_module("stage1_opa", workspace / "munarium-gate/scripts/check_opa.py")
    from munarium_client import ApiRequest
    canonical, digest, b64 = fixture.canonical, fixture.digest, fixture.b64
    opa = Path(os.environ["STAGE1_OPA"]).resolve(strict=True)
    assert sha(opa.read_bytes()) == evaluator.PIN
    caps = evaluator.capabilities(opa)

    def sign(key, header, payload):
        message = b64(canonical(header)) + "." + b64(canonical(payload))
        return message + "." + b64(key.sign(message.encode()))

    services = ("svc-warden", "svc-registry", "svc-gate", "svc-harness", "svc-other")
    with fixture.deployment(database, services) as d:
        tenant, directory = d["tenant"], d["directory"]
        now = int(time.time())
        issuer, provider, publisher = (ed25519.Ed25519PrivateKey.generate() for _ in range(3))
        issuer_file = directory / "warden-signing.key"
        issuer_file.write_bytes(issuer.private_bytes_raw())
        ports = {name: fixture.port() for name in services[:3]}
        endpoints = {name: f"https://127.0.0.1:{port}" for name, port in ports.items()}
        worker = workspace / "munarium-gate/scripts/opa_worker.py"
        engine = dict(python=sys.executable, worker=str(worker), executable=str(opa),
                      worker_digest=sha(worker.read_bytes()), executable_digest=evaluator.PIN,
                      version="1.21.1", capabilities=caps)
        schema = {"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object",
                  "properties": {"artifact_digest": {"type": "string", "minLength": 71, "maxLength": 71}},
                  "required": ["artifact_digest"], "additionalProperties": False}
        spec = dict(field_path="tests.passed", source_id="build-receipt", derivation_id="test-result",
                    derivation_version="1", permitted_use="decision")
        policy = dict(engine="opa", version="1.21.1", engine_digest=evaluator.PIN,
                      worker_digest=engine["worker_digest"], capabilities_digest=digest("munarium:opa-capabilities:v1", caps),
                      rules={"permit": None}, inputs=[spec],
                      code='package munarium\nimport rego.v1\ndecision := {"allow": input.evidence["tests.passed"] == true, "forbid": false, "rules": ["permit"], "predicates": {}, "diagnostics": []}\n')
        policy_digest = digest("munarium:decision-policy:v1", policy)
        inventory = json.loads((workspace / "munarium-registry/contracts/registry-v2/trust.json").read_bytes())
        inventory["tenants"] = inventory["tenants"][:1]
        catalog = inventory["tenants"][0]
        catalog["id"] = tenant
        schema_digest = digest("munarium:capability-schema:v1", schema)
        catalog["schemas"][0] = dict(digest=schema_digest, canonical=canonical(schema).decode())
        operation = dict(catalog["operations"][0], target_id="sandbox-release",
                         capability_id="release.publish_approved_artifact", operation_id="release.publish_approved_artifact",
                         parameter_schema_digest=schema_digest)
        catalog["operations"] = [operation]
        catalog["publishers"] = catalog["publishers"][:1]
        catalog["publishers"][0].update(public_key=b64(publisher.public_key().public_bytes_raw()), operations=[operation])
        vectors = json.loads((workspace / "munarium-registry/contracts/registry-v2/signed-vectors.json").read_bytes())
        manifest = json.loads(vectors["cases"][0]["payload"])
        manifest.update({key: operation[key] for key in ("target_id", "capability_id", "operation_id", "parameter_schema_digest")})
        manifest.update(tenant=tenant, required_inputs=[spec], effect="external-effect")
        envelope = sign(publisher, dict(alg="Ed25519", kid="key-1", typ="munarium-manifest+jws"), manifest)
        manifest_digest = digest("munarium:manifest:v2", manifest)
        artifact_digest = sha(b"munarium:manifest-artifact:v2\0" + envelope.encode())
        artifact = sha(b"fictional-release-bytes")
        source = canonical({"tests.passed": True, "artifact_digest": artifact})
        snapshot = dict(manifest=manifest, artifact_digest=artifact_digest, policy=policy, parameter_schema=schema,
                        binding=dict(available=True, tenant=tenant, target_id="sandbox-release", environment="test",
                                     manifest_digest=manifest_digest, artifact_digest=artifact_digest, policy_digest=policy_digest,
                                     activation_epoch=1, mode="enforce"), attachments=[],
                        evidence=[dict(source=list(source), value=False, lineage=dict(
                            tenant=tenant, source_id="build-receipt", revision="1", content_digest=sha(source),
                            derivation_id="test-result", derivation_version="1", field_path="tests.passed", observed_at=now,
                            evidence_ref="receipt-a", trust="verified", verifier_ref="fixture-verifier", policy_digest=policy_digest))])

        def identity(peers):
            contexts = {}
            for peer, scopes, resources in peers:
                restriction = dict(digest=policy_digest, nbf=now-10, exp=now+600, scopes=scopes, resources=resources)
                contexts[peer] = dict(task=restriction, policy=restriction, maximum_depth=0)
            return dict(keys={"warden": dict(public_key=b64(issuer.public_key().public_bytes_raw()), issuer="warden", decision=True)},
                        peers=contexts, registrations=[])

        bindings = {
            "identity:svc-server": identity([("svc-gate", ["read", "propose"], ["records:"+tenant])]),
            "identity:svc-registry": identity([(p, ["read", "propose"], ["registry:"+tenant]) for p in ("svc-gate", "svc-harness")]),
            "identity:svc-gate": identity([(p, ["read", "evaluate"], ["sandbox-release"]) for p in ("svc-harness", "svc-other")]),
            "registry": inventory,
            "decisions": {"sandbox-release": snapshot},
        }
        roots = []
        for peer in ("svc-gate", "svc-harness", "svc-other"):
            roots.append(dict(schema_version=1, binding_id=peer, deployment="stage1-live", tenant=tenant,
                              provider_issuer="fixture-provider", provider_subject=peer, origin_kind="service", origin=peer,
                              peer_service=peer, audiences=["svc-server", "svc-registry", "svc-gate"],
                              scopes=["read", "propose", "evaluate"], resources=["records:"+tenant, "registry:"+tenant, "sandbox-release"],
                              nbf=now-10, exp=now+600))
        bindings["warden"] = dict(providers={"workload": dict(issuer="fixture-provider", audience="warden-admission", key_id="provider",
                                                             public_key=b64(provider.public_key().public_bytes_raw()),
                                                             subjects={r["origin"]: "service" for r in roots})}, bindings=roots)
        governance = dict(schema_version=1, bindings=bindings, retire_bootstrap=False, successor_keys={})

        def install(nonce):
            path = {"tenant": tenant}
            state = d["api"].get_platform_authority(ApiRequest(path=path)).json()
            d["api"].transition_platform_authority(ApiRequest.json(fixture.signed(d, state, governance, nonce), path=path))

        install("network-setup")
        tokens = {}
        for root in roots:
            peer = root["origin"]
            tokens[peer] = sign(provider, dict(alg="EdDSA", kid="provider", typ="at+jwt"),
                                dict(iss="fixture-provider", sub=peer, aud="warden-admission", iat=now-5, nbf=now-5, exp=now+600))
        token_file = directory / "gate-provider.token"
        token_file.write_text(tokens["svc-gate"])

        def tls(name, peers):
            cert, key, _ = d["identities"][name]
            return dict(listen=f"127.0.0.1:{ports[name]}", certificate_file=str(cert), private_key_file=str(key),
                        ca_file=str(directory / "ca.pem"),
                        peers={d["identities"][p][2]: dict(service=p, tenants=[tenant]) for p in peers})

        configs = {
            "svc-warden": dict(tls=tls("svc-warden", ("svc-gate", "svc-harness", "svc-other")), server_endpoint=d["endpoint"],
                               deployment="stage1-live", signing_key_file=str(issuer_file), key_id="warden"),
            "svc-registry": dict(tls=tls("svc-registry", ("svc-gate", "svc-harness")), server_endpoint=d["endpoint"],
                                 deployment="stage1-live", service="svc-registry", database_directory=str(directory), capacity=32),
            "svc-gate": dict(tls=tls("svc-gate", ("svc-harness", "svc-other")), server_endpoint=d["endpoint"],
                             registry_endpoint=endpoints["svc-registry"], warden_endpoint=endpoints["svc-warden"],
                             deployment="stage1-live", service="svc-gate", server_service="svc-server", registry_service="svc-registry",
                             provider_id="workload", provider_token_file=str(token_file), journal=str(directory / "gate.sqlite"), evaluator=engine),
        }
        # Fault boundary validates Gate's actual certificate, forwards to the real Server
        # with Gate's enrolled identity, and can lose one acknowledgement after commit.
        faults = {"lose_archive_ack": False}
        upstream = d["http"](d["identities"]["svc-gate"])

        class FaultBoundary(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def forward(self):
                if hashlib.sha256(self.connection.getpeercert(binary_form=True)).hexdigest() != d["identities"]["svc-gate"][2]:
                    self.send_error(403)
                    return
                length = int(self.headers.get("Content-Length", "0"))
                if length > 16 * 1024 * 1024:
                    self.send_error(413)
                    return
                body = self.rfile.read(length)
                response = upstream.request(self.command, d["endpoint"]+self.path, content=body,
                                            headers={"Content-Type": "application/json"})
                if (faults["lose_archive_ack"] and self.command == "POST" and self.path.endswith("/records")
                        and json.loads(body)["action"]["operation"] == "archive" and response.status_code == 200):
                    faults["lose_archive_ack"] = False
                    self.connection.shutdown(socket.SHUT_RDWR)
                    self.close_connection = True
                    return
                self.send_response(response.status_code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response.content)))
                self.end_headers()
                self.wfile.write(response.content)

            do_GET = forward
            do_POST = forward

        boundary = ThreadingHTTPServer(("127.0.0.1", 0), FaultBoundary)
        boundary_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        boundary_context.load_cert_chain(*[str(p) for p in d["identities"]["svc-other"][:2]])
        boundary_context.load_verify_locations(cafile=str(directory / "ca.pem"))
        boundary_context.verify_mode = ssl.CERT_REQUIRED
        boundary.socket = boundary_context.wrap_socket(boundary.socket, server_side=True)
        boundary_thread = Thread(target=boundary.serve_forever, daemon=True)
        boundary_thread.start()
        configs["svc-gate"]["server_endpoint"] = f"https://127.0.0.1:{boundary.server_port}"
        processes = {}
        env = {k: os.environ[k] for k in ("PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP") if k in os.environ}
        client = d["http"](d["identities"]["svc-harness"])
        client.timeout = httpx.Timeout(20)

        def start(name):
            config = directory / f"{name}.json"
            config.write_bytes(canonical(configs[name]))
            binary = workspace / ("munarium-"+name.removeprefix("svc-")) / "target/debug" / ("munarium-"+name.removeprefix("svc-")+".exe")
            processes[name] = subprocess.Popen([str(binary), str(config)], env=env, stdin=subprocess.DEVNULL,
                                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            deadline = time.monotonic()+10
            route = {"svc-warden": "/v1/identity", "svc-registry": "/v1/candidates", "svc-gate": "/v1/decisions"}[name]
            while time.monotonic() < deadline:
                assert processes[name].poll() is None, name+" exited"
                try:
                    if client.get(endpoints[name]+route, timeout=1).status_code == 405:
                        return
                except httpx.TransportError:
                    pass
                time.sleep(0.05)
            pytest.fail(name+" did not start")

        def stop(name):
            process = processes.pop(name)
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)

        def issue(audience, scopes, resources, *, peer="svc-harness", token=None):
            with d["http"](d["identities"][peer]) as requester:
                response = requester.post(endpoints["svc-warden"]+"/v1/identity", json=dict(tenant=tenant, audience=audience,
                    action=dict(operation="root", provider_id="workload", token=token or tokens[peer], scopes=scopes, resources=resources)))
            assert response.status_code == 200, "Warden issuance refused"
            result = response.json()
            time.sleep(max(0, result["usable_at"]-time.time()+0.1))
            return result["chain"]

        try:
            for name in services[:3]:
                start(name)
            registry_chain = issue("svc-registry", ["read", "propose"], ["registry:"+tenant])
            candidate_body = dict(tenant=tenant, chain=registry_chain, action=dict(operation="submit", envelope=envelope))
            candidate = client.post(endpoints["svc-registry"]+"/v1/candidates", json=candidate_body)
            assert candidate.status_code == 200, "candidate submission refused"
            assert candidate.json()["active"] is False and candidate.json()["manifest_digest"] == manifest_digest
            stop("svc-registry")
            start("svc-registry")
            assert client.post(endpoints["svc-registry"]+"/v1/candidates", json=candidate_body).json() == candidate.json()
            assert client.post(endpoints["svc-registry"]+"/v1/candidates", json=dict(candidate_body, action=dict(operation="submit", envelope=envelope+"x"))).status_code == 403
            assert client.post(endpoints["svc-registry"]+"/v1/candidates", json=dict(candidate_body, tenant="foreign")).status_code == 403
            invalid_root = dict(tenant=tenant, audience="svc-gate", action=dict(operation="root", provider_id="workload", token=tokens["svc-other"], scopes=["read"], resources=["sandbox-release"]))
            assert client.post(endpoints["svc-warden"]+"/v1/identity", json=invalid_root).status_code == 403
            invalid_root["action"]["token"] = tokens["svc-harness"]+"x"
            assert client.post(endpoints["svc-warden"]+"/v1/identity", json=invalid_root).status_code == 403

            chain = issue("svc-gate", ["read", "evaluate"], ["sandbox-release"])
            request = dict(schema_version=1, profile="decision-json-v1", tenant=tenant, operation_id="network-ref01",
                           principal_digest=sha(chain[0].encode()), target_id="sandbox-release", environment="test",
                           capability_id=operation["capability_id"], manifest_digest=manifest_digest, policy_digest=policy_digest,
                           activation_epoch=1, mode="enforce", parameters=dict(artifact_digest=artifact), attachments=[])
            context = ssl.create_default_context(cafile=str(directory / "ca.pem"))
            context.load_cert_chain(*[str(p) for p in d["identities"]["svc-harness"][:2]])
            transport = HttpsTransport(endpoints["svc-gate"], context, lambda: chain)
            harness = Client(transport)
            proposal = Proposal.parse(canonical(request))
            assert harness.submit(proposal) == Outcome.DECISION_ONLY_ALLOW
            assert json.loads(transport.replay(tenant, proposal.operation_id))["outcome"] == "decision-only-allow"
            faults["lose_archive_ack"] = True
            lost_request = dict(request, operation_id="lost-ack")
            lost_proposal = Proposal.parse(canonical(lost_request))
            with pytest.raises(Unresolved):
                harness.submit(lost_proposal)
            assert not faults["lose_archive_ack"], "fault must occur after the real Server archive commit"
            stop("svc-gate")
            # Missing evaluator proves recovery cannot silently evaluate again.
            configs["svc-gate"]["evaluator"] = dict(engine, executable=str(directory / "absent-opa.exe"))
            start("svc-gate")
            chain = issue("svc-gate", ["read", "evaluate"], ["sandbox-release"])
            assert harness.lookup(lost_proposal) == Outcome.DECISION_ONLY_ALLOW
            assert harness.submit(lost_proposal) == Outcome.DECISION_ONLY_ALLOW
            assert harness.lookup(proposal) == Outcome.DECISION_ONLY_ALLOW
            assert harness.submit(proposal) == Outcome.DECISION_ONLY_ALLOW
            changed = dict(request, parameters=dict(artifact_digest=sha(b"substitution")))
            assert client.post(endpoints["svc-gate"]+"/v1/decisions", json=dict(tenant=tenant, chain=chain,
                               action=dict(operation="submit", request=canonical(changed).decode()))).status_code == 409
            other_chain = issue("svc-gate", ["read"], ["sandbox-release"], peer="svc-other")
            with d["http"](d["identities"]["svc-other"]) as other:
                assert other.post(endpoints["svc-gate"]+"/v1/decisions", json=dict(tenant=tenant, chain=other_chain,
                                  action=dict(operation="lookup", operation_id=proposal.operation_id))).status_code == 403
            # New operations must refuse absent authoritative lineage; client values cannot repair it.
            stop("svc-gate")
            configs["svc-gate"]["evaluator"] = engine
            start("svc-gate")
            chain = issue("svc-gate", ["read", "evaluate"], ["sandbox-release"])
            snapshot["evidence"] = []
            install("missing-lineage")
            request.update(operation_id="missing-lineage", principal_digest=sha(chain[0].encode()))
            refusal = client.post(endpoints["svc-gate"]+"/v1/decisions", json=dict(tenant=tenant, chain=chain,
                                  action=dict(operation="submit", request=canonical(request).decode())))
            assert refusal.status_code == 200 and refusal.json()["reasons"] == ["lineage-unavailable"]
            # A fresh authority revocation takes effect without restarting receiving services.
            bindings["identity:svc-gate"]["keys"]["warden"]["decision"] = False
            install("revoke")
            assert client.post(endpoints["svc-gate"]+"/v1/decisions", json=dict(tenant=tenant, chain=chain,
                               action=dict(operation="lookup", operation_id=proposal.operation_id))).status_code == 403
            # Checkpoint loss makes all dependent admissions unavailable, with no cached fallback.
            checkpoint = d["checkpoint"].read_bytes()
            d["checkpoint"].write_bytes(b"")
            try:
                assert client.post(endpoints["svc-registry"]+"/v1/candidates", json=candidate_body).status_code == 503
                assert client.post(endpoints["svc-warden"]+"/v1/identity", json=invalid_root).status_code == 503
            finally:
                d["checkpoint"].write_bytes(checkpoint)
        finally:
            client.close()
            for name in list(processes):
                stop(name)
            boundary.shutdown()
            boundary.server_close()
            boundary_thread.join(timeout=5)
            upstream.close()
