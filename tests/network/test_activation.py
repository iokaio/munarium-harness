# SPDX-License-Identifier: Apache-2.0
"""PYTEST_DONT_REWRITE
Actual five-service activation with one lost response after each durable phase.
No evaluator, connector, grant or target effect is exercised by this profile.
"""
from contextlib import ExitStack
import copy
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
import os
import re
from pathlib import Path
import socket
import ssl
import subprocess
from threading import Thread
import time

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519


def test_real_activation_barrier():
    workspace = os.environ.get("STAGE2_WORKSPACE")
    if not workspace:
        pytest.skip("explicit Stage 2 workspace required")
    assert os.environ.get("MUNARIUM_PLATFORM_TEST_DATABASE_URL"), "isolated Server PostgreSQL required"
    assert os.environ.get("STAGE2_GATE_DATABASE_URL"), "isolated Gate PostgreSQL required"
    workspace = Path(workspace)
    spec = importlib.util.spec_from_file_location("platform_fixture", workspace / "munarium/clients/python/tests/test_platform_authority_live.py")
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    from munarium_client import ApiRequest
    canonical, digest, b64 = fixture.canonical, fixture.digest, fixture.b64
    names = ("svc-council", "svc-registry", "svc-gate", "svc-warden")
    peers = names + ("proposer", "human", "outsider")
    with fixture.deployment("postgres", peers) as d, ExitStack() as stack:
        tenant, directory = d["tenant"], d["directory"]
        identities = dict(d["identities"], **{"svc-server": d["server_identity"]})
        ports = {name: fixture.port() for name in names}
        endpoints = {name: f"https://127.0.0.1:{port}" for name, port in ports.items()}
        endpoints["svc-server"] = d["endpoint"]
        scope = dict(domain="fixture-domain", deployment="stage1-live", tenant=tenant, cell="cell-a")
        now = int(time.time())
        issuer, provider, publisher = (ed25519.Ed25519PrivateKey.generate() for _ in range(3))
        (directory / "issuer.key").write_bytes(issuer.private_bytes_raw())

        def sign(key, header, payload):
            message = b64(canonical(header)) + "." + b64(canonical(payload))
            return message + "." + b64(key.sign(message.encode()))

        trust = json.loads((workspace / "munarium-registry/contracts/registry-v2/trust.json").read_bytes())
        trust["tenants"] = trust["tenants"][:1]
        catalog = trust["tenants"][0]
        catalog["id"] = tenant
        catalog["publishers"] = catalog["publishers"][:1]
        catalog["publishers"][0]["public_key"] = b64(publisher.public_key().public_bytes_raw())
        vectors = json.loads((workspace / "munarium-registry/contracts/registry-v2/signed-vectors.json").read_bytes())
        manifest = json.loads(vectors["cases"][0]["payload"])
        manifest["tenant"] = tenant
        envelope = sign(publisher, dict(alg="Ed25519", kid="key-1", typ="munarium-manifest+jws"), manifest)
        manifest_digest = digest("munarium:manifest:v2", manifest)
        policy_bytes = {"purpose": "activation-composition-only"}
        policy_digest = digest("munarium:decision-policy:v1", policy_bytes)
        records = json.loads((workspace / "munarium-council/contracts/stage2-v1/vectors.json").read_bytes())["records"]
        transition = records["activation"]
        transition["scope"] = transition["transition"]["scope"] = transition["ratification"]["scope"] = scope
        transition.update(not_before=now-10, expires_at=now+600,
            artifacts=[dict(kind="manifest", digest=manifest_digest), dict(kind="policy", digest=policy_digest)])
        transition["artifact_set_digest"] = digest("munarium:stage2:artifact-set:v1", {"artifacts": transition["artifacts"]})
        readers = list(names) + ["svc-server", "human"]
        initial = dict(scope=scope, coordinator="svc-council", readers=readers,
            initial_epoch=1, initial_artifact_set_digest=transition["prior_artifact_set_digest"])
        bindings = {"stage2:"+p: copy.deepcopy(initial) for p in ("svc-server", "svc-registry", "svc-gate", "svc-warden")}
        bindings["stage2:svc-server"].update(stream_id="server-activation", council_endpoint=endpoints["svc-council"],
            gate_endpoint=endpoints["svc-gate"], registry_endpoint=endpoints["svc-registry"])
        bindings["stage2:svc-registry"]["artifacts"] = [
            dict(a, profile="stage2-single-cell-v1", retired=False, **({"policy": policy_bytes} if a["kind"] == "policy" else {}))
            for a in transition["artifacts"]]
        bindings["stage2:svc-council"] = dict(scope=scope, humans={"human": dict(principal=dict(scope=scope, kind="human", subject="approver"), eligibility_revision=1)},
            proposers={"proposer": dict(scope=scope, kind="service", subject="proposer")}, readers=readers, stream="council-approvals", generation=1)
        bindings["action-records:svc-server"] = dict(schema_version=1, profile="stage2-single-cell-v1", scope=scope,
            streams=[dict(stream_id="server-activation", producer="server", service="svc-server", generation=1, kinds=["activation-applied"]),
                     dict(stream_id="council-approvals", producer="council", service="svc-council", generation=1, kinds=["approval-recorded"])], readers=["svc-gate"], recovery=[])
        restriction = dict(digest=policy_digest, nbf=now-10, exp=now+900, scopes=["read", "propose"], resources=["registry:"+tenant])
        bindings["identity:svc-registry"] = dict(keys={"warden": dict(public_key=b64(issuer.public_key().public_bytes_raw()), issuer="warden", decision=True)},
            peers={"svc-gate": dict(task=restriction, policy=restriction, maximum_depth=0)}, registrations=[])
        bindings["registry"] = trust
        bindings["warden"] = dict(providers={"workload": dict(issuer="fixture-provider", audience="warden-admission", key_id="provider",
            public_key=b64(provider.public_key().public_bytes_raw()), subjects={"svc-gate": "service"})}, bindings=[dict(
            schema_version=1, binding_id="gate", deployment="stage1-live", tenant=tenant, provider_issuer="fixture-provider", provider_subject="svc-gate",
            origin_kind="service", origin="svc-gate", peer_service="svc-gate", audiences=["svc-registry"], scopes=["read", "propose"],
            resources=["registry:"+tenant], nbf=now-10, exp=now+900)])
        governance = dict(schema_version=1, bindings=bindings, retire_bootstrap=False, successor_keys={})
        path = {"tenant": tenant}
        state = d["api"].get_platform_authority(ApiRequest(path=path)).json()
        d["api"].transition_platform_authority(ApiRequest.json(fixture.signed(d, state, governance, "activation-setup"), path=path))

        clients = {p: stack.enter_context(d["http"](identities[p])) for p in peers}
        for client in clients.values():
            client.timeout = httpx.Timeout(30)
        faults = {"phase": None, "hits": [], "statuses": []}
        upstream = clients["svc-council"]

        class Boundary(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def forward(self):
                if hashlib.sha256(self.connection.getpeercert(binary_form=True)).hexdigest() != identities["svc-council"][2]:
                    self.send_error(403)
                    return
                length = int(self.headers.get("Content-Length", "0"))
                if length > 131072:
                    self.send_error(413)
                    return
                raw = self.rfile.read(length)
                owner, route = "svc-server", self.path
                for candidate in names:
                    prefix = "/"+candidate
                    if route.startswith(prefix+"/"):
                        owner, route = candidate, route[len(prefix):]
                        break
                response = upstream.request(self.command, endpoints[owner]+route, content=raw, headers={"Content-Type": "application/json"})
                operation = json.loads(raw)["action"]["operation"] if raw else "read"
                phase = owner+":"+operation
                if self.command == "POST":
                    faults["statuses"].append((phase, response.status_code))
                    if owner == "svc-server" and response.status_code == 500:
                        faults["statuses"].extend(re.findall(r"platform activation dependency[^\r\n\x1b]*", d["server_log"].read_text(errors="replace")))
                if response.status_code == 200 and phase == faults["phase"]:
                    faults["hits"].append(phase)
                    faults["phase"] = None
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

        boundary = ThreadingHTTPServer(("127.0.0.1", 0), Boundary)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(*map(str, identities["outsider"][:2]))
        ctx.load_verify_locations(cafile=str(directory / "ca.pem"))
        ctx.verify_mode = ssl.CERT_REQUIRED
        boundary.socket = ctx.wrap_socket(boundary.socket, server_side=True)
        thread = Thread(target=boundary.serve_forever, daemon=True)
        thread.start()
        stack.callback(thread.join, 5)
        stack.callback(boundary.server_close)
        stack.callback(boundary.shutdown)
        proxy = f"https://127.0.0.1:{boundary.server_port}"

        def tls(name):
            cert, key, _ = identities[name]
            return dict(listen=f"127.0.0.1:{ports[name]}", certificate_file=str(cert), private_key_file=str(key), ca_file=str(directory / "ca.pem"),
                peers={cert[2]: dict(service=p, tenants=[tenant]) for p, cert in identities.items()})

        (directory / "gate-url").write_text(os.environ["STAGE2_GATE_DATABASE_URL"])
        configs = {p: dict(tls=tls(p), server_endpoint=d["endpoint"], deployment="stage1-live") for p in names}
        configs["svc-council"].update(database=str(directory / "council.sqlite"), service="svc-council", server_service="svc-server", provider_id="unused",
            provider_token_file=str(directory / "unused-token"), server_endpoint=proxy,
            gate_endpoint=proxy+"/svc-gate", registry_endpoint=proxy+"/svc-registry", warden_endpoint=proxy+"/svc-warden")
        configs["svc-registry"].update(service="svc-registry", database_directory=str(directory), capacity=32,
            council_endpoint=endpoints["svc-council"], gate_endpoint=endpoints["svc-gate"])
        configs["svc-warden"].update(signing_key_file=str(directory / "issuer.key"), key_id="warden",
            activation=dict(database=str(directory / "warden.sqlite"), service="svc-warden", council_endpoint=endpoints["svc-council"],
                gate_endpoint=endpoints["svc-gate"], registry_endpoint=endpoints["svc-registry"]))
        configs["svc-gate"].update(service="svc-gate", server_service="svc-server", registry_service="svc-registry", provider_id="unused",
            provider_token_file=str(directory / "unused-token"), journal=str(directory / "gate.sqlite"), registry_endpoint=endpoints["svc-registry"],
            warden_endpoint=endpoints["svc-warden"], evaluator=dict(python="unused", worker="unused", executable="unused", worker_digest="unused", executable_digest="unused", version="unused", capabilities={}),
            activation=dict(database_url_file=str(directory / "gate-url"), council_endpoint=endpoints["svc-council"]))
        processes = {}

        def stop(name):
            process = processes.pop(name, None)
            if process:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)

        def start(name):
            config = directory / (name+".json")
            config.write_bytes(canonical(configs[name]))
            repo = "munarium-"+name.removeprefix("svc-")
            binary = workspace / repo / "target/debug" / (repo+(".exe" if os.name == "nt" else ""))
            env = {k: os.environ[k] for k in ("PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP") if k in os.environ}
            processes[name] = subprocess.Popen([str(binary), str(config)], env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            deadline = time.monotonic()+15
            route = {"svc-council": "/v1/transitions", "svc-gate": "/v1/actions", "svc-registry": "/v1/activation", "svc-warden": "/v1/activation"}[name]
            while time.monotonic() < deadline:
                assert processes[name].poll() is None, name+" exited during startup"
                try:
                    if clients["human"].get(endpoints[name]+route, timeout=1).status_code == 405:
                        return
                except httpx.TransportError:
                    pass
                time.sleep(.05)
            pytest.fail(name+" did not start")

        for name in names:
            stack.callback(stop, name)
            start(name)

        def call(owner, operation, peer="human", **fields):
            route = "/v1/transitions" if owner == "svc-council" else "/v1/actions" if owner == "svc-gate" else f"/v1/platform/{tenant}/activation" if owner == "svc-server" else "/v1/activation"
            return clients[peer].post(endpoints[owner]+route, json=dict(tenant=tenant, action=dict(operation=operation, **fields)))

        token = sign(provider, dict(alg="EdDSA", kid="provider", typ="at+jwt"), dict(iss="fixture-provider", sub="svc-gate", aud="warden-admission", iat=now-5, nbf=now-5, exp=now+900))
        issued = clients["svc-gate"].post(endpoints["svc-warden"]+"/v1/identity", json=dict(tenant=tenant, audience="svc-registry", action=dict(
            operation="root", provider_id="workload", token=token, scopes=["read", "propose"], resources=["registry:"+tenant])))
        assert issued.status_code == 200, "real Warden root issuance"
        root = issued.json()
        time.sleep(max(0, root["usable_at"]-time.time()+.1))
        candidate = clients["svc-gate"].post(endpoints["svc-registry"]+"/v1/candidates", json=dict(tenant=tenant, chain=root["chain"], action=dict(operation="submit", envelope=envelope)))
        assert candidate.status_code == 200, "real signed Registry candidate admission"
        assert candidate.json()["active"] is False
        transition_id = transition["transition"]["id"]
        assert call("svc-council", "propose", "proposer", transition=canonical(transition).decode()).status_code == 200
        assert call("svc-council", "ratify", "proposer", transition_id=transition_id).status_code == 403
        assert call("svc-council", "ratify", transition_id=transition_id).status_code == 200
        assert call("svc-server", "apply", "svc-gate", transition=canonical(transition).decode()).status_code == 403
        with pytest.raises(httpx.TransportError):
            call("svc-server", "head", "outsider")

        receipts = {}
        phases = [("svc-gate", "pause"), ("svc-registry", "apply"), ("svc-server", "apply"), ("svc-warden", "apply"), ("svc-gate", "apply-activation"), ("svc-gate", "resume")]
        for owner, operation in phases:
            phase = owner+":"+operation
            faults["phase"] = phase
            result = call("svc-council", "advance", transition_id=transition_id)
            assert result.status_code == 503, "lost committed response must remain incomplete"
            assert faults["phase"] is None and faults["hits"][-1] == phase, f"expected committed {phase}; statuses {faults['statuses']}"
            head = call("svc-gate", "activation-head", "svc-council").json()
            assert head["paused"] is (operation != "resume")
            assert head["execution_enabled"] is False
            if operation in ("apply", "apply-activation"):
                lookup = "activation-lookup" if owner == "svc-gate" else "lookup"
                receipts[owner] = call(owner, lookup, "svc-council", transition_id=transition_id).json()
                assert receipts[owner]["participant"] == owner.removeprefix("svc-")
            stop("svc-council")
            if owner == "svc-server":
                d["restart"]()
            elif owner != "svc-council":
                stop(owner)
                start(owner)
            start("svc-council")
        completed = call("svc-council", "advance", transition_id=transition_id)
        assert completed.status_code == 200, "same transition must recover every lost response"
        assert completed.json()["resumed"] is True
        assert len(completed.json()["receipts"]) == 4
        for owner in ("svc-registry", "svc-server", "svc-warden", "svc-gate"):
            head = call(owner, "activation-head" if owner == "svc-gate" else "head", "svc-council").json()
            assert head["epoch"] == transition["successor_epoch"]
            assert head["artifact_set_digest"] == transition["artifact_set_digest"]
            receipt = call(owner, "activation-lookup" if owner == "svc-gate" else "lookup", "svc-council", transition_id=transition_id).json()
            assert receipt == receipts[owner]
        assert len(faults["hits"]) == 6
