# SPDX-License-Identifier: Apache-2.0
"""Prepared release composition using native services, PostgreSQL, OpenBao and a target process."""
import copy
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time

import httpx

BAO = "ghcr.io/openbao/openbao:2.4.4@sha256:01bdba095690b1fe7cc1ec956ca422cfe01fd9a994ea28d9a6a2f84886dc9569"


class Execution:
    def __init__(self, fixture, deployment, workspace, stack, scope, identities, endpoints, records, case):
        self.fixture, self.d, self.workspace, self.stack = fixture, deployment, workspace, stack
        self.scope, self.identities, self.endpoints = scope, identities, endpoints
        self.records = records
        self.directory = deployment["directory"]
        self.requests = {}
        self.case = case

    def bindings(self, bindings, now, manifest_digest, policy_digest):
        self.authority_bindings = bindings
        scope = self.scope
        template = self.records["request"]

        def scoped(value):
            if isinstance(value, dict):
                for key, child in list(value.items()):
                    if key == "scope":
                        value[key] = scope
                    else:
                        scoped(child)
            elif isinstance(value, list):
                for child in value:
                    scoped(child)

        for name in ("publish-one", "lost-admission", "lost-target", "stale-worker"):
            r = copy.deepcopy(template)
            scoped(r)
            r["operation"]["id"] = name
            r["attempt"]["id"] = "attempt-"+name
            r["context"].update(valid_from=now-10, expires_at=now+600, manifest_digest=manifest_digest, policy_digest=policy_digest)
            r["context"]["evaluator_profile_digest"] = self.fixture.digest("munarium:prepared-release:v1", {"profile": "operator-enrolled-disposable-release"})
            for evidence in r["context"]["evidence"]:
                evidence.update(observed_at=now-10, expires_at=now+600)
            if name != "publish-one" and self.case != "admission":
                r["intent"]["target_precondition"] = dict(version=2, content_digest=r["intent"]["parameters"]["artifact_digest"])
            self.requests[name] = r
        bindings["execution:svc-gate"] = dict(scope=scope, council="svc-council", warden="svc-warden", connector="connector",
            readers=["human"], stream="gate-actions", generation=1, recovery=1, requests={name: dict(proposer="proposer", request=r,
                requester_chain=[r["intent"]["actor"]]) for name, r in self.requests.items()})
        bindings["execution:svc-warden"] = dict(scope=scope, gate="svc-gate", connector="connector", stream="warden-grants",
            generation=1, recovery=1, blocked=[], target=template["intent"]["target"] | {"scope": scope})
        bindings["stage2:svc-council"]["humans"]["human"]["principal"]["subject_generation"] = 1
        bindings["stage2:svc-council"]["readers"].append("connector")
        for owner, stream, kinds in [("gate", "gate-actions", ["claim-created", "consumption-reserved", "predispatch", "send-intent", "outcome", "reconciliation"]), ("warden", "warden-grants", ["grant-issued"])]:
            bindings["action-records:svc-server"]["streams"].append(dict(stream_id=stream, producer=owner, service="svc-"+owner, generation=1, kinds=kinds))
        # One workload enrollment per subject, including Council's actual recorder.
        resource = "action-records:"+scope["tenant"]
        restrictions = copy.deepcopy(bindings["identity:svc-server"]["peers"]["svc-gate"])
        bindings["identity:svc-server"]["peers"]["svc-council"] = restrictions
        bindings["warden"]["providers"]["workload"]["subjects"]["svc-council"] = "service"
        bindings["warden"]["bindings"].append(dict(schema_version=1, binding_id="council-record", deployment=scope["deployment"], tenant=scope["tenant"],
            provider_issuer="fixture-provider", provider_subject="svc-council", origin_kind="service", origin="svc-council", peer_service="svc-council",
            audiences=["svc-server"], scopes=["read", "propose"], resources=[resource], nbf=now-10, exp=now+900))

    def configure(self, configs, sign, provider, now):
        for owner in ("svc-gate", "svc-council"):
            path = self.directory / (owner+"-execution-token")
            path.write_text(sign(provider, dict(alg="EdDSA", kid="provider", typ="at+jwt"), dict(iss="fixture-provider", sub=owner, aud="warden-admission", iat=now-5, nbf=now-5, exp=now+900)))
            configs[owner].update(provider_id="workload", provider_token_file=str(path))
        token = secrets.token_hex(24)
        container = subprocess.run(["docker", "run", "-d", "--memory", "256m", "--cpus", "1", "--cap-add", "IPC_LOCK", "-p", "127.0.0.1::8200", "-e", "BAO_DEV_ROOT_TOKEN_ID", BAO, "server", "-dev", "-dev-listen-address=0.0.0.0:8200"], env=dict(os.environ, BAO_DEV_ROOT_TOKEN_ID=token), check=True, capture_output=True, text=True).stdout.strip()
        self.stack.callback(lambda: subprocess.run(["docker", "rm", "-f", "-v", container], check=True, capture_output=True))
        port = subprocess.run(["docker", "port", container, "8200/tcp"], check=True, capture_output=True, text=True).stdout.strip().rsplit(":", 1)[1]
        bao = "http://127.0.0.1:"+port
        with httpx.Client(trust_env=False, timeout=2) as client:
            for _ in range(100):
                try:
                    if client.get(bao+"/v1/sys/health").status_code == 200:
                        break
                except httpx.TransportError:
                    pass
                time.sleep(.1)
            credential = secrets.token_hex(32).encode()
            response = client.post(bao+"/v1/secret/data/release", headers={"X-Vault-Token": token}, json={"data": {"credential": credential.decode()}})
            assert response.status_code == 200, "disposable OpenBao secret installation"
        token_file = self.directory / "bao-token"
        token_file.write_text(token)
        configs["svc-warden"]["broker"] = dict(endpoint=bao+"/v1/secret/data/release", token_file=str(token_file), resource="synthetic-release", loopback_test=True)
        credential_file = self.directory / "target-credential"
        credential_file.write_bytes(credential)
        port = self.fixture.port()
        self.target = f"https://127.0.0.1:{port}"
        configs["svc-gate"]["execution"] = dict(target_endpoint=self.target)
        cert, key, _ = self.identities["target"]
        cfg = dict(port=port, certificate=str(cert), key=str(key), ca=str(self.directory/"ca.pem"), credential_file=str(credential_file),
            database=str(self.directory/"target.sqlite"), initial_digest=self.requests["publish-one"]["intent"]["target_precondition"]["content_digest"],
            target=self.requests["publish-one"]["intent"]["target"], connector=self.identities["connector"][2],
            readers=[self.identities[p][2] for p in ("human", "svc-gate")], recovery_peer=self.identities["human"][2])
        path = self.directory/"target.json"
        path.write_bytes(self.fixture.canonical(cfg))
        self.target_process = subprocess.Popen([sys.executable, str(Path(__file__).with_name("synthetic_target.py")), str(path)], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.stack.callback(self.stop_target)
        with self.d["http"](self.identities["human"]) as client:
            for _ in range(100):
                assert self.target_process.poll() is None, "target startup"
                try:
                    if client.post(self.target+"/observe", json={}).status_code == 200:
                        break
                except httpx.TransportError:
                    pass
                time.sleep(.1)
            else:
                raise AssertionError("target availability")

    def stop_target(self):
        self.target_process.terminate()
        try:
            self.target_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.target_process.kill()
            self.target_process.wait(timeout=5)

    def exercise(self, clients, stop, start, faults, proxy):
        tenant = self.scope["tenant"]

        def call(owner, route, operation, peer="connector", **fields):
            return clients[peer].post(self.endpoints[owner]+route, json=dict(tenant=tenant, action=dict(operation=operation, **fields)))

        def gate(operation, **fields):
            return call("svc-gate", "/v1/actions", operation, **fields)

        def flush():
            for _ in range(20):
                response = gate("action-flush")
                assert response.status_code == 200, "Gate lifecycle delivery: "+response.text
                if response.json()["delivered"] == 0:
                    return
            raise AssertionError("outbox did not drain")

        def ready(name, consume=True):
            response = gate("prepare", peer="proposer", operation_id=name, attempt_id="attempt-"+name)
            assert response.status_code == 200, "prepared request: "+response.text
            approval_id = "approval-"+name
            response = call("svc-council", "/v1/approvals", "approve", peer="human", id=approval_id, operation_id=name, attempt_id="attempt-"+name)
            assert response.status_code == 200, "distinct live approval: "+response.text
            response = call("svc-council", "/v1/approvals", "flush")
            assert response.status_code == 200, "Council audit: "+response.text
            response = gate("claim", operation_id=name, approval_id=approval_id)
            assert response.status_code == 200, "claim: "+response.text
            flush()
            if not consume:
                return
            response = gate("consume", operation_id=name)
            assert response.status_code == 200, "grant/consumption: "+response.text
            flush()

        def connector(name, lose_reply=False, gate_endpoint=None, hold=False):
            cert, key, _ = self.identities["connector"]
            config = dict(certificate=str(cert), key=str(key), ca=str(self.directory/"ca.pem"), tenant=tenant,
                gate=gate_endpoint or self.endpoints["svc-gate"], warden=self.endpoints["svc-warden"], target=self.target,
                operation_id=name, invocation=dict(scope=self.scope, kind="invocation", id="invoke-"+name), lose_reply=lose_reply)
            path = self.directory/(name+"-connector.json")
            if hold:
                config["hold"] = str(self.directory/(name+"-hold"))
            path.write_bytes(self.fixture.canonical(config))
            command = [sys.executable, str(Path(__file__).with_name("release_connector.py")), str(path)]
            if hold:
                child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    deadline = time.monotonic()+15
                    while not Path(config["hold"]+".ready").exists() and time.monotonic() < deadline:
                        assert child.poll() is None, "connector reached final admission"
                        time.sleep(.01)
                    assert Path(config["hold"]+".ready").exists()
                    assert clients["human"].post(self.target+"/floor", json=dict(epoch=2)).status_code == 200
                    Path(config["hold"]+".release").write_text("release")
                    out, err = child.communicate(timeout=10)
                    assert not out and not err
                    return child.returncode
                finally:
                    if child.poll() is None:
                        child.kill()
                        child.communicate(timeout=5)
            result = subprocess.run(command, capture_output=True, timeout=20)
            assert not result.stdout and not result.stderr, "connector must not emit credentials or transport bodies"
            return result.returncode

        def observe():
            response = clients["human"].post(self.target+"/observe", json={})
            assert response.status_code == 200
            return response.json()

        if self.case == "admission":
            ready("publish-one")
            faults["phase"] = "svc-gate:final-send"
            assert connector("publish-one", gate_endpoint=proxy+"/svc-gate") == 2
            assert faults["phase"] is None, "drop the successful final-admission reply after commit"
            assert observe()["sends"] == 0 and not observe()["effects"]
            stop("svc-gate")
            start("svc-gate")
            assert connector("publish-one") == 2
            assert observe()["sends"] == 0, "lost final reply cannot be replaced"
            flush()
            # A worker paused after valid final admission is rejected by a newer target floor.
            ready("lost-target")
            assert connector("lost-target", hold=True) == 2
            observed = observe()
            assert observed["sends"] == 1 and not observed["effects"] and observed["epoch"] == 2
            assert observed["rejections"] == ["recovery-floor"], "target independently records its actual refusal reason"
            ready("lost-admission", consume=False)
            withdrawn = call("svc-council", "/v1/approvals", "withdraw", peer="human", id="approval-lost-target", withdrawal_id="cancel-live")
            assert withdrawn.status_code == 200 and withdrawn.json()["status"] == "withdrawal-too-late"
            withdrawn = call("svc-council", "/v1/approvals", "withdraw", peer="human", id="approval-lost-admission", withdrawal_id="cancel-early")
            assert withdrawn.status_code == 200 and withdrawn.json()["status"] == "withdrawn"
            assert gate("consume", operation_id="lost-admission").status_code != 200
            assert connector("lost-admission") == 2
            assert observe() == observed
            print("execution evidence: final reply lost after durable commit; restart cannot replace permission; live withdrawal prevents custody")
            return

        # The actual proposing identity cannot mint a grant, consume, request custody or mutate target.
        assert gate("consume", peer="proposer", operation_id="publish-one").status_code == 403
        assert call("svc-warden", "/v1/grants", "issue", peer="proposer", operation_id="publish-one").status_code == 403
        assert call("svc-warden", "/v1/custody", "custody", peer="proposer", operation_id="publish-one", invocation={}).status_code == 403
        assert clients["proposer"].post(self.target+"/effect", json={}).status_code == 403
        ready("publish-one")
        # Actual PostgreSQL snapshot containing consumption but predating the target effect.
        from urllib.parse import urlsplit
        parsed = urlsplit(os.environ["STAGE2_GATE_DATABASE_URL"])
        container = os.environ["STAGE2_DATABASE_CONTAINER"]
        database = parsed.path.removeprefix("/")
        snapshot = subprocess.run(["docker", "exec", container, "pg_dump", "-U", parsed.username, "-d", database, "-Fc"], check=True, capture_output=True).stdout
        assert snapshot.startswith(b"PGDMP"), "actual database snapshot"
        assert connector("publish-one") == 0, "one approved synthetic effect"
        first = observe()
        assert first["sends"] == 1 and len(first["effects"]) == 1
        stop("svc-gate")
        start("svc-gate")
        assert connector("publish-one") == 2, "restart cannot recover spent permission"
        assert observe() == first
        flush()
        # A committed target effect with a lost response is observed independently, never resent.
        ready("lost-target")
        assert connector("lost-target", lose_reply=True) == 2
        second = observe()
        assert second["sends"] == 2 and len(second["effects"]) == 2
        assert connector("lost-target", lose_reply=True) == 2
        assert observe() == second
        flush()
        # Pending/uncertain exposure retains the cap even though both workers ended.
        response = gate("prepare", peer="proposer", operation_id="lost-admission", attempt_id="attempt-lost-admission")
        assert response.status_code == 200
        response = call("svc-council", "/v1/approvals", "approve", peer="human", id="approval-lost-admission", operation_id="lost-admission", attempt_id="attempt-lost-admission")
        assert response.status_code == 200
        assert call("svc-council", "/v1/approvals", "flush").status_code == 200
        assert gate("claim", operation_id="lost-admission", approval_id="approval-lost-admission").status_code == 200
        flush()
        assert gate("consume", operation_id="lost-admission").status_code == 403, "unsettled capacity remains charged"
        assert observe() == second
        for name in ("publish-one", "lost-target"):
            receipt = gate("reconcile", peer="human", operation_id=name)
            assert receipt.status_code == 200 and receipt.json()["payload"]["effect_status"] == "completed", "independent target reconciliation"
            assert gate("reconcile", peer="human", operation_id=name).json() == receipt.json(), "settlement retry retains original event"
        flush()
        # Same-hour retention and rollover settlement are separately exercised with bounded clocks in Gate's PostgreSQL tests.
        # Restore into a NEW owned database; never overwrite the original store or target.
        restored = "stage2_restore_"+secrets.token_hex(6)
        subprocess.run(["docker", "exec", container, "createdb", "-U", parsed.username, restored], check=True, capture_output=True)
        self.stack.callback(lambda: subprocess.run(["docker", "exec", container, "dropdb", "--force", "-U", parsed.username, restored], check=True, capture_output=True))
        subprocess.run(["docker", "exec", "-i", container, "pg_restore", "--exit-on-error", "-U", parsed.username, "-d", restored], input=snapshot, check=True, capture_output=True)
        assert clients["human"].post(self.target+"/floor", json=dict(epoch=2)).status_code == 200
        from munarium_client import ApiRequest
        self.authority_bindings["execution:svc-gate"]["recovery"] = 2
        self.authority_bindings["execution:svc-warden"]["recovery"] = 2
        state = self.d["api"].get_platform_authority(ApiRequest(path={"tenant": tenant})).json()
        governance = dict(schema_version=1, bindings=self.authority_bindings, retire_bootstrap=False, successor_keys={})
        self.d["api"].transition_platform_authority(ApiRequest.json(self.fixture.signed(self.d, state, governance, "restore-quarantine"), path={"tenant": tenant}))
        stop("svc-gate")
        (self.directory/"gate-url").write_text(os.environ["STAGE2_GATE_DATABASE_URL"].rsplit("/", 1)[0]+"/"+restored)
        start("svc-gate")
        assert gate("consume", operation_id="publish-one").status_code == 403
        assert gate("final-send", operation_id="publish-one", invocation=dict(scope=self.scope, kind="invocation", id="restored-invocation")).status_code == 403
        assert connector("publish-one") == 2
        restored_observation = observe()
        assert restored_observation["effects"] == second["effects"] and restored_observation["sends"] == second["sends"]
        assert restored_observation["epoch"] == 2
        stop("svc-gate")
        print("execution evidence: live approval, grant, OpenBao custody, one-shot send, lost target reply, restart, independent effects and retained capacity passed")
