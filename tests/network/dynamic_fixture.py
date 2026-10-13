# SPDX-License-Identifier: Apache-2.0
"""Native dynamic inputs for real owner services; no synthetic service answers."""
import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import sys

import httpx

PIN = "sha256:668506eb17a2eaa1fce6cc0d1f42ef85125d4ac5bda5fc74d1152d0c77145031"


class Dynamic:
    def __init__(self, fixture, workspace, catalog, manifest, records):
        self.fixture = fixture
        executable = Path(os.environ["OPA_LINUX_EXECUTABLE"]).resolve(strict=True)
        if "sha256:" + hashlib.sha256(executable.read_bytes()).hexdigest() != PIN:
            raise ValueError("native evaluator pin")
        if not Path(os.environ["MUNARIUM_OPA_CGROUP_ROOT"], "cgroup.controllers").is_file():
            raise ValueError("delegated Linux evaluator subtree required")
        scripts = workspace / "munarium-gate/scripts"
        spec = importlib.util.spec_from_file_location("gate_caps", scripts / "check_opa.py")
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        caps = helper.capabilities(executable)
        worker = (scripts / "opa_worker_linux.py").resolve(strict=True)
        self.evaluator = dict(python=sys.executable, worker=str(worker), executable=str(executable),
            worker_digest="sha256:" + hashlib.sha256(worker.read_bytes()).hexdigest(), executable_digest=PIN,
            version="1.21.1", capabilities=caps)
        schema = dict(type="object", additionalProperties=False,
            properties=dict(artifact_digest=dict(type="string", minLength=71, maxLength=71),
                            destination=dict(type="string", minLength=1, maxLength=64)),
            required=["artifact_digest", "destination"])
        schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
        schema_digest = fixture.digest("munarium:capability-schema:v1", schema)
        target = records["request"]["intent"]["target"]["id"]
        manifest.update(id="publish-approved", capability_id="release", operation_id="release.publish_approved_artifact",
            environment="disposable", target_id=target, credential_audience=target, base_consequence="C2",
            effect="external-effect", idempotency="operation-key", compensation="none", modifiers=[],
            required_inputs=[], required_obligations=["distinct-approval"], parameter_schema_digest=schema_digest)
        operation = {key: manifest[key] for key in ("capability_id", "target_id", "environment", "operation_id",
            "credential_audience", "parameter_schema_digest", "result_schema_digest")}
        catalog["operations"] = [operation]
        catalog["publishers"][0]["operations"] = [copy.deepcopy(operation)]
        catalog["schemas"].append(dict(digest=schema_digest, canonical=fixture.canonical(schema).decode()))
        self.policy = dict(profile="stage2-release-evaluation-v1", engine="opa", engine_version="1.21.1", engine_digest=PIN,
            worker_digest=self.evaluator["worker_digest"], capabilities_digest=fixture.digest("munarium:opa-capabilities:v1", caps),
            parameter_schema=schema, rule_obligations=dict(permit="distinct-approval"),
            code='package munarium\nimport rego.v1\ndecision := {"allow": input.evidence.tests_passed, "forbid": false, "rules": ["permit"], "predicates": {}, "diagnostics": []}')
        self.profile = fixture.digest("munarium:stage2:evaluator-profile:v1", dict(engine="opa", version="1.21.1",
            binary=PIN, worker=self.evaluator["worker_digest"], capabilities=self.policy["capabilities_digest"]))

    def enroll(self, execution, bindings, now):
        requests = execution.requests
        for name in ("native-denied", "stale-evidence", "lost-proposal", "wrong-archive"):
            requests[name] = copy.deepcopy(requests["publish-one"])
            requests[name]["operation"]["id"] = name
            requests[name]["attempt"]["id"] = "attempt-" + name
        for name, request in requests.items():
            request["intent"]["parameter_schema_digest"] = self.fixture.digest("munarium:capability-schema:v1", self.policy["parameter_schema"])
            request["context"]["evaluator_profile_digest"] = self.profile
            source = self.fixture.canonical({"artifact_digest": request["intent"]["parameters"]["artifact_digest"],
                                             "tests.passed": name != "native-denied"})
            evidence = request["context"]["evidence"][0]
            evidence.update(content_digest="sha256:" + hashlib.sha256(source).hexdigest(), derivation="test-result",
                derivation_version=1, field="tests.passed")
            evidence["source"]["id"] = "test-result-" + name
            evidence["verifier"]["id"] = "test-result-verifier"
            if name == "stale-evidence":
                evidence["expires_at"] = now - 1
            slot = bindings["execution:svc-gate"]["requests"].setdefault(name, dict(proposer="proposer", requester_chain=[request["intent"]["actor"]]))
            slot.update(request=request, evaluation=dict(evidence_source=source.decode()))

    def exercise(self, execution, boundary, gate, call, observe, stop, start, faults, proxy):
        assert boundary is not None, "dynamic effect profile requires the actual agent boundary"
        parameters = execution.requests["publish-one"]["intent"]["parameters"]
        denied = boundary.propose(execution.scope["tenant"], "native-denied", parameters)
        assert denied["status"] == 200 and denied["value"]["decision"]["outcome"] == "denied"
        assert denied["value"]["decision"]["obligations"] == []
        assert call("svc-council", "/v1/approvals", "approve", peer="human", id="deny-approval",
                    operation_id="native-denied", attempt_id="attempt-native-denied").status_code == 403
        for name, proposed in [("stale-evidence", parameters),
                               ("publish-one", parameters | {"artifact_digest": "sha256:" + "0" * 64}),
                               ("publish-one", parameters | {"context": {}})]:
            assert boundary.propose(execution.scope["tenant"], name, proposed)["status"] != 200
        assert boundary.propose("foreign-tenant", "publish-one", parameters)["status"] != 200
        assert gate("propose", peer="human", operation_id="publish-one", attempt_id="attempt-publish-one", parameters=parameters).status_code == 403
        assert gate("prepare", peer="proposer", operation_id="publish-one", attempt_id="attempt-publish-one").status_code == 403
        # Real Server commits archive custody; Gate refuses a substituted receipt,
        # and an exact agent retry recovers without modifying the Server history.
        faults["archive_wrong"] = True
        assert boundary.propose(execution.scope["tenant"], "wrong-archive", parameters)["status"] == 403
        faults["archive_wrong"] = False
        archived = boundary.propose(execution.scope["tenant"], "wrong-archive", parameters)
        assert archived["status"] == 200
        # Drop a successful service response after immutable source persistence.
        faults["phase"] = "svc-gate:propose"
        try:
            execution.proposer_client.post(proxy + "/svc-gate/v1/actions", json=dict(tenant=execution.scope["tenant"],
                action=dict(operation="propose", operation_id="lost-proposal", attempt_id="attempt-lost-proposal", parameters=parameters)))
        except httpx.TransportError:
            pass
        else:
            raise AssertionError("successful proposal reply was not lost")
        assert faults["phase"] is None
        original = gate("source", operation_id="lost-proposal", attempt_id="attempt-lost-proposal").json()
        stop("svc-gate")
        start("svc-gate")
        retry = boundary.propose(execution.scope["tenant"], "lost-proposal", parameters)
        assert retry["status"] == 200 and retry["value"] == original
        assert boundary.propose(execution.scope["tenant"], "lost-proposal", parameters | {"artifact_digest": "sha256:" + "1" * 64})["status"] == 409
        observed = observe()
        assert observed["sends"] == 0 and not observed["effects"], "dynamic refusal/retry controls must not send"
        boundary.record("dynamic-controls", native_deny=True, stale_evidence_refused=True, substituted_parameters_refused=True,
            foreign_identity_refused=True, prepare_bypass_refused=True, wrong_archive_refused=True,
            committed_reply_lost=True, restart_retry_immutable=True, changed_retry_conflict=True, sends=0, effects=0,
            policy_digest=execution.requests["publish-one"]["context"]["policy_digest"],
            manifest_digest=execution.requests["publish-one"]["context"]["manifest_digest"],
            evaluator_profile_digest=self.profile, capabilities_digest=self.policy["capabilities_digest"])
