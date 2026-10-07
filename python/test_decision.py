# SPDX-License-Identifier: Apache-2.0
import hashlib
import json
from pathlib import Path
import unittest
from munarium_harness.decision import Client, Outcome, Proposal, ProtocolError, Unresolved, canonical, request_digest

ROOT = Path(__file__).resolve().parents[1]


class DecisionTests(unittest.TestCase):
    def test_unchanged_canonical_vectors(self):
        vectors = json.loads((ROOT / "contracts/stage1/decision-json-v1-vectors.json").read_text(encoding="utf-8"))
        for case in vectors["cases"]:
            with self.subTest(case=case["id"]):
                if case["result"] == "reject":
                    with self.assertRaises(ProtocolError):
                        canonical(case["input"].encode())
                else:
                    self.assertEqual(canonical(case["input"].encode()).decode(), case["canonical"])
                    self.assertEqual(request_digest(case["input"].encode()), case["digest"])

    def test_contract_pins(self):
        root = ROOT / "contracts/stage1"
        lock = json.loads((root / "vendor-lock.json").read_text(encoding="utf-8"))
        for name, pin in lock["files"].items():
            self.assertEqual(hashlib.sha256((root / name).read_bytes().replace(b"\r\n", b"\n")).hexdigest(), pin["sha256"])

    def test_recovery_never_resubmits_and_outcomes_stay_distinct(self):
        examples = json.loads((ROOT / "contracts/stage1/record-vectors.json").read_text(encoding="utf-8"))["examples"]
        proposal = Proposal.parse(json.dumps(examples["request"]).encode())
        class Wire:
            submits = 0
            outcome = "unresolved"
            def submit(self, _):
                self.submits += 1
                raise Unresolved()
            def lookup(self, tenant, operation_id):
                return json.dumps(dict(tenant=tenant, operation_id=operation_id,
                                       request_digest=proposal.digest, outcome=self.outcome)).encode()
        wire = Wire()
        client = Client(wire)
        with self.assertRaises(Unresolved):
            client.submit(proposal)
        for outcome in Outcome:
            wire.outcome = outcome.value
            self.assertEqual(client.lookup(proposal), outcome)
        self.assertEqual(wire.submits, 1)
        wire.outcome = "retryable"
        with self.assertRaises(ProtocolError):
            client.lookup(proposal)

    def test_ambiguity_and_bounds(self):
        for raw in [b'{"a":1,"a":2}', b'{"a":-0}', b'{"a":1e0}', b'\xef\xbb\xbf{}',
                    b'{"a":"\xff"}', b'{"a":"\\ud800"}', b'{"a":' + b'['*16 + b'0' + b']'*16 + b'}']:
            with self.assertRaises(ProtocolError):
                canonical(raw)
        self.assertEqual(len(canonical(b'{"a":"' + b'x'*65528 + b'"}')), 65536)


if __name__ == "__main__":
    unittest.main()
