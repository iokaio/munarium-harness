# SPDX-License-Identifier: Apache-2.0
"""Diagnostics must retain failure boundaries without response or credential bytes."""
from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import httpx

spec = importlib.util.spec_from_file_location("release_connector", Path(__file__).resolve().parents[1] / "tests/network/release_connector.py")
connector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(connector)


class Evidence(unittest.TestCase):
    def test_final_refusal_records_only_sanitized_boundary(self):
        secret = "fictional-credential-never-in-evidence"

        class Client:
            def __enter__(self): return self
            def __exit__(self, *_args): pass

            def post(self, url, **fields):
                action = fields["json"]["action"]["operation"]
                request = httpx.Request("POST", url)
                if action == "claim-lookup":
                    return httpx.Response(200, json={"binding": {"request": {}}}, request=request)
                if action == "custody":
                    return httpx.Response(200, content=secret.encode(), request=request)
                if action == "final-send":
                    return httpx.Response(403, json={"error": "Refused", "private": secret}, request=request)
                return httpx.Response(200, json={}, request=request)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "connector.json"
            evidence = Path(directory) / "observations.jsonl"
            path.write_text(json.dumps(dict(ca="synthetic", certificate="synthetic", key="synthetic", tenant="fictional",
                gate="https://example.test", warden="https://example.test", operation_id="operation", invocation={}, case="effects")))
            output = io.StringIO()
            with patch.dict(os.environ, STAGE2_AGENT_EVIDENCE_FILE=str(evidence)), patch.object(connector.ssl, "create_default_context"), \
                    patch.object(connector.httpx, "Client", return_value=Client()), redirect_stdout(output), redirect_stderr(output):
                self.assertEqual(connector.run(path), 2)
            self.assertEqual(output.getvalue(), "")
            raw = evidence.read_text()
            self.assertNotIn(secret, raw)
            facts = json.loads(raw.splitlines()[-1])
            self.assertEqual((facts["step"], facts["status"], facts["reason"]), ("final-send", 403, "Refused"))
            self.assertEqual(set(facts), {"case", "phase", "operation", "step", "elapsed_ms", "result", "status", "reason"})


if __name__ == "__main__":
    unittest.main()
