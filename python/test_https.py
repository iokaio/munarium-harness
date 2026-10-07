# SPDX-License-Identifier: Apache-2.0
import json
import ssl
import sys
from pathlib import Path
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
from munarium_harness.decision import Client, Proposal, ProtocolError, Refused, Unresolved
from munarium_harness.https import HttpsTransport


class HttpsTests(unittest.TestCase):
    def test_insecure_configuration_is_refused(self):
        context = ssl.create_default_context()
        for endpoint in ("http://example.test", "https://user@example.test", "https://example.test/path", "https://example.test?token=x"):
            with self.assertRaises(ProtocolError):
                HttpsTransport(endpoint, context, lambda: [])
        context.check_hostname = False
        with self.assertRaises(ProtocolError):
            HttpsTransport("https://example.test", context, lambda: [])

    def test_ambiguous_request_is_sent_once_and_connection_closes(self):
        transport = HttpsTransport("https://example.test", ssl.create_default_context(), lambda: [])
        with patch("http.client.HTTPSConnection") as factory:
            connection = factory.return_value
            connection.getresponse.side_effect = ConnectionResetError()
            with self.assertRaises(Unresolved):
                transport.lookup("tenant", "original")
            self.assertEqual(connection.request.call_count, 1)
            connection.close.assert_called_once()

    def test_bound_recorded_refusal_is_distinct_from_ambiguity(self):
        root = Path(__file__).resolve().parents[1]
        example = json.loads((root / "contracts/stage1/record-vectors.json").read_bytes())["examples"]["request"]
        proposal = Proposal.parse(json.dumps(example).encode())
        class Wire:
            def lookup(self, tenant, operation_id):
                return json.dumps(dict(schema_version=1, tenant=tenant, operation_id=operation_id,
                                       request_digest=proposal.digest, reasons=["lineage-unavailable"])).encode()
        with self.assertRaises(Refused) as refused:
            Client(Wire()).lookup(proposal)
        self.assertEqual(refused.exception.reasons, ("lineage-unavailable",))


if __name__ == "__main__":
    unittest.main()
