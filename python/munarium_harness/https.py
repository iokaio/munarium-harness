# SPDX-License-Identifier: Apache-2.0
"""Single-attempt mutual TLS transport for the decision service."""
import http.client
import json
import ssl
from urllib.parse import urlsplit

from .decision import ProtocolError, Unresolved


class HttpsTransport:
    """Caller owns the verified TLS context and supplies fresh signed evidence.

    No redirects, proxies, implicit retries or execution methods are available.
    The evidence callback may refresh assertions without changing proposal bytes.
    """

    def __init__(self, endpoint, context, chain, timeout=20):
        url = urlsplit(endpoint)
        if (url.scheme != "https" or not url.hostname or url.username or url.password
                or url.path not in ("", "/") or url.query or url.fragment
                or not isinstance(context, ssl.SSLContext)
                or context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname
                or timeout <= 0):
            raise ProtocolError("HTTPS configuration")
        self.host, self.port = url.hostname, url.port or 443
        self.context, self.chain, self.timeout = context, chain, timeout

    def _call(self, tenant, action):
        connection = http.client.HTTPSConnection(
            self.host, self.port, context=self.context, timeout=self.timeout)
        try:
            raw = json.dumps(dict(tenant=tenant, chain=self.chain(), action=action),
                             separators=(",", ":")).encode()
            connection.request("POST", "/v1/decisions", body=raw,
                               headers={"Content-Type": "application/json"})
            response = connection.getresponse()
            body = response.read(65537)
            if len(body) > 65536 or response.status != 200:
                raise Unresolved("decision unavailable; use original operation lookup")
            return body
        except (OSError, http.client.HTTPException):
            raise Unresolved("decision unavailable; use original operation lookup") from None
        finally:
            connection.close()

    def submit(self, proposal):
        return self._call(proposal.tenant, dict(operation="submit", request=proposal.raw.decode()))

    def lookup(self, tenant, operation_id):
        return self._call(tenant, dict(operation="lookup", operation_id=operation_id))

    def replay(self, tenant, operation_id):
        """Read and reevaluate the archived inputs; never writes or dispatches."""
        return self._call(tenant, dict(operation="replay", operation_id=operation_id))
