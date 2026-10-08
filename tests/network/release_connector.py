# SPDX-License-Identifier: Apache-2.0
"""Disposable connector process. No send retry, no credential output."""
import json
from pathlib import Path
import ssl
import sys
import time

import httpx


def run(path):
    config = json.loads(Path(path).read_bytes())
    context = ssl.create_default_context(cafile=config["ca"])
    context.load_cert_chain(config["certificate"], config["key"])
    common = dict(tenant=config["tenant"])
    operation = config["operation_id"]
    invocation = config["invocation"]
    with httpx.Client(verify=context, trust_env=False, follow_redirects=False, timeout=5) as client:
        def gate(action, **fields):
            return client.post(config["gate"]+"/v1/actions", json=dict(common, action=dict(operation=action, operation_id=operation, **fields)))
        try:
            lookup = gate("claim-lookup")
            lookup.raise_for_status()
            request = lookup.json()["binding"]["request"]
            custody = client.post(config["warden"]+"/v1/custody", json=dict(common,
                action=dict(operation="custody", operation_id=operation, invocation=invocation)))
            custody.raise_for_status()
            credential = custody.content
            if not 0 < len(credential) <= 16384:
                return 2
            final = gate("final-send", invocation=invocation)
            final.raise_for_status()
            admission = final.json()
            if admission.get("send_permitted") is not True or time.time()+2 >= admission["expires_at"]:
                return 2
            if config.get("hold"):
                ready, release = Path(config["hold"]+".ready"), Path(config["hold"]+".release")
                ready.write_text("admitted")
                deadline = time.monotonic()+2
                while not release.exists() and time.monotonic() < deadline:
                    time.sleep(.01)
                if not release.exists():
                    return 2
            # Exactly one call. HTTP clients have no configured retries or redirects.
            result = client.post(config["target"]+"/effect", headers={"Authorization": "Bearer "+credential.decode()},
                json=dict(request=request, admission=admission, lose_reply=config.get("lose_reply", False)))
            result.raise_for_status()
            return 0
        except (httpx.HTTPError, ValueError, KeyError):
            return 2
        finally:
            # The connector's observation is never independent settlement evidence.
            # Failure to record leaves the durable send intent for later investigation.
            try:
                gate("unresolved")
            except httpx.HTTPError:
                pass


if __name__ == "__main__":
    raise SystemExit(run(sys.argv[1]))
