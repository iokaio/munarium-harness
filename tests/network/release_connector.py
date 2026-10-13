# SPDX-License-Identifier: Apache-2.0
"""Disposable connector process. No send retry, no credential output."""
import json
import os
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
    started = time.monotonic()
    step = "claim-lookup"

    def record(**facts):
        if path := os.environ.get("STAGE2_AGENT_EVIDENCE_FILE"):
            with Path(path).open("a", encoding="utf-8") as out:
                out.write(json.dumps(dict(case=config["case"], phase="connector", operation=operation,
                    step=step, elapsed_ms=round((time.monotonic()-started)*1000), **facts), sort_keys=True)+"\n")

    with httpx.Client(verify=context, trust_env=False, follow_redirects=False, timeout=5) as client:
        def gate(action, **fields):
            return client.post(config["gate"]+"/v1/actions", json=dict(common, action=dict(operation=action, operation_id=operation, **fields)))
        try:
            lookup = gate("claim-lookup")
            lookup.raise_for_status()
            request = lookup.json()["binding"]["request"]
            step = "custody"
            custody = client.post(config["warden"]+"/v1/custody", json=dict(common,
                action=dict(operation="custody", operation_id=operation, invocation=invocation)))
            custody.raise_for_status()
            credential = custody.content
            if not 0 < len(credential) <= 16384:
                record(result="invalid-credential-size")
                return 2
            record(result="credential-received")
            step = "final-send"
            final = gate("final-send", invocation=invocation)
            final.raise_for_status()
            admission = final.json()
            if admission.get("send_permitted") is not True or time.time()+2 >= admission["expires_at"]:
                record(result="no-current-send-permission")
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
            step = "target"
            result = client.post(config["target"]+"/effect", headers={"Authorization": "Bearer "+credential.decode()},
                json=dict(request=request, admission=admission, lose_reply=config.get("lose_reply", False)))
            result.raise_for_status()
            record(result="target-response-success")
            return 0
        except (httpx.HTTPError, ValueError, KeyError) as error:
            facts = dict(result=type(error).__name__)
            if isinstance(error, httpx.HTTPStatusError):
                facts["status"] = error.response.status_code
                if step != "custody":
                    try:
                        reason = error.response.json().get("error")
                    except ValueError:
                        reason = None
                    if reason in ("Invalid", "Refused", "Conflict", "Unavailable"):
                        facts["reason"] = reason
            record(**facts)
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
