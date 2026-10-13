# SPDX-License-Identifier: Apache-2.0
"""Run from the unprivileged agent container; never receive privileged credentials."""
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
import sys


class Service(http.client.HTTPSConnection):
    def connect(self):
        connection = socket.create_connection((self.host, self.port), self.timeout)
        # The relay transports TLS unchanged to the loopback-named service.
        self.sock = self._context.wrap_socket(connection, server_hostname="127.0.0.1")


def connected(address, port):
    try:
        with socket.create_connection((address, port), timeout=1):
            return True
    except OSError:
        return False


def main():
    spec = json.load(sys.stdin)
    context = ssl.create_default_context(cafile="/run/agent/ca.pem")
    context.load_cert_chain("/run/agent/proposer.pem", "/run/agent/proposer.key")
    if spec["operation"] == "prepare":
        service = Service(spec["gateway"], spec["gate"], context=context, timeout=5)
        service.request("POST", "/v1/actions", json.dumps(spec["request"]), {"Content-Type": "application/json"})
        response = service.getresponse()
        value = json.loads(response.read(65537))
        print(json.dumps({"status": response.status, "value": value}))
        service.close()
        return
    if spec["operation"] != "probe":
        raise ValueError("probe operation")
    assert os.getuid() == 65534, "agent privilege"
    results = {}
    for name, address, port in spec["denied"]:
        results[name] = not connected(address, port)
        assert results[name], "denied edge: " + name
    # Positive controls prevent an offline/broken container counting as isolation.
    for name, port in [("gate", spec["gate"]), ("warden", spec["warden"])]:
        assert connected(spec["gateway"], port), "permitted edge: " + name
        results[name + "-reachable"] = True
    for name in ("/var/run/docker.sock", "/run/secrets/target", "/run/secrets/broker", "/root/.aws/credentials"):
        assert not Path(name).exists(), "privileged mount exposed"
    assert set(Path("/run/agent").iterdir()) == {Path("/run/agent") / name for name in
                                               ("ca.pem", "proposer.pem", "proposer.key", "probe.py")}
    try:
        Path("/run/agent/write-probe").write_text("forbidden")
    except OSError:
        results["mount-read-only"] = True
    else:
        raise AssertionError("agent mount writable")
    results["privileged-mounts-absent"] = True
    print(json.dumps({"status": "passed", "checks": results}))


if __name__ == "__main__":
    main()
