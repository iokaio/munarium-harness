# SPDX-License-Identifier: Apache-2.0
"""Task-owned Linux agent boundary around the actual native-service composition."""
from contextlib import ExitStack
import ipaddress
import json
import os
from pathlib import Path
import select
import shutil
import socket
import socketserver
import subprocess
import sys
from threading import Thread
from urllib.parse import urlsplit
import uuid

AGENT_IMAGE = "python:3.13-slim@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f"


def command(*args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, timeout=30, **kwargs)


def rule(*args):
    command("sudo", "-n", "iptables", "-w", "5", *args)


def relay(address, backend, stack):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                with socket.create_connection(backend, timeout=5) as remote:
                    self.request.settimeout(5)
                    peers = (self.request, remote)
                    while True:
                        readable, _, _ = select.select(peers, [], [], 5)
                        if not readable:
                            return
                        for source in readable:
                            data = source.recv(65536)
                            if not data:
                                return
                            (remote if source is self.request else self.request).sendall(data)
            except OSError:
                return

    class Server(socketserver.ThreadingTCPServer):
        daemon_threads = True

    server = Server((address, 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    stack.callback(server.server_close)
    stack.callback(server.shutdown)
    return server.server_address[1]


class Boundary:
    def __init__(self, execution):
        if sys.platform != "linux":
            raise RuntimeError("actual Linux host required for agent isolation")
        self.stack = ExitStack()
        self.execution = execution
        self.name = "ref-agent-" + uuid.uuid4().hex[:12]
        self.chain = "MNR_" + uuid.uuid4().hex[:12]
        try:
            network = command("docker", "network", "create", "--internal", self.name).stdout.decode().strip()
            self.stack.callback(command, "docker", "network", "rm", network)
            info = json.loads(command("docker", "network", "inspect", network).stdout)[0]
            assert info["Internal"] is True, "internal agent network"
            self.gateway = str(ipaddress.ip_address(info["IPAM"]["Config"][0]["Gateway"]))
            bridge = "br-" + network[:12]
            self.gate = relay(self.gateway, ("127.0.0.1", urlsplit(execution.endpoints["svc-gate"]).port), self.stack)
            self.warden = relay(self.gateway, ("127.0.0.1", urlsplit(execution.endpoints["svc-warden"]).port), self.stack)
            rule("-N", self.chain)
            self.stack.callback(rule, "-X", self.chain)
            self.stack.callback(rule, "-F", self.chain)
            for port in (self.gate, self.warden):
                rule("-A", self.chain, "-d", self.gateway, "-p", "tcp", "--dport", str(port), "-j", "ACCEPT")
            rule("-A", self.chain, "-j", "REJECT")
            # Host listeners traverse INPUT; Docker-published database ports can
            # DNAT into FORWARD. Both paths must enforce the agent boundary.
            for parent in ("INPUT", "DOCKER-USER"):
                rule("-I", parent, "1", "-i", bridge, "-j", self.chain)
                self.stack.callback(rule, "-D", parent, "-i", bridge, "-j", self.chain)
            inputs = execution.directory / "agent-inputs"
            inputs.mkdir()
            cert, key, _ = execution.identities["proposer"]
            for source, name in ((cert, "proposer.pem"), (key, "proposer.key"),
                                 (execution.directory / "ca.pem", "ca.pem"),
                                 (Path(__file__).with_name("agent_probe.py"), "probe.py")):
                shutil.copyfile(source, inputs / name)
                (inputs / name).chmod(0o444)
            self.mounts = ["/run/agent/" + name for name in ("proposer.pem", "proposer.key", "ca.pem", "probe.py")]
            args = ["docker", "run", "-d", "--name", self.name, "--network", network,
                    "--platform", "linux/amd64",
                    "--user", "65534:65534", "--read-only", "--cap-drop", "ALL",
                    "--security-opt", "no-new-privileges", "--memory", "128m", "--cpus", "1",
                    "--pids-limit", "16", "--tmpfs", "/tmp:rw,noexec,nosuid,size=8m"]
            for destination in self.mounts:
                args += ["--mount", "type=bind,src=" + str(inputs / Path(destination).name) + ",dst=" + destination + ",readonly"]
            self.container = command(*args, AGENT_IMAGE, "python", "-c", "import time; time.sleep(600)").stdout.decode().strip()
            self.stack.callback(command, "docker", "rm", "-f", "-v", self.container)
            self.inspect()
        except BaseException:
            self.close()
            raise

    def inspect(self):
        info = json.loads(command("docker", "inspect", self.container).stdout)[0]
        host = info["HostConfig"]
        assert info["Config"]["User"] == "65534:65534"
        assert host["ReadonlyRootfs"] and host["CapDrop"] == ["ALL"]
        assert "no-new-privileges" in host["SecurityOpt"]
        assert host["Memory"] == 128 * 1024 * 1024 and host["PidsLimit"] == 16
        mounts = [m for m in info["Mounts"] if m["Type"] == "bind"]
        assert {m["Destination"] for m in mounts} == set(self.mounts), "exact agent mounts"
        assert all(not m["RW"] for m in mounts), "read-only agent mounts"
        assert all(m["Type"] == "bind" or (m["Type"] == "tmpfs" and m["Destination"] == "/tmp")
                   for m in info["Mounts"]), "unexpected agent mount"

    def run(self, spec):
        spec.update(gateway=self.gateway, gate=self.gate, warden=self.warden)
        result = subprocess.run(["docker", "exec", "-i", self.container, "python", "/run/agent/probe.py"],
                                input=json.dumps(spec).encode(), capture_output=True, timeout=30)
        if result.returncode:
            # The probe emits only fixed diagnostic labels; never print its input,
            # service responses, environment or mounted identity bytes.
            lines = result.stderr.decode(errors="replace").splitlines()
            raise AssertionError("agent probe refused: " + (lines[-1] if lines else "no diagnostic"))
        return json.loads(result.stdout)

    def probe(self):
        e = self.execution
        denied = [("target", self.gateway, urlsplit(e.target).port),
                  ("broker", self.gateway, urlsplit(e.bao_endpoint).port),
                  ("authority", self.gateway, urlsplit(e.endpoints["svc-server"]).port),
                  ("metadata", "169.254.169.254", 80),
                  ("public-egress", "1.1.1.1", 443)]
        for name, variable in (("gate-database", "STAGE2_GATE_DATABASE_URL"),
                               ("server-database", "MUNARIUM_PLATFORM_TEST_DATABASE_URL")):
            denied.append((name, self.gateway, urlsplit(os.environ[variable]).port or 5432))
        result = self.run(dict(operation="probe", denied=denied))
        assert result["status"] == "passed", "agent denied-edge evidence"
        print("agent isolation evidence: permitted service edges, denied target/broker/stores/authority/metadata/egress and exact read-only mounts passed")

    def prepare(self, tenant, name):
        result = self.run(dict(operation="prepare", request=dict(tenant=tenant,
                         action=dict(operation="prepare", operation_id=name, attempt_id="attempt-" + name))))
        assert result["status"] == 200, "actual agent prepared request"
        return result["value"]

    def close(self):
        self.stack.close()
