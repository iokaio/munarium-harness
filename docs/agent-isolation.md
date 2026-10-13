# Experimental Linux agent isolation

The opt-in [boundary](../tests/network/agent_isolation.py) adds ISOLATION-01 under
[ADR 0015](https://github.com/iokaio/munarium-platform/blob/349059e16c38a66adc725c87ca6a9059260c32c9/docs/decisions/0015-stage2-linux-qualification.md)
to the existing real-service prepared-action composition. It runs the actual
proposer from an unprivileged Docker container while the trusted host runs the
five services, connector, target and independent observer. This tests the agent
boundary; separate per-service OS isolation remains outside this profile.

The Linux amd64 Python agent image is pinned by immutable multi-platform manifest
digest. Only four exact files enter the container: its proposer certificate/key,
the test CA and the probe script. Each is read-only. There is no checkout, home,
container socket, broker/target credential or privileged service identity mount.
The agent has UID/GID 65534, no capabilities, no new privileges, read-only root,
128 MiB memory, one CPU, 16 tasks and an 8 MiB temporary filesystem.

A unique internal bridge and dedicated firewall chain restrict agent traffic.
Only two host-bound TLS relays reach Gate and Warden; the relays forward unchanged
TLS to those exact enrolled services. Host INPUT and Docker forwarding paths both
enforce the restriction, including ports published by database containers. No
global firewall policy is flushed or relaxed. The test removes only its inserted
rules, chain, agent container and network, in dependency order.

The [agent probe](../tests/network/agent_probe.py) verifies positive Gate/Warden
connectivity before reporting denied target, broker, authority, database, metadata
and public egress paths. It checks absent privileged mounts and a read-only agent
directory. Container inspection independently checks the exact mount/privilege
configuration. Prepared proposals then originate from that same container and
continue through live distinct approval, grants/custody and final-send admission.
The existing independently persisted target oracle still checks actual effects,
response loss, stale workers and snapshot quarantine.

## Run and retained evidence

Use the [activation recipe](activation-profile.md) and its isolated database inputs:

```console
python scripts/run_activation.py --workspace WORKSPACE_PARENT --output target/isolation-unique.json --owner TEST_OWNER --database-image sha256:OBSERVED_IMAGE_DIGEST --execution --isolation
```

The host must be Linux with Docker's iptables networking and noninteractive sudo
for task-scoped network rules. Windows/Docker Desktop cannot substitute for that
host boundary. Environment owner, availability, limits and teardown are the same
disposable local/CI intake as the existing execution profile. A missing prerequisite
fails; it never counts as a denied path. The evidence records the image and boundary,
retains `qualification:false` and lists dynamic evaluation, per-service host isolation,
production and restore reopening as exclusions. Source/binary/image/log pins and
all failed attempts are retained. The additive hosted step preserves the original
activation and execution histories and publishes its own sanitized evidence.
