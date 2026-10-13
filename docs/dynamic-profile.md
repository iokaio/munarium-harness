# Experimental dynamic isolated release profile

This opt-in DYNAMIC-01 profile follows
[ADR 0016](https://github.com/iokaio/munarium-platform/blob/74fffdf67d7911f62eec3650fc0a8e9d7ec42239/docs/decisions/0016-dynamic-release-admission.md).
It composes actual Server, Registry, Warden, Council and Gate processes and journals,
native pinned Linux OPA, the [unprivileged agent boundary](agent-isolation.md),
OpenBao custody, connector and independently persisted target. No owner service
response is stubbed. The fault proxy forwards actual enrolled identities and only
drops successful replies or substitutes acknowledgement digests for negative tests.

The fixture admits a signed disposable C2 publication manifest through real Registry
inventory and the existing activation barrier. Signed Server owner enrollment binds
each task's immutable canonical test-result source, qualified context and native
policy/schema pins. The agent proposes parameters within those enrolled slots;
it cannot supply context, identity, target URLs or credentials. The evidence adapter
is `test-result` v1, not arbitrary Server/Matrix retrieval. The native policy permits
only a verified passed result for the proposed artifact. Exact distinct approval,
recording, action capacity and credential custody remain required before dispatch.

Gate's [ADR 0017](https://github.com/iokaio/munarium-platform/blob/513543df9cf17ada46feffcf590883d16b950980/docs/decisions/0017-scoped-registry-assertions.md)
preflight verifies its scoped Registry read identity before custody and retains only
that signed identity in bounded private memory. Every owner query remains live.
This avoids repeated usability waits during Warden's before/after broker checks
and final admission, while preserving five-second custody and two-second clock
margins. Assertion bytes never enter agent responses or evidence.

The extra controls exercise actual native denial, stale evidence, parameter/context
substitution, foreign tenant/actor, prepared-request bypass, incorrect real Server
archive receipts, loss of a committed proposal reply, restart with immutable retry
and changed-parameter conflict. An independent target observation must show zero
sends/effects for these controls. The existing execution histories then require
approved effects, no resend after restart or lost replies, retained capacity,
withdrawal, stale-worker target refusal and restored-store quarantine.

Run the [activation recipe](activation-profile.md) with its explicit disposable
database/container inputs on a Linux cgroup v2 host:

```console
python scripts/run_activation.py --workspace WORKSPACE_PARENT --output target/dynamic-unique.json --owner TEST_OWNER --database-image sha256:OBSERVED_IMAGE_DIGEST --execution --isolation --dynamic
```

Set `OPA_LINUX_EXECUTABLE` to the public OPA 1.21.1 Linux amd64 static executable
with SHA-256 `668506eb17a2eaa1fce6cc0d1f42ef85125d4ac5bda5fc74d1152d0c77145031`.
The trusted test supervisor and Gate must start inside `MUNARIUM_OPA_CGROUP_ROOT`'s
delegated supervisor child; the workflow records the exact administrative placement
and drops back to the ordinary runner before tests. Each worker gets its own bounded
child: 64 MiB aggregate memory, zero swap, 16 tasks, one CPU and 100 ms evaluation.
Unavailable bounds fail. The agent gains no cgroup or administrative privilege.

Use only existing disposable local/CI hosts, with the owner, resource limits and
end-of-test expiry in the recipe. The scenario removes its task-owned services,
OpenBao, target, network rules, agent container and restored database. The workflow
removes only its unique evaluator subtree; the caller removes initial databases.
No production trust, external model calls, deployment or paid resources are involved.

The runner retains source/binary/image/evaluator pins, log and per-case agent
observations, including dynamic controls and independent target counts. Missing
required case phases fail even after successful pytest exit. Every attempt has a
distinct output path and `qualification:false`. Separate per-service OS isolation,
arbitrary tasks/evidence, automatic rollback detection/reopening and production
qualification remain excluded. This profile adds coverage without replacing the
activation, prepared execution or prepared agent-isolation histories. Hosted CI
must pass on the exact PR head before a result is claimed.
