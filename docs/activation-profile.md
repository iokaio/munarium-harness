# Experimental Stage 2 activation composition

The [scenario](../tests/network/test_activation.py) runs actual Server, Council,
Registry, Gate and Warden processes. Server and Gate use PostgreSQL; the other
owners retain SQLite WAL/FULL journals. Ephemeral mTLS peers, provider keys,
publisher keys and operator bindings have no trust outside the test directory.
Council requires a separate enrolled human ratifier; a proposer cannot ratify.
Registry admits an actual signed candidate using an assertion issued by Warden.

The test drops one successful owner response after each durable phase: Gate
pause, Registry apply, Server apply, Warden apply, Gate apply, and Gate resume.
It restarts Council and the affected participant after each loss, checks that
incomplete progress remains paused, and recovers through the same transition.
All four installed heads and immutable receipts must match at completion.
Gate continues to report `execution_enabled:false` after successful resume.

These are process restart and activation tests. They do not prove snapshot restore,
action lifecycle outbox delivery, grant/custody or target behavior, evaluator
limits, or denied agent network/secret access. No execution endpoint is exercised.
The fault proxy uses the real Council certificate for its Council-only upstream
calls; it discards responses only after a real owner has returned success.
Synthetic dependency services are not substituted for participants.

## Reproduction and retained evidence

Build each component from the exact revisions pinned by the
[automatic workflow](../.github/workflows/stage2-activation.yml), using Rust 1.98.1.
Install Server's Python `dev,platform-test` extras. Supply two disposable databases
through `MUNARIUM_PLATFORM_TEST_DATABASE_URL` and `STAGE2_GATE_DATABASE_URL`, using
loopback bindings and synthetic credentials. The Server database needs pgvector.
The same isolated database can be used locally when database isolation is explicitly
excluded; hosted CI uses separate databases on its own bounded test container.

```console
python scripts/run_activation.py --workspace WORKSPACE_PARENT --output target/activation-unique.json --owner TEST_OWNER --database-image sha256:OBSERVED_IMAGE_DIGEST
```

The runner refuses an existing evidence path and records source revisions/dirty
state, source tree digests, binary hashes, image digest, environment, test command,
result and log hash. It includes Council in its inventory. It never records
database URLs or temporary keys. A failed attempt stays failed; use a new path
for a corrected run. Pytest assertion rewriting is disabled so failures cannot
dump locals containing temporary credentials. Diagnostic labels contain operation
names and status codes only.

The caller owns database availability, a maximum 2 CPU/768 MiB container budget,
host resource authority and teardown at test completion. The scenario removes
only its temporary directory and stops only its own processes/proxy. On the
runner's 240-second timeout, inspect those owned resources before removing the
test database; forced termination can prevent Python cleanup. Hosted CI always
tears down its job services. No paid or production resources are authorized.

Local Windows evidence and hosted Linux evidence are distinct. The passing
activation scenario is an experimental composition result, not human acceptance,
execution qualification, or permission to merge/release.

## Participant delivery extension

The composition also enrolls each participant as its own Server recorder, with
real Warden provider assertions and dedicated activation source streams. After the
six existing activation response-loss histories, it rejects a reader's flush,
substitutes a wrong acknowledgement, loses the real committed acknowledgement,
restarts each owner and verifies recovery of the original Server acknowledgement.
A second flush returns zero; delivery never changes execution availability.

The fault proxy forwards as the actual enrolled caller and accepts only the named
service certificates. No recording identity or acknowledgement is accepted from
an ordinary test caller. The fixture uses one provider binding per workload
subject, with recipient-specific policies narrowing its allowed audience/resource.
This remains activation/audit integration, not action effect qualification.

## Prepared synthetic release extension

Run `scripts/run_activation.py --execution` with the same arguments and database
inputs above, plus `STAGE2_DATABASE_CONTAINER` set to the exact caller-owned
PostgreSQL container ID. The runner retains each attempt separately; it refuses to
overwrite earlier evidence. Allow 480 seconds for two histories. The test starts a
pinned OpenBao 2.4.4 container (256 MiB, one CPU, loopback port), native service and
connector processes, and an independent mTLS target with its own SQLite store.
It removes its own OpenBao container, temporary identities and restored database;
the caller remains responsible for the original PostgreSQL test container.

The service surface accepts operator-enrolled prepared disposable release requests.
It does not run a dynamic Linux evaluator. Each operation has a unique qualified
attempt identity. Gate assembles hashes/mandatory obligations, Council records a
distinct enrolled human approval, Warden issues and records a stable grant, and
Gate consumes it with capacity and worker custody. Only the connector certificate
can retrieve OpenBao secret bytes or call final send. The target checks expected
version/content, stable effect key and recovery floor atomically with mutation.

The two real-service histories exercise:

- One approved effect and a second target commit with a lost reply, with independent
  target observations and no resend after Gate/connector restart.
- Exact action outbox delivery, independent target reconciliation, retained original
  unresolved outcomes and no same-hour capacity refund after settlement.
- A real PostgreSQL snapshot captured after consumption but before an effect,
  restored into a NEW disposable database. A signed external recovery generation
  and installed target floor keep that restored state quarantined; original Server
  and target histories remain intact.
- A final-admission commit whose successful reply is lost. No target send follows,
  including after restart. A paused admitted worker is rejected by the target's
  newer recovery floor, with the actual refusal reason retained by the target.
- Live Council withdrawal before consumption and too-late withdrawal after final
  admission, plus refusal of the real proposing identity at grant/custody/target
  interfaces. These are authenticated access tests, not OS isolation tests.

The target and connector are test executables under `tests/network/`, not supported
release clients or deployments. The reusable test credential's scope is the exact
synthetic target; no production credential or destination is used. No-effect
settlement, automatic rollback detection, reconciled reopening, arbitrary dynamic
policy evaluation and OS network/mount isolation remain unqualified. The recovery
procedure must advance external authority and fence the target before restored
workers start; an undisclosed rollback is outside this experimental boundary.
