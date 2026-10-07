# Stage 1 clients and library composition

The [Rust client](../src/decision.rs) and independent
[Python client](../python/munarium_harness/decision.py) implement decision-json-v1,
typed proposals, exact tenant/operation/digest response binding and seven explicit outcomes.
Retain the proposal and operation ID before calling `submit`. The transport sends once;
an ambiguous result leads to `lookup` of that same operation. Neither client automatically
resubmits or creates a replacement operation ID. `decision-only-allow` grants no authority.
Applications supply an authenticated transport; these helpers do not establish a security
boundary inside an agent process. No package has been published.

## Component checks

Rust 1.98.1 and Python 3.12+ are required. Component tests need no other repository.

```console
cargo fetch --locked
cargo fmt --all --check
cargo test --offline --locked
cargo clippy --offline --locked --all-targets -- -D warnings
python -m unittest discover -s python -p "test_*.py"
```

Both clients consume the [same unchanged hub vectors](../contracts/stage1/README.md)
with independent implementations. Rust and Python test ambiguous input, binding failures,
closed outcomes and read-only response-loss recovery. Add `python/` to the application's
Python import path when using this unreleased source package.

## Actual component composition

Check out public `munarium`, `munarium-platform`, `munarium-registry`, `munarium-warden`,
`munarium-gate` and `munarium-harness` side by side with these Stage 1 changes applied.
Branches are development inputs, not immutable released pins. The
[runner](../scripts/run_stage1.py) verifies origins and retains HEAD, dirty state and a
source-content digest, including new source files but excluding ignored files and unrelated
worktrees. Its disposable consumer uses the separate checked-in
[composition lock](../tests/composition/Cargo.lock). No component depends on a sibling
checkout for its ordinary build. Use `--refresh-lock` only for an intentional reviewed
dependency change; normal runs are locked.

Acquire Gate's pinned Windows OPA binary using its Stage 1 guide. From this repository:

```console
python scripts/run_stage1.py --workspace WORKSPACE_PARENT --opa PATH_TO_OPA --owner OPERATOR --output target/stage1-runs/unique-run.json --online
```

`--online` fetches locked public crates; omit it with a populated cache. If rustup's
installed `stable` alias is exactly 1.98.1, `--toolchain stable` avoids downloading a
duplicate toolchain. The runner checks the actual compiler version. It refuses to replace
a prior run record. Use `--prior-attempt` to link a retry without deleting failed evidence.

The [scenario](../tests/composition/scenario.rs) calls real implementations: Registry's
signed candidate admission/resolution, Warden's existing verifier through its identity-only
package, Gate and native OPA, and Server's event/replay ledger. Registry and Warden also
run all 32 unchanged signed identity vectors. Synthetic keys are generated in memory,
never written or printed. Fixtures use a frozen clock and must not become live identities.

To exercise actual PostgreSQL, create a separate loopback test database using Server's
pinned `pgvector/pgvector:pg16` image and its migrations. Pass its fictional test connection
through `MUNARIUM_TEST_DATABASE_URL`, then add `--database postgres`.
Supply the observed `--database-image IMAGE@sha256:DIGEST` and
`--database-version VERSION` as nonsecret run metadata. Do not use an
existing service or production database. The memory profile ignores that environment value.
The database belongs to the caller: remove only the container/volume created for the run
after checking its identity. The runner removes its temporary Cargo consumer and OPA
workers; compiled caches and the run's evidence directory remain.

## Evidence and limits

Cases include allow and deny with exact replay; inactive and unknown candidates; missing
and untrusted lineage; tenant substitution; unavailable recording/identity; actual lost
response followed by lookup without resubmission; changed operation content; and recovery
from a persisted replay bundle. Commands, times, exit statuses, separate stdout/stderr
files and digests, contract/policy/manifest/evaluator pins, ledger positions/source ranges,
review state, exclusions and prior attempts are retained beside each record.

This runner covers the in-process composition using privileged adapters and operator
fixtures. The additional [service profile](service-profile.md) supplies separate
mTLS identities, provider enrollment, Server authority and durable recording/recovery.
Neither run includes a grant issuer, connector or target. Structural absence is not
a measured production network-isolation claim. Human acceptance, immutable published
inputs and independent review remain requirements for closing Stage 1 qualification.
