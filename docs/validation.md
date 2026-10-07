# Munarium Harness validation

## Build the experimental library locally

Use Rust **1.98.1** with Cargo, rustfmt and Clippy, plus the platform's native linker.
The manifest requires Rust 1.98; older toolchains are not qualified by this scaffold.
CI installs 1.98.1 explicitly. Fetch the locked public crates once; subsequent component
checks are offline and need no provider account, database or sibling checkout:

```console
cargo fetch --locked
cargo fmt --all --check
cargo build --offline --locked
cargo clippy --offline --locked --all-targets -- -D warnings
cargo test --offline --locked
cargo doc --offline --locked --no-deps
```

`Cargo.lock` is checked in. Do not regenerate it to bypass a locked-build failure.
The lock pins reviewed public dependencies. See [Stage 1](stage1.md) for native evaluator
and cross-repository composition prerequisites.

Build, lint and tests cover the implemented Stage 1 library. See [Stage 1](stage1.md)
for exact behavioral coverage; broader acceptance cases below remain specifications.
`cargo doc` produces local API documentation under `target/doc/`.

Run the existing repository checks too:

```console
py check_license.py
py scripts/private_material_scan.py
py scripts/docs_linkcheck.py
gitleaks dir . --config .gitleaks.toml --no-banner --redact --exit-code 1
git diff --check
```

Use `python` or `python3` if the `py` launcher is unavailable. The secret command scans
the working tree; the existing hygiene workflow also scans Git history. No local result
is evidence that hosted CI passed.

## Automatic coverage

The new [Rust workflow](../.github/workflows/rust.yml) runs formatting, build, lint, tests
and warning-free API documentation on pushes to main and pull requests. It uses read-only
repository permissions and has no publishing, deployment or provider steps.
The existing [hygiene workflow](../.github/workflows/repo-hygiene.yml) and
[DCO workflow](../.github/workflows/dco.yml) retain their independent checks.

## Required behavioral acceptance cases

These broader acceptance requirements are not all implemented. Invariant IDs refer to the catalog in
[platform plan revision 4, Appendix C](https://github.com/iokaio/munarium-platform/blob/main/docs/platform-plan.md) and the
[hub catalog](https://github.com/iokaio/munarium-platform/blob/main/README.md#the-invariant-catalog). No contract bundle has been released.

| Invariant | Scenario | Required observation |
|---|---|---|
| INV-05 | Run every canonicalization vector in Rust and the selected application client. | Identical accepted bytes/digests and ambiguity refusals. |
| INV-11 | Return unresolved or lose a submission response. | Expose investigation/lookup; never blind redispatch. |
| INV-03 / INV-04 | Bypass Harness with an equivalent hand-built request. | Server-side validation is identical; no privilege is granted by SDK use. |
| INV-05 | Generate bindings from a different contract bundle. | Detect digest mismatch; regenerate rather than hand-edit. |
| INV-11 | Use an adapter that cannot represent a required obligation. | Reject or explicitly narrow supported operations. |

INV-21 (protected development authority) and INV-22 (claims bounded by evidence)
apply to every packet in addition to the component-specific cases.

## Evidence to retain when the tests exist

Record source and contract digests, toolchain, fixture identifiers, command/exit status,
environment, declared trust boundary, expected and actual outcome, and remaining gaps.
Concurrency, crash/restart, identity, network and storage claims require their real test
environment; an in-memory fake cannot certify them. A live integration needs its own
authorization and qualification record.

Keep operational credentials and raw private payloads out of test artifacts. Distinguish
a local pass, unavailable coverage, a failing case, and an independently reviewed result.
No capability-status or invariant-evidence field advances from the scaffold checks.
