# Munarium Harness

**SDKs that make the governed path easy for honest agents.** Harness is the agent-plane component
of the Munarium Governance Platform: client bindings, examples and framework adapters that build a
typed Action Proposal, carry task and evidence references, and return a typed outcome an agent can
act on correctly. Its purpose is adoption and consistency. **It does not create a security boundary
inside the agent that uses it.** Gate, Server, Warden and Council verify every request even when
Harness is bypassed, modified or absent.

> **Status: Stage 1 clients implemented.** The authenticated service/client
> profile is implemented and covered by component and separate-process tests.
> See the [service profile](docs/service-profile.md). Candidates remain inactive;
> no execution endpoint is mounted. Human acceptance and production qualification
> remain pending.

The experimental [Stage 2 activation composition](docs/activation-profile.md)
tests the five-service barrier and restart recovery. Its opt-in prepared release
extension tests real grants/custody, synthetic effects and restore quarantine;
OS isolation and safe reopening remain unqualified.

Harness is one of nine components built around the existing Munarium foundation, Munarium Server
and Munarium Matrix. Their shared architecture, normative contracts, decision records, roadmap and
composition evidence live in the public hub,
[iokaio/munarium-platform](https://github.com/iokaio/munarium-platform). This repository will hold
the clients, their conformance fixtures, examples, diagnostics, package definitions and release
evidence. It is open source from its first public commit, under the Apache License 2.0, with no
proprietary edition.

## Start building

Read the [development index](docs/README.md), then the [architecture](docs/architecture.md),
[implementation plan](docs/implementation-plan.md) and [validation guide](docs/validation.md).
They map the public platform plan to source modules, dependencies, a first bounded work item
and acceptance cases. See the experimental [Stage 1 implementation](docs/stage1.md).
Released supported contract versions remain **none**.

## What Harness is for

The platform separates four powers: **read**, **governed write**, **act** and **govern**. Harness
lives in the agent plane, where code can reason and propose but cannot inherit administrator
credentials, read broker secrets, edit active policy or reach a consequential target directly.
Harness makes the correct path the easiest one: the same proposal shape, the same outcome
vocabulary and the same recovery behavior in every language, so that two clients mean the same
thing when they submit or recover the same action.

## The design, as planned

### The initial client surface

The first client builds a typed **Action Proposal**, carries task and evidence references, receives
a typed **outcome**, and exposes decision explanations. The outcome vocabulary is closed:

| Outcome | Meaning | What an honest agent does next |
|---|---|---|
| denied | Required authority or condition absent | Does not retry as-is; a changed proposal is a new evaluation |
| approval-required | A specific obligation or distinct authority is missing | Waits, withdraws, or lets the request expire |
| accepted-for-execution | A durable claim exists; dispatch will be attempted | Waits for the outcome; does not resubmit |
| completed | The target outcome is known within the connector contract | Replays the recorded response; never repeats the effect |
| failed-before-dispatch | No effect was attempted | May propose again under the operation identity rules |
| unresolved | Some, all or none of the effect may have occurred | Investigates; never redispatches blindly |

**A generic exception must not encourage an agent to repeat an action that may already have
occurred.** Unresolved is a first-class typed outcome, not an error.

Evidence references are convenient to carry, but the client does not claim to prove the model's
information lineage. A model can combine uncited material with cited material; for
authority-bearing fields, Gate or its connector validates the value against an authoritative source
or requires a separately approved verification step.

### Languages and order

**Rust contract fixtures and one practical application client precede a broad language matrix.**
Python and .NET are the initial candidates because they support useful reference applications;
TypeScript, Java and further framework adapters follow demand and conformance evidence. The
commitment is shared semantics across languages, not simultaneous first releases of every binding.
Generated bindings identify the contract digest they were generated from.

### Framework and protocol adapters

LangGraph, Semantic Kernel, the OpenAI and Claude agent SDKs, Google ADK, MCP clients and custom
applications are integration targets. Each adapter is a **separately qualified surface**, not a
claim of current support. Framework callbacks and convenience hooks do not substitute for
deployment-level credential and egress controls.

The **native Action API remains canonical**. An MCP client sees a narrow tool surface synthesized
from approved manifests. An adapter that cannot represent a required obligation or preserve a
request binding rejects the operation or restricts its supported scope rather than silently
degrading the contract.

### Developer experience

Harness ships local examples, test fixtures and diagnostics that explain why a proposal was refused
without disclosing another tenant's policy or sensitive evidence. The initial samples cover **a fake
ticket, a harmless approved effect, a blocked governance mutation and an ambiguous target
response**, and they show what is not covered: unmanaged model endpoints and tools outside the
mediated deployment.

Two measurements matter: **time to the first governed action** and **time to diagnose the first
denial**. A sample that requires undocumented manual changes has not passed the adoption gate.

Harness also owns the platform's developer command line and scaffolding: local setup, explain,
replay and diagnostic export, with composition recipes kept in the hub.

### Cross-language conformance

Conformance compares **canonical request bytes, hashes, error codes and outcome handling** against
the hub's golden vectors. The most important test is not whether each client can call an endpoint;
it is whether two clients mean the same thing.

## First public increment

**A typed proposal-and-outcome client with examples**, in the platform's first usable increment
alongside Registry's catalog, Gate's decision-only evaluator, the action-record shapes and verified
principal context. The examples run against a disposable target and explain and replay decisions;
they do not govern enterprise effects.

Target window: Stage 1 (months 2–3).

## Capability status

The labels are evidence labels, not editions: **Planned**, **Experimental**, **Conformance-tested**,
**Reference-qualified**, **Independently reviewed**. In the hub's component catalog this
repository is at **repository created**.

| Capability | Status | Evidence |
|---|---|---|
| Rust canonical bytes/digests and outcome vectors | Experimental | [Tests](tests/decision.rs) |
| Python application client with supplied transport | Experimental | [Client and tests](docs/stage1.md) |
| Typed proposal builder and closed outcome vocabulary | Experimental | [Stage 1](docs/stage1.md) |
| Decision explanations and refusal diagnostics without cross-tenant disclosure | Planned | none |
| Local examples: fake ticket, harmless approved effect, blocked governance mutation, ambiguous target response | Planned | none |
| Developer command line: local setup, explain, replay, diagnostic export | Planned | none |
| Independent Rust and Python decision clients | Experimental | [Unchanged vectors](contracts/stage1/README.md) |
| MCP client adapter with a narrow synthesized tool surface | Planned | none |
| TypeScript and Java bindings | Deferred; follow demand and evidence | none |
| LangGraph, Semantic Kernel, OpenAI and Claude agent SDK, Google ADK adapters | Deferred; each separately qualified | none |

Released contract versions: **none**. Published packages: **none**. Experimental library
operations and composition are described in [Stage 1](docs/stage1.md).

## Acceptance evidence for the first release

| Test | Required outcome |
|---|---|
| Golden canonicalization vectors | Every client produces the same bytes and digest for accepted inputs and the same rejection for ambiguous ones |
| Outcome handling | Denied, approval-required, accepted-for-execution, completed, failed-before-dispatch and unresolved are distinguishable in every client; unresolved never surfaces as a retryable error |
| The four samples | Each runs from a clean clone with the documented inputs and no undocumented manual change |
| Refusal diagnostics | Explain the denial; disclose no other tenant's policy or sensitive evidence |
| Bypass | Gate refuses a hand-built request with the same rigor as a Harness-built one; the client adds no permission |
| Adapter contract | An MCP adapter refuses an operation whose obligation or request binding it cannot represent |
| Generated bindings | Carry the contract digest they were generated from |

A blank evidence field means unverified, not passed.

## Invariants

| ID | Required property | Owner and first gate |
|---|---|---|
| INV-05 | Canonical requests produce the same digest across supported clients | Hub contracts and Harness; stage 1 |
| INV-11 | An unresolved effect is never blindly repeated | Gate, connector, Harness, Console; stages 2–3 |
| INV-22 | A release advertises only the profiles and capabilities supported by its evidence | every component; every stage |

## Contracts, dependencies and neighbors

- **Contracts.** The hub's contracts directory is normative for the Action Proposal, the outcome
  vocabulary and the canonicalization specification with its golden vectors. Harness implements
  and may publish generated bindings for them; the generation identifies the contract digest.
  Supported contract versions: none yet.
- **Foundation.** The Server client libraries in [iokaio/munarium](https://github.com/iokaio/munarium)
  and the Matrix clients in [iokaio/munarium-matrix](https://github.com/iokaio/munarium-matrix)
  are the precedent: official clients proven against their service by the same conformance
  scenarios. Whether Harness packages are published through
  [iokaio/munarium-clients-publish](https://github.com/iokaio/munarium-clients-publish) is decided
  when they exist.
- **Gate** is what the client talks to; **Registry** manifests define the tool surface an MCP
  adapter synthesizes; **Console** shares the outcome vocabulary and the rule against retrying the
  unresolved.
- **External dependencies.** See [Cargo.toml](Cargo.toml), the lockfile and
  [dependency notices](THIRD_PARTY_NOTICES.md). Stage 1 choices remain experimental.

## Not in scope

- Enforcing anything. A check only the client performs is not a control, and the documentation
  will not describe it as one.
- Proving a model's information lineage.
- Simultaneous first releases of every language binding, or a framework adapter listed as supported
  before its conformance evidence exists.
- Retry helpers that can redispatch a possibly completed effect.
- Hiding what is uncovered: unmanaged model endpoints and tools outside the mediated deployment.

## Roadmap position

| Stage | Harness's part |
|---|---|
| 0 · month 1 | This repository; the canonicalization specification and outcome vocabulary drafted in the hub |
| 1 · months 2–3 | Rust fixtures, the first application client, the four samples, against Gate's decision-only slice |
| 2 · months 4–6 | The client through the first complete governed action, including the unresolved path |
| 3 · months 7–9 | The developer command line; external evaluations exercise the samples and denial explanations |
| 4 · months 10–12 | Second binding and MCP adapter conformance; inclusion in the reference composition |
| 5 · months 13+ | Further bindings and framework adapters, demand-led and separately qualified |

SDK breadth is among the first things reduced when capacity is constrained; shared semantics are
not.

## Repository layout

| Path | What exists |
|---|---|
| [Cargo.toml](Cargo.toml), [Cargo.lock](Cargo.lock) | Independent library, version 0.1.0-dev, publishing disabled, reviewed locked dependencies |
| [src/lib.rs](src/lib.rs) | Experimental decision implementation and proposed later-stage interfaces |
| [docs/](docs/README.md) | Architecture, implementation sequence and acceptance specifications |
| [CONTRIBUTING.md](CONTRIBUTING.md), [AGENTS.md](AGENTS.md), [CLAUDE.md](CLAUDE.md) | Contribution process and aligned development guidance |
| [.github/workflows/](.github/workflows/) | Automatic Rust, repository-hygiene and DCO checks |
| [scripts/](scripts/), [check_license.py](check_license.py) | Existing documentation, private-material and license checks |
| [LICENSE](LICENSE), [NOTICE](NOTICE), [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) | Licensing and dependency notices |

Subsystem modules: [proposal](src/proposal.rs), [client](src/client.rs), [recovery](src/recovery.rs).
Stage 1 tests and candidate fixtures are implemented. The ordinary component build depends on
no sibling checkout; Harness owns the separate experimental composition.

## Development

Use Rust 1.98.1 with rustfmt, Clippy and the platform's native linker. From this repository root:

```console
cargo fetch --locked
cargo fmt --all --check
cargo build --offline --locked
cargo clippy --offline --locked --all-targets -- -D warnings
cargo test --offline --locked
cargo doc --offline --locked --no-deps
```

The [Stage 1 guide](docs/stage1.md) names the implemented tests and remaining coverage.
The [validation guide](docs/validation.md) retains the broader acceptance specifications.

Also run the existing hygiene gates:

```console
py check_license.py
py scripts/private_material_scan.py
py scripts/docs_linkcheck.py
gitleaks dir . --config .gitleaks.toml --no-banner --redact --exit-code 1
git diff --check
```

Use `python` or `python3` where `py` is unavailable. The new
[Rust workflow](.github/workflows/rust.yml) runs on main pushes and pull requests alongside
the existing [repository hygiene](.github/workflows/repo-hygiene.yml) and
[DCO](.github/workflows/dco.yml) workflows. They provide build and repository checks, not a
qualified runtime. No package is published or service deployed by these workflows.
Local checks do not imply hosted CI success. See [CONTRIBUTING.md](CONTRIBUTING.md).

## The platform

| Repository | Plane | Role |
|---|---|---|
| [iokaio/munarium-platform](https://github.com/iokaio/munarium-platform) | hub | Architecture, normative contracts, decision records, roadmap and composition evidence for the whole platform |
| [iokaio/munarium](https://github.com/iokaio/munarium) | foundation (mediation) | Munarium Server: governed memory, the append-only ledger, and the Server client libraries |
| [iokaio/munarium-matrix](https://github.com/iokaio/munarium-matrix) | foundation (mediation) | Munarium Matrix: governed, read-only structured evidence from enterprise data sources |
| [iokaio/munarium-registry](https://github.com/iokaio/munarium-registry) | authority | Inventory of agents, tools, manifests, and policy bundles |
| [iokaio/munarium-harness](https://github.com/iokaio/munarium-harness) | agent | SDKs that make the governed path easy for honest agents |
| [iokaio/munarium-warden](https://github.com/iokaio/munarium-warden) | authority | Workload identity, delegation, just-in-time credentials, kill switches |
| [iokaio/munarium-gate](https://github.com/iokaio/munarium-gate) | mediation | Policy decision and enforcement point for every tool call |
| [iokaio/munarium-gateway](https://github.com/iokaio/munarium-gateway) | mediation | Model-call mediation: routing, BYOK, budgets, screening |
| [iokaio/munarium-council](https://github.com/iokaio/munarium-council) | authority | Approvals, policy lifecycle, ratified governance transitions |
| [iokaio/munarium-sentinel](https://github.com/iokaio/munarium-sentinel) | assurance | Telemetry, anomaly detection, circuit breakers, incident replay |
| [iokaio/munarium-assure](https://github.com/iokaio/munarium-assure) | assurance | Control-framework mapping and evidence packs |
| [iokaio/munarium-console](https://github.com/iokaio/munarium-console) | assurance | One interface for approvers, operators, and auditors |
| [iokaio/munarium-clients-publish](https://github.com/iokaio/munarium-clients-publish) | tooling | The one place Munarium client packages are built for release and published from |
| [iokaio/munarium-demo](https://github.com/iokaio/munarium-demo) | examples | Munarium Demo: working applications and bundled datasets for evaluating the foundation |

The development tool VCP ([iokaio/vcp](https://github.com/iokaio/vcp)) is separate: not one of the
nine components and not a runtime dependency for adopters. Ioka's private repositories hold
planning material awaiting publication review and the proprietary Matrix analytics adapters;
nothing from them is copied into a public repository without that review.

## Licensing

Apache-2.0 ([LICENSE](LICENSE), [NOTICE](NOTICE)). The names are not part of that grant:
[TRADEMARK.md](TRADEMARK.md) says what you may do without asking, which is most things. There is
no proprietary edition of this component and none is planned; a capability that arrives later is
deferred roadmap work, not a commercial restriction.

## Contributing, support, security

Signed-off pull requests, no CLA ([CONTRIBUTING.md](CONTRIBUTING.md)). Questions go to Discussions,
defects and design findings to Issues, and suspected vulnerabilities to the private channel
[SECURITY.md](SECURITY.md) names, never a public issue. What is and is not supported:
[SUPPORT.md](SUPPORT.md). Conduct: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Release history,
such as it is: [CHANGELOG.md](CHANGELOG.md).
