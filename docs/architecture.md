# Munarium Harness implementation architecture

**Proposed design; scaffold only.** Based on section 11 of the
[platform plan, revision 4](https://github.com/iokaio/munarium-platform/blob/main/docs/platform-plan.md), with lifecycle and failure rules in
sections 17–19 and 22. See the hub's
[scaffold decision proposal](https://github.com/iokaio/munarium-platform/blob/main/docs/decisions/0001-scaffold-boundaries.md)
for the distinction between local interfaces and normative contracts.

## Responsibility and current boundary

Client-side proposal building, typed outcome retrieval, and refusal diagnostics. Harness belongs to the **agent plane**.
The crate declares interfaces only: no concrete implementations, serialization,
network listeners, persistence, service authentication or target operations exist.

The associated input, output and error types are intentionally unspecified.
These are proposed in-process seams for implementation work, not a released Rust API
or a second definition of the shared wire contract. A trait signature does not enforce
the trust assumptions below. Async runtime, transport and storage choices remain open.

## Module map

| Source | Proposed interface | Responsibility |
|---|---|---|
| [proposal](../src/proposal.rs) | `ProposalBuilder` | This is client convenience. Canonicalization must follow the future hub vectors and Gate independently validates the request. |
| [client](../src/client.rs) | `ActionClient` | No default retry behavior is provided. Wire types and transport are pending the hub contract. |
| [recovery](../src/recovery.rs) | `OutcomeReader` | Lookup must not resubmit. Unresolved outcomes are investigation items, not retryable transport failures. |

## Planned flow and state ownership

Build a proposal with task, operation identity and evidence references → submit through the native Action API → present typed outcome → query existing operation for progress or investigation. No client-generated hash or local check substitutes for Gate validation.

Own client configuration and local correlation needed for recovery. Persist stable operation identity in the calling application's state. Store no target credential and no authoritative approval, policy, or outcome history in the SDK.

## Dependencies and failure behavior

| Dependency | Required input or service | Failure rule |
|---|---|---|
| Hub / Gate | Canonicalization vectors and native Action API outcome contract | Reject ambiguous or unsupported forms; do not implement private wire variants. |
| Gate | Decision and recorded execution outcomes | Ambiguous submission is not permission to resubmit; recover by stable operation reference. |
| Server / Matrix evidence | References carried into the proposal | References are not proof of a model's complete information lineage. |
| Application / framework | Task and stable business-operation identity | An adapter cannot drop a required obligation or invent a new retry identity. |

No dependency is linked into this scaffold. Supported contract versions are **none**.
Future adapters must consume a reviewed, versioned contract and identify its digest;
a floating hub branch is design context, never deployment authority.

## Threat assumptions

Treat agent code, supplied content and self-reported identity as untrusted.
Host administrators, release roots and required signing authorities remain explicit
trust assumptions of a qualified deployment. Process separation alone does not prove
independent administration.

| Threat | Required control to implement and test |
|---|---|
| Compromised or modified client | Controls reside outside the SDK; service validation remains mandatory. |
| Transport ambiguity and generic retry wrappers | Stable operation reference, distinct outcomes, read-only recovery lookup. |
| Cross-tenant diagnostics or binding drift | Sanitized refusal details and shared versioned contract vectors. |

The [validation specification](validation.md) connects these requirements to the hub
invariants. No test evidence is implied by this design.

## Decisions needed before implementation

Select one practical application client after the first reference application is chosen. Rust fixtures precede a broad language matrix. Decide versioned generation and transport error handling only after the hub contract is accepted.

A cross-component semantic change starts in a hub decision record. Keep publication,
activation and component implementation separate. Use expand, migrate, remove for
future breaking contract changes; never duplicate hashing, identity or grant rules.

## Deferred scope

Broad language support and framework adapters before one client and its conformance fixtures are useful.

The [implementation plan](implementation-plan.md) sequences the first useful increment.
No deployment recipe, service port or live-provider configuration is supplied at this stage.
