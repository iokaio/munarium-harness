# Security

Do not file a vulnerability as an issue or a pull request.

Report a suspected vulnerability in anything in this repository privately, by either route:

- GitHub's private vulnerability reporting ("Report a vulnerability" under the Security tab), or
- email to **info@ioka.io** with "security" in the subject.

Say what you found, where, and how to reproduce it. Do not include live credentials, customer data,
or a proof of concept run against a system you do not operate. You will get an acknowledgement
within two business days, and a fix, or a recorded decision, on the affected path before any related
release. Credit is given if you ask for it.

## Supported versions

Munarium Harness has no release. Until the first tagged release, `main` is the only line and a fix
lands there. Once releases exist, security fixes go to the current minor release and to the previous
one for six months after its successor ships; an older release gets a fix only where the
vulnerability is in a contract it still speaks.

A finding in the design is welcome now, through the same private channel if it has security
consequences and as an ordinary issue otherwise. The threat model this component is built against
is in [README.md](README.md) and, for the platform as a whole, in the hub
([iokaio/munarium-platform](https://github.com/iokaio/munarium-platform)).

## What matters most here

As runtime behavior is implemented, these are the classes of finding taken most seriously and most
quickly:

- **Two clients that mean different things by the same action**: canonical request bytes, hashes, error codes or outcome handling that diverge between languages.
- **A client that encourages repetition of an action that may already have occurred**: an unresolved outcome surfaced as a generic exception, a retry helper that redispatches, or an outcome vocabulary that collapses completed and unresolved.
- **Diagnostics that disclose another tenant's policy or sensitive evidence** while explaining a refusal.
- **A framework or protocol adapter that silently degrades the contract**: an obligation it cannot represent, a request binding it does not preserve, or a token it forwards where the MCP authorization specification says it must not.
- **Generated bindings that do not identify the contract digest they were generated from.**

## What is deliberate, and is not a defect

- **Harness is not a security boundary.** It runs inside the untrusted agent plane. Gate, Server, Warden and Council verify every request even when Harness is bypassed, modified, or absent, so "an agent can call Gate without Harness" or "an agent can patch the client" describes the design. A finding is something the client does that makes an honest agent less safe or a dishonest one more convincing, not the absence of enforcement inside the client.
- **Evidence references carried by the client do not prove the model's information lineage.** A model can combine uncited material with cited material; authority-bearing fields are verified by Gate or its connector against an authoritative source.

When a local development profile exists, its test identity provider, test broker, disposable target
and generated sample credentials are development conveniences confined to that profile. They are
not vulnerabilities in themselves. A path by which they reach a production deployment unnoticed is.

## Findings that cross components

A contract ambiguity that lets two components disagree about authority, a canonicalization
difference between clients, or a gap between what a release advertises and what its evidence
supports is still a security finding. Report it here, or to any other Munarium repository, through
the same private channel; it is routed to the hub and the affected repositories together. Do not
open a public issue for it in the hub.

## Secrets

If you have committed a token or key, treat it as compromised: rotate it first, then report it.
