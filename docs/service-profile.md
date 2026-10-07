# Stage 1 service clients and integration

Rust's `https::HttpsTransport::new(endpoint, identity_pem, ca_pem, chain_callback)`
and Python's `HttpsTransport(endpoint, ssl_context, chain_callback)` implement the
existing typed decision client. Python requires a certificate-validating context
with hostname checking; load its enrolled client certificate/key with
`SSLContext.load_cert_chain`. These APIs do not obtain operator or target credentials.
The callback supplies original signed Warden evidence, refreshed when necessary.

Retain a `Proposal` before the first submission. Transports send once, use no proxy
or redirect, bound response bytes and return `Unresolved` on transport ambiguity.
Recover with `Client.lookup(original_proposal)`; it never falls back to submission.
The client checks the returned tenant, operation ID and original request digest.
Recorded pre-evaluation refusals are distinct from unresolved requests (`Error::Refused`
in Rust, `Refused` with sanitized reasons in Python). `replay` is also read-only.

The [network test](../tests/network/test_services.py) runs actual Server, Warden,
Registry and Gate processes with separate certificates, temporary operator/provider/
publisher keys and no target credentials. It exercises candidate restart, invalid
provider/signature/tenant, REF-01 allow/replay, fresh-assertion recovery, another actor's
refused lookup, missing lineage, current revocation and unavailable authority.
A certificate-checking test proxy loses one acknowledgement after real Server archive
commit. Gate restarts with the evaluator absent: lookup and exact recovery still work,
proving that recovery did not evaluate again. The proxy is test fault injection only.

Build the four service binaries from the coordinated workspace using locked Cargo
dependencies. Install Server's Python SDK with `pip install -e
../munarium/clients/python[dev,platform-test]` into a test environment. Then run:

```console
python scripts/run_services.py --workspace WORKSPACE_PARENT --opa PATH_TO_PINNED_OPA --output target/stage1-runs/unique-memory.json
python scripts/run_services.py --workspace WORKSPACE_PARENT --opa PATH_TO_PINNED_OPA --database postgres --output target/stage1-runs/unique-postgres.json
```

The PostgreSQL profile requires `MUNARIUM_PLATFORM_TEST_DATABASE_URL` pointing to an
owned disposable pgvector database. The runner records exact source inventories,
dirty states, binary/evaluator hashes, test command, output digest and exit status.
It never records the database URL, runtime keys or tokens. Attempt paths must be new.
Normal test cleanup stops owned processes and deletes their temporary keys/configs;
investigate and account for those resources after a runner timeout.

Both profiles passed locally on Windows amd64, 6 October 2026. The existing
[library composition](stage1.md) separately covers 13 case groups and the unchanged
identity/canonical vectors. A read-only CI workflow accepts exact reviewed sibling
commit SHAs and runs the memory service profile; no remote run is claimed here.
The native evaluator is currently implemented and tested only for its documented Windows profile.
Published immutable pins, human contract acceptance, independent review and production
qualification remain open; passing local tests does not close those gates.
