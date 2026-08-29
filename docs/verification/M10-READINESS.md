# M10 Readiness Record

## Current result

`M10_NOT_READY`  
`PRODUCTION_AUTHORITY_NONE`  
`HOLD_NOT_READY`

This record describes current proof coverage. It is not a deployment approval, production receipt, security sign-off, or amendment to the pre-freeze specification.

## Proven in the local WSL2 rehearsal

| Boundary | Evidence status |
|---|---|
| Frozen SPEC-3.12 source bytes and SHA-256 | Proven |
| Bounded raw JSON scan before typed decode | Unit proven |
| Duplicate decoded object-key rejection | Unit proven |
| Canonical identifiers and lowercase SHA-256 text | Unit proven |
| Exact registered-asset money parsing without floats | Unit proven |
| Complete typed capability lattice comparisons | Unit proven |
| Immutable evaluation snapshot | Unit proven |
| Bounded policy IR with explicit default-deny compilation | Unit proven |
| Current entitlement and complete revocation snapshot prerequisites | Unit and pipeline proven |
| Evidence issuer/provenance allowlist and exact object digest checks | Unit and pipeline proven |
| Trust resolution with effective revocation winning | Unit and pipeline proven |
| Unknown/stale/unsupported state never becomes allow | Unit proven |
| Branch-local delegation traversal and semantic-cycle denial | Unit proven |
| Deterministic in-memory receipt issuance and replay | Unit proven |
| Every modeled dependency revalidated before finalization | Unit and PostgreSQL rehearsal proven |
| Two synchronization sequences assigned under row locks | PostgreSQL rehearsal proven |
| Decision and database finalization witness inserted atomically | PostgreSQL rehearsal proven |
| Exact idempotent retry returns the same witness without another sequence | PostgreSQL rehearsal proven |
| Changed semantic input under the same idempotency key | Denied |
| Sequence exhaustion | Denied before durable finalization |
| Wrong tenant and absent tenant | Denied |
| Direct runtime-role writes | Denied |
| One-shot internal mutation race | Exactly one winner proven |
| Payload/target digest mutation after grant | Denied |
| Mutation target and grant updates require exact one-row effects | PostgreSQL rehearsal proven |
| Mutation generation and revocation-epoch bump with immutable event | PostgreSQL rehearsal proven |
| Deferred execution requires a valid decision, exact payload, and online high-risk revalidation | Unit proven |
| Shadow comparison remains dimension-by-dimension without aggregate score | Unit proven |
| Postgres service state | tmpfs only; teardown proven |
| Postgres network | internal network and loopback-only host bind proven |
| Registry or production endpoint contact | None configured or contacted by the runner |
| Four-service local readiness (PostgreSQL, NATS/JetStream, MinIO, Zitadel) | Durable readiness packet proven; business-operation semantics remain open |

## Still open

1. A production Rust persistence adapter using the selected SQL client.
2. Exact Rust receipt bytes inserted before commit in the same transaction that assigns both database sequences.
3. Cross-language replay identity between Rust canonical receipt bytes and the PostgreSQL durable record.
4. Production-grade schema migration/rollback rehearsal against the chosen deployment topology.
5. Live Vault credential leasing, renewal, deadline-safe pool rotation, and failure recovery.
6. Transport, identity-provider, rate-limit, and live HTTP proofs.
7. Restore proof, backup policy, operational runbooks, alert delivery, and incident review.
8. Independent security review and independent evidence adjudication.
9. Complete M9 adversarial corpus and every milestone family enumerated in SPEC-3.12.
10. Full undisclosed reviewer adjudication and formally accepted pilot threshold; the prerequisite corpus is evidence input, not a threshold.
11. Any production deployment, customer admission, credential transition, or release authorization.

No open item is converted into a pass by this rehearsal.
