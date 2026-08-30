# Anar-Core vNext

This repository is the isolated implementation workspace for the Anar-Core current-authority substrate described by the frozen SPEC-3.12 baseline.

## Current authority state

```text
SPECIFICATION        FROZEN SPEC-3.12 BASELINE
IMPLEMENTATION       CONDITIONAL PASS
M10 HARD FREEZE      NOT READY
PRODUCTION AUTHORITY NONE
PRODUCTION MUTATION  NONE
```

The specification is implementation input, not proof that a live authority service exists. No code, fixture, receipt, passing test, repository access, historical role, or successful secret-broker operation independently creates authority.

## Working boundary

Anar-Core resolves current technical authority for typed principals, internal organizations, memberships, organization units, role and policy bindings, entitlements, bounded delegations, guardian reductions, purpose-bound elevation, external assertions, revocations, authority contexts, and effective capability decisions.

It does not own product workflow, CAL translation, secrets, provider credentials, execution, evidence bodies, product billing, or legal authority.

## Source preservation

- `docs/specification/` preserves the supplied SPEC-3.12 bytes unchanged.
- `evidence/source-archives/` preserves the supplied predecessor archives unchanged.
- `legacy/predecessor/` is a byte-derived inspection copy. It is migration evidence and is excluded from the vNext runtime path.
- `proof/` contains transition receipts, discrepancy receipts, manifests, and verification outputs.

## Build posture

The first operational target is a loopback-only WSL2 rehearsal. Production deployment and consumer cutover require separate authority and evidence.

