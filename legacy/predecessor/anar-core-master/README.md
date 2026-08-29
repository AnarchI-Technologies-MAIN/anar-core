# Anar-Core v0.1

Anar-Core is AnarchI's identity and current-authority kernel. Version 0.1 is a
freeze candidate, not a frozen release. It intentionally owns only the minimum
authoritative spine needed to replace pre-Anar-Core authorization seams without
absorbing Broker, Vault, product policy, safety policy, billing, or legal
authority.

## Authority model

```text
Identity
├── Personal Account ── Account Session
└── Membership ── Organization ── Tenant
        └── Organization Session ── AuthorizedSubject
                                  └── Consumer Handoff + Hydration References
```

A membership owns organization-scoped authorization and entitlement generation
numbers. Roles, entitlements, policies, adapters, and operations are stable,
versioned definition references. An organization session is derived from an
active account session and an active membership; it never has independent
authority.

The Broker remains responsible for bounded executable capabilities. Anar-Core
and the Broker must agree on the normalized shared boundary contract. A mismatch
fails closed.

## v0.1 guarantees

- Stable typed identifiers distinguish identities, accounts, memberships,
  organizations, tenants, sessions, definitions, bindings, and handoffs.
- Passwords are Argon2 hashes. Verification, reset, session, MFA, invitation,
  and handoff bearer material is persisted only as SHA-256 digests.
- Email verification, password-reset challenges, invitations, MFA receipts,
  recovery codes, and consumer handoffs are single-use state transitions.
- Account sessions require an active identity, account, verified email, active
  credential, current credential revision, unexpired session, and exact bearer.
- Organization sessions require an active parent account session, active
  membership, matching identity/account/organization/tenant graph, current
  authority generations, current credential revision, and exact bearer.
- An organization session expires no later than its parent account session.
- Membership suspension, departure, or revocation invalidates its organization
  sessions and pending consumer handoffs without revoking unrelated account or
  organization sessions.
- Password or email credential changes revoke account-derived authority.
  Signing out revokes only authority derived from that account session.
- Adapter grants bind exact adapter, operation, entitlement, policy-definition,
  authority-generation, and canonical resource-scope facts.
- Hydration exposes references and versions, never secret values.
- SQLite writes that consume one-use authority use immediate transactions;
  cross-connection race tests prove that only one consumer wins.
- The schema declares `anar-core.v0.1` revision `9`. Foreign contracts, invalid
  revisions, and future revisions are refused before migration writes occur.

## Enforced boundaries

The following methods are privileged kernel administration surfaces and must be
called only by a trusted service layer: direct identity/account/organization
creation, definition creation, invitation issuance, grant mutation, membership
state mutation, hydration-reference mutation, and Cloud Spine bootstrap. This
library does not authenticate an administrator for those calls and must not be
mounted directly as a public API.

User-facing account operations require their documented bearer, password,
one-use challenge, or MFA proof. Derived organization authority is checked again
when projected or authenticated; possession of a stale row is not authority.

`anar_core_contracts` is included in this distribution so the running kernel and
its boundary projections use the same definitions. A consumer must compare the
exact contract facts and fail closed on disagreement.

## Intentionally out of scope

Version 0.1 does not provide:

- Broker capability issuance or execution
- Vault secret storage, retrieval, or rotation
- product, safety, billing, payment, or legal policy decisions
- token or cryptocurrency systems
- AdForge execution or product integration
- HTTP routes, UI, email delivery, rate limiting, abuse prevention, CAPTCHA, or
  account-enumeration masking
- database encryption, key management, backup orchestration, replication,
  multi-region consensus, or hosted operations
- a v0.2 roadmap or compatibility promise beyond the v0.1 contract

## Security assumptions

- The SQLite database file, WAL, and backups are protected by operating-system
  permissions and storage encryption. Anar-Core does not encrypt the database.
- The host clock is trustworthy enough to enforce expiry windows.
- The process supplying privileged kernel calls is authenticated, authorized,
  and validates its own administrative intent.
- MFA broker-attestation rows originate only from the trusted Broker and remain
  bound to the exact account, account session, authenticator, purpose, and expiry.
- Runtime dependencies are obtained from a trusted package source and deployment
  environments constrain filesystem and process access.
- Schema migration is run against a recoverable backup. Future and foreign
  schemas are refused; migration is forward-only within `anar-core.v0.1`.

## Verification

The project uses the Python standard-library test runner; no test framework is
required.

```text
python -m unittest discover -s tests -v
python -m compileall -q anar_core anar_core_contracts tests
```

The suite covers success paths, failure paths, stale authority, credential and
generation drift, purpose and session binding, one-use replay, cross-connection
races, legacy schema migration, foreign-key integrity, schema forward-version
refusal, and contract normalization.

## Build and reproducibility

The package targets Python 3.12 and newer, uses the build backend pinned in
`pyproject.toml`, and ships both `anar_core` and `anar_core_contracts`. A clean
wheel build and clean-target installation should be verified for every freeze
candidate.

For a byte-stable wheel, set the same fixed build epoch for every build before
running the wheel command:

```text
SOURCE_DATE_EPOCH=1704067200 python -m pip wheel --no-deps --no-build-isolation .
```

Two candidate builds made with that epoch must have the same SHA-256 digest.

The source tree can be reproduced exactly from a SHA-256 manifest. Runtime
dependency resolution is not byte-for-byte reproducible from `pyproject.toml`
alone because the supported Argon2 dependency is a bounded range and its
platform-specific transitive wheels may differ. A deployment lockfile or
artifact digest is therefore required before production promotion.
