# SPEC-3.0-Anar-Core-vNext-Authority-Substrate

**Status:** Architecture baseline locked; **pre-hard-freeze**  
**Purpose:** Implementation-grade redesign specification for Anar-Core vNext  
**Freeze rule:** This document is stable enough to implement against, but it is intentionally **not** the final hard freeze. A dedicated adversarial back-and-forth hardening pass must occur before the frozen release candidate is minted.

---

## Background

Anar-Core began as the current-authority boundary for identities, organizations, memberships, roles, entitlements, sessions, hydration references, and adapter/product handoffs. The existing implementation already contains several strong properties that must be preserved:

- identity is distinct from account state;
- organization membership is explicit;
- organization-scoped sessions are derived rather than ambient;
- authority and entitlement generations are versioned;
- current-state revalidation is performed rather than trusting historical session material;
- stale authority fails closed;
- secret values remain outside Anar-Core;
- privileged administration is separated from ordinary runtime access;
- historical records survive revocation.

The larger AnarchI platform has since clarified the intended architecture:

```text
DOMAIN / FOREIGN WORLD
        ↓
CERBERUS MEMBRANE / CAL
        ↓
ANAR-CORE AUTHORITY RESOLUTION
        ↓
CERBERUS ORCHESTRATION
        ↓
BROKERED / BOUNDED EXECUTION
        ↓
OBSERVED EFFECT / RECEIPTS
```

The membrane translates domain-specific operations into CAL. Anar-Core does **not** need to understand Claw Royale, student grading, finance, property management, AdForge campaigns, Recoveries opportunities, marketplace products, blockchain protocol semantics, or vendor APIs. It resolves current authority over normalized capabilities and bounded resources.

Two product seams materially refined the vNext model:

1. **AdForge** exposed the organization/team seam:
   - organization units/groups;
   - scoped guests/client approvers;
   - team observation permissions;
   - purpose-bound access to sensitive content;
   - human approval;
   - service/autopilot principals;
   - queue-time vs execution-time authority;
   - organization-level hydration and revocation.

2. **Recoveries** exposed the high-consequence seam:
   - human, service, workload, agent, and device principals;
   - exact financial constraints;
   - external state/evidence satisfying policy without granting authority;
   - deferred execution requiring fresh authorization;
   - offline intent that must fail closed;
   - independently bounded service identities;
   - event causation without event-derived ambient authority.

The resulting architectural charter is:

> **Anar-Core is the authoritative current-state resolver for principals, organizational relationships, memberships, organization-unit relationships, delegations, entitlements, guardian relationships, policy bindings, revocations, trusted external assertions, authority contexts, and effective capability decisions.**

Anar-Core explicitly does **not** own:

- product workflow state;
- package/adapter definitions;
- CAL translation;
- marketplace billing history;
- secrets;
- provider credentials;
- execution;
- evidence observation;
- domain-specific objects such as campaigns, packets, payments, queues, messages, goals, or performance records.

The governing system invariant is:

> **Historical authority material, external assertions, entitlements, signatures, approvals, tokens, sessions, and cached state may contribute evidence to a decision; none independently establish current execution authority.**

---

## Requirements

### Must Have

- **M1 — Current-state authority resolution.** Every consequential decision must be evaluated against current authoritative state, not merely historical session claims.
- **M2 — Principal model.** Human, agent, service, workload, and device principals must be first-class and must not be represented as fake personal users.
- **M3 — Organization isolation.** Internal `organization_id` is the sole tenant-authority identifier. External provider organization IDs are provenance/mapping data only.
- **M4 — Membership lifecycle.** Memberships must support activation, suspension, revocation, bounded validity, membership classes, and generation/version invalidation.
- **M5 — Organization units.** Teams/groups/divisions must exist as generic authority-scoping units without importing product-specific goals or workflow semantics.
- **M6 — Resource-scoped capabilities.** Authority must be expressible as capability + organization + resource scope + effect scope + constraints.
- **M7 — Role indirection.** Roles must remain grouping/binding constructs. Role names must never become magical authority.
- **M8 — Entitlement separation.** Commercial/package entitlement, organization availability, membership entitlement, and runtime authority must remain distinct concepts.
- **M9 — Delegation.** Delegation must be first-class, bounded, revocable, expiring, auditable, and unable to exceed the delegator's delegable authority.
- **M10 — Guardian/family relationships.** Guardian relationships must participate in authority reduction without becoming product-specific parental-control logic.
- **M11 — Policy engine.** Anar-Core must deterministically evaluate current principal, organization, membership, bindings, delegations, entitlements, evidence, revocations, risk facts, runtime context, and constraints.
- **M12 — Policy evidence.** External product or platform state may satisfy policy only through typed, digest-bound assertions. External state does not directly grant authority.
- **M13 — Exact financial constraints.** Currency and exact-decimal limits must be native authority constraints. Floating-point money is prohibited.
- **M14 — Purpose-bound elevation.** Sensitive administrative access must support short-lived, reason-bound, auditable elevation instead of permanent omniscience.
- **M15 — Authority contexts.** Authenticated subjects must resolve to bounded authority contexts for one active organization context per request/decision.
- **M16 — Fail-closed offline behavior.** Offline clients may preserve drafts, evidence, intent, and pending actions but may not silently preserve consequential execution authority.
- **M17 — Effect-time reauthorization.** Deferred, queued, retried, scheduled, or reconciled effect-bearing work must obtain a fresh authority decision before execution.
- **M18 — Decision receipts.** Every material decision must produce an immutable receipt binding the exact request, policy/evidence versions, current-state generations, constraints, and outcome.
- **M19 — Capability envelope.** `ALLOW` decisions must produce a bounded effective capability envelope suitable for CERBERUS consumption.
- **M20 — Revocation propagation.** Membership, delegation, entitlement, package/trust, guardian, organization, principal, or authority-context revocation must invalidate future decisions and stale reusable authority.
- **M21 — No adapter/domain ownership.** Adapter definitions, operation definitions, protocol-specific semantics, and product-specific bootstrap grants must move out of Anar-Core.
- **M22 — Product hydration separation.** Anar-Core determines what a product may hydrate; it does not load or own product data.
- **M23 — Append-oriented security history.** Security-relevant lifecycle events must remain reconstructable after projection rebuilds.
- **M24 — Migration preservation.** Existing correct identity, membership, generation, revocation, and live-revalidation behavior must be evolved rather than discarded.
- **M25 — Deterministic canonical decision material.** Decision inputs and receipts must have an explicit canonical hashing profile aligned with CAL boundary semantics.
- **M26 — Observability without content leakage.** Operational-observation capabilities must be distinguishable from content-reading capabilities.
- **M27 — No implicit authority from events.** Event presence, queue admission, workflow state, approval records, or previous decisions must not become ambient authority.
- **M28 — External trust facts are inputs only.** Registry trust, package integrity, publisher verification, and revocation facts may narrow or block authority but may not directly grant it.

### Should Have

- **S1 — Policy compilation.** Human-authored policy should compile into a typed deterministic policy IR before production evaluation.
- **S2 — Device binding.** High-risk authority contexts should optionally bind to a device/workload identity.
- **S3 — Risk-tier freshness.** Higher-risk capabilities should require fresher authority state and shorter envelope lifetimes.
- **S4 — Organization relationships.** Parent/child, affiliate, managed-service, and delegated-administration relationships should be supported without implicit cross-org authority.
- **S5 — Delegation chains.** Bounded delegation chains should be representable with explicit maximum depth.
- **S6 — Capability decision explainability.** Denials and narrowing should produce machine-readable reason codes without leaking unrelated tenant state.
- **S7 — Local projection caches.** Products may cache authority projections only with explicit version/watermark checks.
- **S8 — External assertion issuer policy.** Policy must constrain which service/principal is allowed to assert each external evidence type.
- **S9 — Emergency deny controls.** Organization and platform safety policy should support fast global or scoped deny switches.
- **S10 — Decision replay harness.** Frozen inputs should replay to byte-identical decision receipts.

### Could Have

- **C1 — Explicit low-risk offline leases.** Short-lived, resource-scoped, device-bound offline leases may be added later for narrowly defined low-risk/read-only capabilities.
- **C2 — Federated authority queries.** Anar-Core may later consume signed authority facts from separately administered trust domains.
- **C3 — Hardware-backed principal keys.** Workload/device identities may later bind to TPM/WebAuthn/secure-enclave credentials.
- **C4 — Policy simulation mode.** Administrators may test proposed policy versions against historical decisions without activating them.
- **C5 — Formal policy linting.** Detect shadowed rules, unreachable allow branches, contradictory constraints, and unbounded delegation.

### Won't Have in vNext Core

- **W1 — Product workflow engines.**
- **W2 — Marketplace billing ledger.**
- **W3 — Secret storage.**
- **W4 — Adapter execution.**
- **W5 — CAL domain translation.**
- **W6 — Evidence collection/observation.**
- **W7 — Product messaging, campaign, payment, queue, performance, or asset stores.**
- **W8 — Arbitrary embedded scripting in policy.**
- **W9 — Universal "admin" bypass.**
- **W10 — Automatic authority inheritance from purchase, install, approval, event, token, or signature.**

---

## Method

### 1. Core authority equation

An effective capability is always an intersection, never a union of ambient grants:

```text
effective capability
=
requested CAL capability
∩ principal validity
∩ active organization context
∩ membership scope
∩ organization-unit bindings
∩ role/policy bindings
∩ entitlement availability
∩ delegation bounds
∩ guardian/family policy
∩ platform safety policy
∩ external trust/revocation facts
∩ required policy evidence
∩ runtime constraints
```

Anything unresolved, stale, contradictory, unsupported, expired, revoked, or outside scope causes narrowing, `REQUIRE_APPROVAL`, or `DENY` according to explicit policy. Unknown authority-relevant semantics never default to `ALLOW`.

### 2. Architectural boundaries

```plantuml
@startuml
skinparam componentStyle rectangle

actor "Human / Agent / Service / Device" as Actor

component "Product / Foreign System" as Product
component "CAL / Membrane" as CAL
component "Anar-Core vNext" as AC
component "CERBERUS" as Cerberus
component "Broker / Vault" as Broker
component "Execution Target" as Target
component "Evidence / Observation" as Evidence
component "Registry / Marketplace" as Registry

Actor --> Product
Product --> CAL : domain intent
CAL --> AC : normalized capability request
Registry --> AC : trust / entitlement / revocation facts
Product --> AC : policy evidence refs
AC --> Cerberus : effective capability envelope
Cerberus --> Broker : bounded execution request
Broker --> Target
Target --> Evidence
Evidence --> Product
Evidence --> AC : only when policy requires assertion refs

note right of AC
Owns current authority resolution.
Does NOT own product state,
secrets, adapters, or execution.
end note
@enduml
```

### 3. Principal model

`identity` remains the stable real-world/system identity concept. `principal` is the authenticated actor that participates in authorization.

```text
Identity
  └── Principal
      ├── HUMAN
      ├── AGENT
      ├── SERVICE
      ├── WORKLOAD
      └── DEVICE
```

A human may have multiple authenticators and devices. A service or workload does not require a `personal_account`.

```sql
CREATE TABLE anar_core.principals (
    principal_id UUID PRIMARY KEY,
    identity_id UUID NULL REFERENCES anar_core.identities(identity_id),
    principal_type TEXT NOT NULL CHECK (
        principal_type IN ('HUMAN','AGENT','SERVICE','WORKLOAD','DEVICE')
    ),
    canonical_name TEXT NOT NULL,
    status TEXT NOT NULL CHECK (
        status IN ('ACTIVE','SUSPENDED','REVOKED')
    ),
    authority_generation BIGINT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    suspended_at TIMESTAMPTZ NULL,
    revoked_at TIMESTAMPTZ NULL
);
```

```sql
CREATE TABLE anar_core.principal_authenticators (
    authenticator_id UUID PRIMARY KEY,
    principal_id UUID NOT NULL REFERENCES anar_core.principals(principal_id),
    authenticator_type TEXT NOT NULL,
    issuer TEXT NULL,
    subject TEXT NULL,
    public_key_fingerprint TEXT NULL,
    device_binding_ref TEXT NULL,
    status TEXT NOT NULL,
    credential_revision BIGINT NOT NULL DEFAULT 1,
    valid_from TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ NULL,
    UNIQUE (issuer, subject)
);
```

Passwords, tokens, private keys, provider secrets, or signing secrets are not stored here. Only verification material or references are stored as appropriate.

### 4. Organizations

```sql
CREATE TABLE anar_core.organizations (
    organization_id UUID PRIMARY KEY,
    canonical_name TEXT NOT NULL,
    organization_type TEXT NOT NULL DEFAULT 'STANDARD',
    status TEXT NOT NULL CHECK (
        status IN ('ACTIVE','SUSPENDED','REVOKED','ARCHIVED')
    ),
    authority_generation BIGINT NOT NULL DEFAULT 1,
    policy_generation BIGINT NOT NULL DEFAULT 1,
    entitlement_generation BIGINT NOT NULL DEFAULT 1,
    revocation_epoch BIGINT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

External tenancy identifiers are mappings only:

```sql
CREATE TABLE anar_core.organization_external_refs (
    organization_id UUID NOT NULL REFERENCES anar_core.organizations(organization_id),
    provider TEXT NOT NULL,
    external_tenant_id TEXT NOT NULL,
    provenance_json JSONB NOT NULL DEFAULT '{}',
    PRIMARY KEY (provider, external_tenant_id)
);
```

**Invariant:** no authorization query may substitute `external_tenant_id` for `organization_id`.

### 5. Organization relationships

```sql
CREATE TABLE anar_core.organization_relationships (
    relationship_id UUID PRIMARY KEY,
    source_organization_id UUID NOT NULL REFERENCES anar_core.organizations(organization_id),
    target_organization_id UUID NOT NULL REFERENCES anar_core.organizations(organization_id),
    relationship_type TEXT NOT NULL,
    status TEXT NOT NULL,
    valid_from TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ NULL,
    policy_binding_id UUID NULL,
    CHECK (source_organization_id <> target_organization_id)
);
```

Relationship existence grants no authority by itself.

### 6. Memberships

```sql
CREATE TABLE anar_core.memberships (
    membership_id UUID PRIMARY KEY,
    principal_id UUID NOT NULL REFERENCES anar_core.principals(principal_id),
    organization_id UUID NOT NULL REFERENCES anar_core.organizations(organization_id),
    membership_class TEXT NOT NULL CHECK (
        membership_class IN (
            'STANDARD','GUEST','SERVICE','EXTERNAL_COLLABORATOR','CHILD'
        )
    ),
    status TEXT NOT NULL CHECK (
        status IN ('PENDING','ACTIVE','SUSPENDED','REVOKED','EXPIRED')
    ),
    membership_generation BIGINT NOT NULL DEFAULT 1,
    valid_from TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

Membership class is metadata used by policy. It does not itself grant capabilities.

### 7. Organization units

Units are generic authority scopes.

```sql
CREATE TABLE anar_core.organization_units (
    unit_id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES anar_core.organizations(organization_id),
    unit_type TEXT NOT NULL,
    canonical_name TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, canonical_name)
);

CREATE TABLE anar_core.organization_unit_memberships (
    unit_membership_id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES anar_core.organizations(organization_id),
    unit_id UUID NOT NULL REFERENCES anar_core.organization_units(unit_id),
    membership_id UUID NOT NULL REFERENCES anar_core.memberships(membership_id),
    relation_type TEXT NOT NULL CHECK (
        relation_type IN ('MEMBER','LEAD','ADMIN')
    ),
    status TEXT NOT NULL,
    valid_from TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ NULL
);
```

Product-owned goals, performance, work hours, chat content, and queues do not belong here.

### 8. Roles

```sql
CREATE TABLE anar_core.role_definitions (
    role_definition_id UUID PRIMARY KEY,
    namespace TEXT NOT NULL,
    symbolic_name TEXT NOT NULL,
    version TEXT NOT NULL,
    status TEXT NOT NULL,
    metadata_json JSONB NOT NULL DEFAULT '{}',
    UNIQUE(namespace, symbolic_name, version)
);

CREATE TABLE anar_core.role_bindings (
    role_binding_id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES anar_core.organizations(organization_id),
    membership_id UUID NULL REFERENCES anar_core.memberships(membership_id),
    unit_id UUID NULL REFERENCES anar_core.organization_units(unit_id),
    role_definition_id UUID NOT NULL REFERENCES anar_core.role_definitions(role_definition_id),
    status TEXT NOT NULL,
    valid_from TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ NULL,
    CHECK (
        (membership_id IS NOT NULL)::int +
        (unit_id IS NOT NULL)::int = 1
    )
);
```

No policy branch may contain `IF role_name='ADMIN' THEN ALLOW`. Roles must resolve through explicit bindings.

### 9. Entitlement bindings

Marketplace/product definitions remain outside Anar-Core. Anar-Core stores current authoritative entitlement bindings by stable external reference.

```sql
CREATE TABLE anar_core.entitlement_bindings (
    entitlement_binding_id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES anar_core.organizations(organization_id),
    membership_id UUID NULL REFERENCES anar_core.memberships(membership_id),
    principal_id UUID NULL REFERENCES anar_core.principals(principal_id),
    package_ref TEXT NOT NULL,
    entitlement_ref TEXT NOT NULL,
    source_system TEXT NOT NULL,
    source_digest TEXT NOT NULL,
    status TEXT NOT NULL CHECK (
        status IN ('ACTIVE','SUSPENDED','REVOKED','EXPIRED')
    ),
    valid_from TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ NULL,
    generation BIGINT NOT NULL DEFAULT 1
);
```

Commercial purchase creates entitlement evidence; it does not directly create capability authority.

### 10. Capability references and scopes

Canonical capability definitions live in CAL/Registry. Anar-Core stores references and bindings only.

```sql
CREATE TABLE anar_core.capability_bindings (
    capability_binding_id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES anar_core.organizations(organization_id),
    capability_id TEXT NOT NULL,
    capability_version TEXT NOT NULL,
    source_type TEXT NOT NULL,
    source_id UUID NOT NULL,
    resource_scope_json JSONB NOT NULL,
    effect_scope_json JSONB NOT NULL,
    constraints_json JSONB NOT NULL,
    policy_ref TEXT NULL,
    status TEXT NOT NULL,
    valid_from TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ NULL
);
```

`source_type` may reference role binding, delegation, guardian rule, direct policy binding, or approved internal system authority. Validation must ensure the referenced source exists and belongs to the same organization.

### 11. Policy bindings and deterministic policy IR

Human-authored policies should not execute as arbitrary YAML, SQL, JavaScript, WASM, Python, or shell.

```text
Human policy source
      ↓
schema validation
      ↓
type checking
      ↓
capability/resource/effect resolution
      ↓
compiled Policy IR
      ↓
canonical hash
      ↓
production evaluator
```

```sql
CREATE TABLE anar_core.policy_bindings (
    policy_binding_id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES anar_core.organizations(organization_id),
    policy_ref TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    compiled_policy_hash TEXT NOT NULL,
    policy_ir_json JSONB NOT NULL,
    status TEXT NOT NULL,
    valid_from TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ NULL
);
```

Production evaluation must not interpret arbitrary code.

### 12. Delegations

```sql
CREATE TABLE anar_core.delegations (
    delegation_id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES anar_core.organizations(organization_id),
    delegator_principal_id UUID NOT NULL REFERENCES anar_core.principals(principal_id),
    delegate_principal_id UUID NOT NULL REFERENCES anar_core.principals(principal_id),
    capability_id TEXT NOT NULL,
    capability_version TEXT NOT NULL,
    resource_scope_json JSONB NOT NULL,
    effect_scope_json JSONB NOT NULL,
    constraints_json JSONB NOT NULL,
    max_uses BIGINT NULL,
    uses_consumed BIGINT NOT NULL DEFAULT 0,
    delegable BOOLEAN NOT NULL DEFAULT FALSE,
    max_delegation_depth SMALLINT NOT NULL DEFAULT 0,
    status TEXT NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ NULL,
    CHECK (delegator_principal_id <> delegate_principal_id),
    CHECK (uses_consumed >= 0),
    CHECK (max_uses IS NULL OR uses_consumed <= max_uses)
);
```

At issuance and use time:

```text
delegated authority
⊆ delegator's current delegable authority
```

A delegation cannot broaden capability, resource scope, effect scope, amount, duration, usage count, or delegation depth.

### 13. Guardian/family relationships

```sql
CREATE TABLE anar_core.guardian_relationships (
    guardian_relationship_id UUID PRIMARY KEY,
    organization_id UUID NULL REFERENCES anar_core.organizations(organization_id),
    guardian_principal_id UUID NOT NULL REFERENCES anar_core.principals(principal_id),
    protected_principal_id UUID NOT NULL REFERENCES anar_core.principals(principal_id),
    relationship_type TEXT NOT NULL,
    policy_ref TEXT NOT NULL,
    status TEXT NOT NULL,
    valid_from TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ NULL,
    CHECK (guardian_principal_id <> protected_principal_id)
);
```

Guardian policy may narrow authority or require approval. It may not expand authority beyond platform/org/publisher constraints.

### 14. PolicyEvidenceRef / ExternalStateAssertion

```sql
CREATE TABLE anar_core.external_state_assertions (
    assertion_id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES anar_core.organizations(organization_id),
    assertion_type TEXT NOT NULL,
    object_ref TEXT NOT NULL,
    object_digest TEXT NOT NULL,
    issuer_principal_id UUID NOT NULL REFERENCES anar_core.principals(principal_id),
    issuer_system_ref TEXT NULL,
    assertion_payload_json JSONB NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ NULL,
    revoked_at TIMESTAMPTZ NULL,
    provenance_digest TEXT NOT NULL
);
```

Examples:

```text
AdForge:
packet digest X has client approval

Recoveries:
opportunity digest Y has adjudication approval

Marketplace:
package entitlement Z is active

Registry:
artifact digest A passed review
```

Anar-Core policy may require an assertion. The assertion cannot grant authority by itself.

### 15. External trust and revocation facts

```sql
CREATE TABLE anar_core.external_trust_facts (
    fact_id UUID PRIMARY KEY,
    organization_id UUID NULL REFERENCES anar_core.organizations(organization_id),
    subject_type TEXT NOT NULL,
    subject_ref TEXT NOT NULL,
    fact_type TEXT NOT NULL,
    fact_value TEXT NOT NULL,
    source_system TEXT NOT NULL,
    source_digest TEXT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ NULL
);

CREATE TABLE anar_core.external_revocation_facts (
    revocation_fact_id UUID PRIMARY KEY,
    organization_id UUID NULL REFERENCES anar_core.organizations(organization_id),
    target_type TEXT NOT NULL,
    target_ref TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    severity TEXT NOT NULL,
    source_system TEXT NOT NULL,
    source_digest TEXT NOT NULL,
    effective_at TIMESTAMPTZ NOT NULL
);
```

### 16. Authority contexts

```sql
CREATE TABLE anar_core.authority_contexts (
    authority_context_id UUID PRIMARY KEY,
    principal_id UUID NOT NULL REFERENCES anar_core.principals(principal_id),
    organization_id UUID NOT NULL REFERENCES anar_core.organizations(organization_id),
    membership_id UUID NOT NULL REFERENCES anar_core.memberships(membership_id),

    principal_generation BIGINT NOT NULL,
    membership_generation BIGINT NOT NULL,
    organization_generation BIGINT NOT NULL,
    policy_generation BIGINT NOT NULL,
    entitlement_generation BIGINT NOT NULL,
    credential_revision BIGINT NOT NULL,

    device_principal_id UUID NULL REFERENCES anar_core.principals(principal_id),

    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ NULL
);
```

A context is a freshness-bound decision input, not eternal authority.

### 17. Capability requests

```sql
CREATE TABLE anar_core.capability_requests (
    request_id UUID PRIMARY KEY,
    authority_context_id UUID NOT NULL REFERENCES anar_core.authority_contexts(authority_context_id),

    capability_id TEXT NOT NULL,
    capability_version TEXT NOT NULL,

    resource_scope_json JSONB NOT NULL,
    effect_scope_json JSONB NOT NULL,
    requested_constraints_json JSONB NOT NULL,

    cal_semantic_hash TEXT NOT NULL,
    package_ref TEXT NULL,
    manifest_hash TEXT NULL,

    requested_at TIMESTAMPTZ NOT NULL
);
```

### 18. Decision states

```text
ALLOW
DENY
REQUIRE_APPROVAL
INSUFFICIENT_AUTHORITY
INSUFFICIENT_EVIDENCE
STALE_AUTHORITY
UNSUPPORTED_SEMANTICS
REVOKED
```

`UNKNOWN` must never be silently converted to `ALLOW`.

### 19. Capability decisions

```sql
CREATE TABLE anar_core.capability_decisions (
    decision_id UUID PRIMARY KEY,
    request_id UUID NOT NULL REFERENCES anar_core.capability_requests(request_id),

    decision TEXT NOT NULL,
    reason_codes TEXT[] NOT NULL,

    effective_resource_scope_json JSONB NOT NULL,
    effective_effect_scope_json JSONB NOT NULL,
    effective_constraints_json JSONB NOT NULL,

    evaluated_policy_hashes TEXT[] NOT NULL,
    evaluated_assertion_ids UUID[] NOT NULL,
    evaluated_revocation_refs TEXT[] NOT NULL,

    decided_at TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ NOT NULL
);
```

The effective scope may only be equal to or narrower than the request.

### 20. Decision receipts

```sql
CREATE TABLE anar_core.decision_receipts (
    receipt_id UUID PRIMARY KEY,
    decision_id UUID NOT NULL UNIQUE REFERENCES anar_core.capability_decisions(decision_id),

    principal_id UUID NOT NULL,
    organization_id UUID NOT NULL,
    membership_id UUID NOT NULL,

    capability_id TEXT NOT NULL,
    capability_version TEXT NOT NULL,

    authority_context_hash TEXT NOT NULL,
    request_semantic_hash TEXT NOT NULL,
    effective_capability_hash TEXT NULL,

    policy_bundle_hash TEXT NOT NULL,
    evidence_bundle_hash TEXT NOT NULL,
    revocation_watermark TEXT NOT NULL,

    receipt_version TEXT NOT NULL,
    canonical_receipt_bytes BYTEA NOT NULL,
    receipt_hash TEXT NOT NULL UNIQUE,

    issued_at TIMESTAMPTZ NOT NULL
);
```

### 21. Effective capability envelope

An `ALLOW` result may produce an envelope for CERBERUS:

```json
{
  "envelope_version": "1.0",
  "decision_receipt_id": "receipt:...",
  "principal_id": "principal:...",
  "organization_id": "org:...",
  "capability": {
    "id": "wallet.transaction.propose",
    "version": "1.0"
  },
  "resource_scope": {},
  "effect_scope": {},
  "constraints": {
    "currency": "USD",
    "max_amount": "500.00",
    "max_uses": 1
  },
  "issued_at": "...",
  "expires_at": "...",
  "manifest_hash": "sha256:...",
  "cal_semantic_hash": "calh1:..."
}
```

CERBERUS consumes this envelope. It does not reconstruct membership, delegation, guardian, entitlement, or policy resolution.

### 22. Native financial constraint model

Money is explicit:

```json
{
  "type": "money_limit",
  "currency": "USD",
  "max": "5000.00"
}
```

Rules:

- ISO-4217 fiat codes or registered asset identifiers are explicit.
- Exact decimals are strings with registered scale.
- No IEEE-754 floating point.
- Cross-currency authorization requires explicit FX evidence/policy; implicit conversion is prohibited.
- If currency is unknown, action fails closed.

### 23. Purpose-bound elevation

Permanent owner/admin omniscience is prohibited.

```sql
CREATE TABLE anar_core.elevation_grants (
    elevation_id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES anar_core.organizations(organization_id),
    principal_id UUID NOT NULL REFERENCES anar_core.principals(principal_id),
    capability_id TEXT NOT NULL,
    resource_scope_json JSONB NOT NULL,
    purpose_code TEXT NOT NULL,
    reason_digest TEXT NOT NULL,
    max_uses INTEGER NOT NULL DEFAULT 1,
    uses_consumed INTEGER NOT NULL DEFAULT 0,
    issued_by_principal_id UUID NOT NULL REFERENCES anar_core.principals(principal_id),
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ NULL
);
```

### 24. Offline behavior

Offline may store drafts, pending intents, evidence, exact payload digests, local provenance, and non-authoritative UI state.

Offline must not silently finalize financial effects, publication, credential changes, privileged system effects, irreversible external actions, or child-sensitive high-impact actions.

```plantuml
@startuml
start
:Load queued intent;
:Verify local payload digest;
:Authenticate principal;
:Resolve current organization context;
:Refresh membership / delegation / entitlement / policy;
:Validate required external assertions;
:Check current revocations;
if (Current authority proven?) then (yes)
  :Issue fresh decision receipt;
  :Issue bounded capability envelope;
  :Send to CERBERUS;
else (no)
  :HOLD / DENY;
endif
stop
@enduml
```

**Rule:** deferred work never inherits execution authority from queue admission.

### 25. Revocation watermark

A decision receipt includes a revocation watermark representing the latest authoritative revocation epoch/checkpoint consulted during evaluation.

This is an audit and stale-envelope detection primitive, not a replacement for current-state verification.

### 26. Monotonic narrowing

No downstream stage may broaden an Anar-Core envelope.

```text
REQUEST
      ↓ narrow
ANAR-CORE ENVELOPE
      ↓ narrow
CERBERUS DISPATCH
      ↓ narrow
ADAPTER / BROKER
```

If an adapter requires broader scope than the envelope contains, execution fails.

### 27. Evidence issuer allowlists

Policy evidence types must declare authorized issuer classes.

A client application cannot mint authoritative workflow evidence simply because it can format the assertion correctly.

### 28. Service principal effect separation

Services should be purpose-specific:

```text
recoveries.web
recoveries.outbox
recoveries.action-runner
adforge.renderer
adforge.publisher
marketplace.review-worker
registry.federation-puller
```

No generic `backend-service` principal with broad organization capability should be permitted in production.

### 29. Policy decision algorithm

```rust
fn evaluate(req: CapabilityRequest) -> Decision {
    let ctx = load_authority_context(req.context_id)?;

    require_not_expired(ctx)?;
    require_current_principal_generation(ctx)?;
    require_current_membership_generation(ctx)?;
    require_current_org_generation(ctx)?;
    require_current_policy_generation(ctx)?;
    require_current_entitlement_generation(ctx)?;
    require_current_credential_revision(ctx)?;

    require_principal_active(ctx.principal_id)?;
    require_org_active(ctx.organization_id)?;
    require_membership_active(ctx.membership_id)?;

    let requested = normalize_request(req)?;
    let candidates = collect_current_bindings(ctx, requested.capability)?;

    let delegated = validate_delegations(candidates, ctx)?;
    let entitlements = validate_entitlements(candidates, ctx)?;
    let guardian = resolve_guardian_constraints(ctx)?;
    let trust = resolve_external_trust_and_revocations(requested)?;
    let evidence = resolve_required_policy_evidence(requested)?;

    if trust.requires_deny() {
        return deny(TRUST_OR_REVOCATION);
    }

    let effective = intersect(
        requested,
        candidates,
        delegated,
        entitlements,
        guardian,
        trust.constraints(),
        evidence.constraints(),
        runtime_constraints(),
    )?;

    if effective.is_empty() {
        return deny(INSUFFICIENT_AUTHORITY);
    }

    enforce_exact_financial_constraints(&effective)?;
    enforce_resource_scope(&effective)?;
    enforce_effect_scope(&effective)?;

    issue_decision_and_receipt(effective)
}
```

### 30. Failure semantics

Authority-relevant failures are explicit:

```text
PRINCIPAL_REVOKED
ORGANIZATION_REVOKED
MEMBERSHIP_REVOKED
MEMBERSHIP_EXPIRED
AUTHORITY_CONTEXT_EXPIRED
STALE_PRINCIPAL_GENERATION
STALE_MEMBERSHIP_GENERATION
STALE_POLICY_GENERATION
STALE_ENTITLEMENT_GENERATION
CREDENTIAL_REVISION_MISMATCH
DELEGATION_EXPIRED
DELEGATION_SCOPE_EXCEEDED
ENTITLEMENT_MISSING
GUARDIAN_APPROVAL_REQUIRED
POLICY_EVIDENCE_MISSING
POLICY_EVIDENCE_STALE
POLICY_EVIDENCE_ISSUER_INVALID
EXTERNAL_REVOCATION_ACTIVE
RESOURCE_SCOPE_EXCEEDED
EFFECT_SCOPE_EXCEEDED
FINANCIAL_LIMIT_EXCEEDED
CURRENCY_UNSUPPORTED
UNSUPPORTED_CAL_SEMANTICS
OFFLINE_REAUTHORIZATION_REQUIRED
```

Error responses must not leak unrelated tenant existence.

### 31. Migration map from existing Anar-Core

| Existing concept | vNext disposition | Migration action |
|---|---|---|
| `identity` | KEEP | Preserve stable IDs |
| `personal_account` | EVOLVE | Keep human account/profile concerns separate from principal semantics |
| credential tables | EVOLVE | Convert to principal authenticators; keep secret material out |
| account/session tables | EVOLVE | Preserve authentication session; derive authority context separately |
| `organization` | KEEP | Preserve IDs; add generations/revocation epoch |
| `tenant` | REVIEW/EVOLVE | Retain only if it represents a real isolation/workspace concept |
| `membership` | KEEP/EXPAND | Add class, validity, generation, principal reference |
| `role_definition` | KEEP CONCEPT | Preserve versioning; role metadata is not authority |
| role assignment/binding | EVOLVE | Convert to role bindings |
| `entitlement_definition` | MOVE DEFINITION OUT | Registry/Marketplace owns product/package definition |
| `entitlement_grant` | EVOLVE | Convert to current entitlement bindings |
| `policy_definition` | EVOLVE | Replace symbolic refs-only model with compiled deterministic policy IR + hashes |
| `adapter_definition` | MOVE OUT | Registry/CAL owns |
| `operation_definition` | MOVE OUT | CAL/Registry owns |
| `adapter_grant_binding` | DEPRECATE | Replace with canonical capability bindings |
| hydration reference tables | EVOLVE | Retain reference discipline; product resolves actual data |
| AdForge-specific consumer handoff | REMOVE | Replace with generic capability envelope |
| Cloud-Spine-specific bootstrap grants | MOVE OUT | Registry/bootstrap configuration |
| authority generation/version logic | KEEP STRONGLY | Reuse and extend |
| entitlement generation/version logic | KEEP STRONGLY | Reuse and extend |
| current-state projection/revalidation | KEEP STRONGLY | Becomes vNext decision-engine foundation |
| single-use handoff/challenge logic | KEEP/GENERALIZE | Reuse for elevation, proof challenges, bounded handoffs |

### 32. Migration strategy

No destructive big-bang migration.

```text
Phase A
create vNext tables alongside existing model

Phase B
dual-write selected identity/membership lifecycle facts

Phase C
backfill principals, memberships, roles, entitlements

Phase D
run shadow authority decisions
old resolver vs vNext resolver

Phase E
compare decisions + reason codes

Phase F
cut CAL/CERBERUS consumers to vNext decision API

Phase G
disable legacy adapter/operation authority writes

Phase H
archive/deprecate legacy tables after replay evidence
```

Any old→new mismatch is classified:

```text
EXPECTED_NARROWING
LEGACY_BUG_EXPOSED
VNEXT_BUG
DATA_MIGRATION_DEFECT
UNRESOLVED
```

`UNRESOLVED` blocks cutover for affected capability classes.

### 33. RLS / database roles

Recommended PostgreSQL roles:

```text
anar_core_migration_owner   NOLOGIN
anar_core_api_runtime       NOLOGIN NOBYPASSRLS
anar_core_decision_runtime  NOLOGIN NOBYPASSRLS
anar_core_projection_worker NOLOGIN NOBYPASSRLS
anar_core_audit_reader      NOLOGIN NOBYPASSRLS
```

Runtime roles do not own schema objects.

Organization-scoped tables should use explicit RLS keyed to internal `organization_id`.

### 34. API surface

```text
POST /v1/authority-contexts
POST /v1/authority-contexts/{id}/revoke

POST /v1/decisions/evaluate
GET  /v1/decisions/{id}
GET  /v1/receipts/{id}

POST /v1/delegations
POST /v1/delegations/{id}/revoke

POST /v1/elevations/request
POST /v1/elevations/{id}/revoke

POST /v1/assertions
POST /v1/assertions/{id}/revoke

GET  /v1/organizations/{id}/memberships
GET  /v1/organizations/{id}/units
```

Administrative mutation endpoints require separate administrative capabilities.

### 35. Decision request example

```json
{
  "authority_context_id": "ctx_...",
  "cal": {
    "semantic_hash": "calh1:sha256:...",
    "capability_id": "recoveries.notice.send",
    "capability_version": "1.0"
  },
  "resource_scope": {
    "opportunity_refs": ["recovery:opp_123"]
  },
  "effect_scope": {
    "class": "EXTERNAL_COMMUNICATION"
  },
  "constraints": {
    "max_uses": 1
  },
  "policy_evidence_refs": [
    {
      "assertion_id": "assert_..."
    }
  ]
}
```

### 36. Decision response example

```json
{
  "decision": "ALLOW",
  "decision_id": "dec_...",
  "decision_receipt_id": "receipt_...",
  "reason_codes": ["CURRENT_AUTHORITY_PROVEN"],
  "effective_capability": {
    "capability_id": "recoveries.notice.send",
    "resource_scope": {
      "opportunity_refs": ["recovery:opp_123"]
    },
    "effect_scope": {
      "class": "EXTERNAL_COMMUNICATION"
    },
    "constraints": {
      "max_uses": 1
    },
    "expires_at": "..."
  }
}
```

### 37. Non-goals inside decisions

The decision engine must never answer product-domain questions. It answers only:

> **May this principal perform this normalized capability, against these resources, with these effects, under these bounds, right now?**

---

## Implementation

### Phase 1 — Preserve and inventory existing behavior

- Freeze current Anar-Core test corpus.
- Generate current schema inventory and authority-path map.
- Identify all product-specific constants and bootstrap grants.
- Capture golden tests for existing generation/revocation semantics.
- Capture current `project_authorized_subject()` behavior as migration evidence.
- Tag existing tables as KEEP / EVOLVE / MOVE / DEPRECATE.

### Phase 2 — Introduce vNext identity and organization spine

- Add principals.
- Add principal authenticators.
- Add organization generations and revocation epoch.
- Evolve memberships to principal-based ownership.
- Add organization-unit tables.
- Build dual-read projections without changing production authority.

### Phase 3 — Roles, entitlements, and capability bindings

- Add versioned role definitions/bindings.
- Add entitlement bindings referencing external package/product definitions.
- Introduce canonical capability references.
- Stop creating new adapter/operation definitions inside Anar-Core.
- Build migration views for legacy adapter grants.

### Phase 4 — Policy engine

- Define typed Policy IR.
- Implement policy compiler.
- Implement deterministic evaluator.
- Add exact-decimal financial constraints.
- Add policy reason-code registry.
- Add policy hash/canonicalization tests.

### Phase 5 — Delegation, guardian, elevation

- Add bounded delegations.
- Add usage/expiry/revocation semantics.
- Add guardian relationship policy reduction.
- Add purpose-bound elevation grants.
- Test privilege amplification and delegation-depth attacks.

### Phase 6 — External assertions and trust facts

- Add assertion issuer registry/policy.
- Add external state assertion storage.
- Add external trust/revocation fact ingestion.
- Ensure assertions are digest-bound and revocable.
- Ensure a valid assertion without authority still results in denial.

### Phase 7 — Authority contexts and decisions

- Add authority context issuance/revocation.
- Implement current-generation revalidation.
- Add capability request/decision/receipt persistence.
- Produce effective capability envelopes.
- Add revocation watermark.
- Add byte-stable receipt replay tests.

### Phase 8 — Offline / deferred work hardening

- Add reconnect reauthorization contract.
- Add queue-release decision flow.
- Prove stale authority cannot execute.
- Prove stale approval/evidence cannot execute.
- Add low-risk offline lease design only if separately authorized.

### Phase 9 — Shadow cutover

- Run legacy and vNext decisions side-by-side.
- Persist mismatch reports.
- Categorize every mismatch.
- Require zero unexplained allow-widening before cutover.
- Cut CAL/CERBERUS integration to vNext API.

### Phase 10 — Legacy retirement

- Disable legacy adapter/operation authority writes.
- Remove product-specific handoff code.
- Remove hard-coded AdForge/Cloud-Spine assumptions.
- Archive legacy definitions after receipt-backed migration.
- Keep historical lineage queryable.

---

## Milestones

### M1 — Schema spine
Exit criteria:
- principals and authenticators implemented;
- organizations and memberships migrated without ID loss;
- organization units implemented;
- generation semantics preserved;
- no production behavior broadened.

### M2 — Capability binding model
Exit criteria:
- roles no longer grant magical authority;
- adapter/operation definitions removed from new authority path;
- registry/CAL references used;
- entitlements separated from authority.

### M3 — Deterministic policy engine
Exit criteria:
- typed policy IR;
- exact financial constraints;
- deterministic reason codes;
- unsupported semantics fail closed;
- replay identity proven.

### M4 — Delegation / guardian / elevation
Exit criteria:
- bounded delegation;
- guardian policy reduction;
- purpose-bound elevation;
- privilege amplification tests pass.

### M5 — Assertions / trust / revocation
Exit criteria:
- product assertions are digest-bound;
- issuer authorization enforced;
- registry/revocation facts can deny/narrow but not grant;
- stale assertions fail closed.

### M6 — Authority context and decision receipts
Exit criteria:
- current generations revalidated;
- decision receipts immutable;
- effective capability envelope generated;
- revocation watermark recorded;
- CAL semantic hash bound into decision.

### M7 — Offline and deferred execution
Exit criteria:
- queue admission does not become execution authority;
- reconnect requires current decision;
- stale membership/delegation/approval blocks effect;
- offline high-risk finalization impossible.

### M8 — Shadow migration
Exit criteria:
- legacy/vNext comparison corpus executed;
- all mismatches categorized;
- no unexplained vNext authority widening;
- rollback path tested.

### M9 — Pre-freeze hardening
Exit criteria:
- architecture back-and-forth completed;
- attack tree reviewed;
- Kiln test-plan draft prepared;
- all open semantic questions resolved;
- specification amended atomically.

### M10 — Hard freeze candidate
Exit criteria:
- exact frozen spec hash;
- exact migration manifest;
- exact policy IR schema hash;
- exact API contract hash;
- exact conformance fixture set;
- no unresolved architecture findings.

---

## Gathering Results

The system is accepted only when it proves both **correct authorization** and **correct denial**.

Evaluation must include:

- valid human authorization;
- service-principal least privilege;
- agent delegation;
- scoped guest access;
- organization-unit lead/admin scoping;
- guardian-required action;
- financial-limit allow/approval/deny thresholds;
- expired delegation;
- revoked membership;
- stale authority context;
- stale entitlement generation;
- stale policy generation;
- credential revision mismatch;
- cross-organization resource request;
- external assertion with unauthorized issuer;
- external assertion for wrong object digest;
- revoked package/trust fact;
- queued work after authority loss;
- offline action reconnect after role removal;
- elevation grant expiry/replay;
- delegation amplification attempt;
- unknown CAL semantic;
- unsupported capability version;
- malformed exact decimal;
- currency mismatch;
- downstream envelope-broadening attempt.

Primary production metrics:

```text
authority decision latency
deny/allow/require-approval counts
stale-context rejection count
revocation propagation latency
delegation denial count
assertion validation failure count
offline/deferred reauthorization failure count
decision receipt replay failures
policy compilation failures
cross-org denial count
```

No single trust score should collapse these into one opaque number.

### Required pre-freeze adversarial discussion

Before hard freeze, explicitly challenge:

1. Can any token/session survive revocation longer than intended?
2. Can any product assertion become authority by accident?
3. Can a service principal impersonate a human workflow actor?
4. Can organization-unit membership bleed into another unit?
5. Can role metadata bypass policy bindings?
6. Can delegation be recursively amplified?
7. Can guardian policy expand rather than narrow authority?
8. Can money constraints be bypassed by currency/scale tricks?
9. Can queued/offline work execute after authority loss?
10. Can an external provider tenant ID be confused with internal organization authority?
11. Can stale registry trust enable a revoked package?
12. Can a decision receipt be replayed against another object digest?
13. Can an adapter broaden the effective envelope?
14. Can product hydration expose data outside the decision scope?
15. Can privileged elevation become permanent or reusable?
16. Can policy evidence be issued by the wrong service?
17. Can revocation epochs/watermarks be rolled back?
18. Can migration dual-write create contradictory authority states?
19. Can legacy adapter-grant paths remain accidentally callable?
20. Can unknown/unsupported semantics fall through to allow?

### Future Kiln alignment

After Anar-Core vNext and the larger platform architecture are frozen, Kiln should be re-evaluated against the expanded threat model. Candidate future fracture campaigns include:

```text
stale authority replay
offline-intent escalation
delegation amplification
cross-org scope confusion
publisher-key compromise
registry equivocation
manifest/behavior mismatch
federation rollback
capability-envelope tampering
guardian-policy bypass
financial-limit overflow
queued-action stale approval
service-principal privilege bleed
evidence-ref substitution
revocation propagation delay
membrane semantic smuggling
CAL downgrade attempts
```

Frankentest should remain provenance-preserving when synthesizing novel variants from these campaigns.

---

## Hard-Freeze Gate

This specification must **not** be declared hard frozen until:

```text
schema reviewed
migration mapping reviewed
decision semantics challenged
offline semantics challenged
delegation semantics challenged
guardian semantics challenged
financial constraints challenged
external assertion semantics challenged
revocation propagation challenged
legacy-cutover path challenged
Kiln fracture plan reviewed
```

At that point, amendments must be atomic:

```text
observation
→ affected invariant
→ smallest corrective change
→ focused proof
→ receipt
→ new spec hash
```

---


---

## Pre-Freeze Hardening Addendum 1

The following five findings are accepted as **P0/P1 architectural hardening requirements** and are now part of the pre-freeze baseline.

### H1 — Generation Sync Race / Stale-Context Exploitation

**Finding:** A revocation or generation change can occur after initial freshness checks but before an `ALLOW` envelope and receipt are finalized.

**Required fix:**

1. Initial evaluation may occur on a consistent read snapshot.
2. Before an `ALLOW`, `REQUIRE_APPROVAL`, or any reusable capability envelope is committed, Anar-Core must perform a **final authority freshness recheck inside the same database transaction that persists the decision and receipt**.
3. The final recheck must validate at minimum:
   - principal generation/status;
   - membership generation/status;
   - organization authority generation/status;
   - policy generation;
   - entitlement generation;
   - credential revision;
   - applicable revocation epoch/watermark;
   - delegation generation/status where applicable;
   - guardian/elevation state where applicable.
4. If any value changed since evaluation began, the decision must be discarded and return `STALE_AUTHORITY_RETRY_REQUIRED` or fail closed.
5. High/critical-risk capabilities should use `REPEATABLE READ` or stronger transaction semantics; `SERIALIZABLE` may be used where the invariant requires it. Broad organization-wide row locking is not the default because it would create unnecessary contention.
6. A decision receipt must record both:
   - `evaluation_snapshot_version`;
   - `finalization_revocation_watermark`.

**Invariant:**

> **No consequential ALLOW becomes durable unless current authority is revalidated atomically at decision finalization.**

Suggested failure code:

```text
STALE_AUTHORITY_DURING_EVALUATION
```

### H2 — Recursive Delegation Loops / Cross-Organization Amplification

**Finding:** Depth limits alone do not prevent cyclic or diamond-shaped delegation graphs from re-entering an authority path through another principal/organization tuple.

**Required fix:**

Delegation traversal must maintain:

```text
visited = Set<(principal_id, organization_id, capability_id)>
```

and a current recursion stack.

Rules:

- repeated tuple in the active traversal path → `DELEGATION_LOOP_DETECTED`;
- cross-organization delegation is denied unless an explicit organization-relationship policy authorizes that exact delegation class;
- organization relationship existence alone never authorizes cross-org delegation;
- delegation depth is counted across organization boundaries, not reset by them;
- all branches are intersected independently;
- convergence from multiple valid parents never unions scope beyond the narrowest common authorized scope;
- a child delegation may never expand capability, resource scope, effect scope, financial limit, expiry, usage count, or delegation depth.

Suggested failures:

```text
DELEGATION_LOOP_DETECTED
CROSS_ORG_DELEGATION_NOT_AUTHORIZED
DELEGATION_SCOPE_AMPLIFICATION
DELEGATION_DEPTH_EXCEEDED
```

### H3 — Financial Scale, Unicode, and Sign Manipulation

**Finding:** String-based decimal transport is necessary for exactness but is unsafe without a strict lexical and semantic normalization boundary.

**Required fix:**

Raw monetary strings must never enter policy arithmetic directly.

Edge normalization pipeline:

```text
wire string
→ ASCII-only lexical validation
→ registered currency/asset lookup
→ exact permitted scale check
→ parse to signed integer representation
→ semantic sign validation
→ typed MoneyAmount
```

For fiat-like currencies with fixed minor units:

```rust
struct MoneyAmount {
    currency: CurrencyId,
    minor_units: i128,
}
```

For assets with non-ISO decimal precision, the currency/asset registry defines exact scale.

Requirements:

- ASCII digits only: `[0-9]`;
- optional decimal point only where registry scale permits;
- scientific notation forbidden;
- leading plus signs forbidden;
- non-canonical leading zeros rejected except `0` / `0.xx`;
- Unicode digits and Unicode punctuation rejected;
- fractional precision greater than registered scale rejected, never rounded;
- negative authorization limits rejected unless the specific typed constraint explicitly permits signed values;
- `-0`, negative zero variants, NaN, Infinity, and empty strings rejected;
- upper magnitude bound enforced before conversion to `i128`;
- currency identifiers must resolve through a versioned currency/asset registry;
- implicit cross-currency comparison is prohibited.

The policy engine operates only on typed normalized money values, not raw JSON strings.

### H4 — Shadow Cutover Differential Noise / Authority Widening

**Finding:** Large volumes of legitimate `EXPECTED_NARROWING` results can conceal dangerous migration defects.

**Required fix:**

Shadow comparison must classify results automatically into a directional matrix:

```text
legacy ALLOW  → vNext DENY   = NARROWING
legacy ALLOW  → vNext APPROVAL = NARROWING / REVIEW
legacy DENY   → vNext DENY   = CONSISTENT_DENY
legacy DENY   → vNext ALLOW  = CRITICAL_WIDENING
legacy ERROR  → vNext ALLOW  = MANUAL_CRITICAL_REVIEW
legacy ALLOW  → vNext ALLOW  = CONSISTENT_ALLOW
```

Pipeline behavior:

- any `CRITICAL_WIDENING` immediately blocks cutover for that capability class;
- widening findings are never auto-labeled `EXPECTED`;
- mismatch classifiers must preserve original decision inputs, policy versions, reason codes, and hashes;
- narrowing must still be sampled/reviewed to distinguish desired hardening from accidental functionality loss;
- per-capability and per-organization mismatch budgets are tracked independently.

Required CI/CD gate:

```text
critical_widening_count == 0
```

### H5 — Semantic Smuggling Through Raw JSONB

**Finding:** Deterministic Policy IR is insufficient if resource/effect/constraint payloads remain loosely typed across validation and execution boundaries.

**Required fix:**

1. Raw `JSONB` may be used as a persistence/transport container, but never as the authoritative in-memory decision representation.
2. `normalize_request()` must parse into versioned strongly typed Rust structures.
3. `serde(deny_unknown_fields)` or equivalent must be enabled for authority-relevant structs.
4. Duplicate JSON keys must be rejected **before PostgreSQL JSONB ingestion**, because JSONB normalization can discard duplicate-key evidence.
5. The edge parser must reject:
   - duplicate keys;
   - unknown authority-relevant keys;
   - ambiguous aliases;
   - mixed canonical/non-canonical field names;
   - over-deep nesting;
   - over-large arrays/maps;
   - unsupported extension semantics.
6. Core evaluation may operate only on typed structures such as:

```rust
struct NormalizedCapabilityRequest { /* typed fields */ }
struct ResourceScope { /* typed variants */ }
struct EffectScope { /* typed variants */ }
struct ConstraintSet { /* typed variants */ }
```

7. The exact same canonical normalized structure must be the one hashed into the CAL semantic request and used for execution-envelope derivation.

**Invariant:**

> **The validator, policy engine, receipt generator, and downstream execution envelope must all operate on the same normalized semantic object—not separate reparses of raw JSON.**

Suggested failure codes:

```text
DUPLICATE_FIELD
UNKNOWN_AUTHORITY_FIELD
NON_CANONICAL_FIELD
SEMANTIC_NORMALIZATION_FAILED
UNSUPPORTED_EXTENSION_SEMANTICS
```

### Hardening Tests Added to M9

The pre-freeze adversarial suite must now include:

```text
revocation between initial generation check and receipt finalization
delegation cycle within one org
delegation cycle across organizations
diamond delegation with unequal scopes
cross-org delegation without explicit relationship policy
Unicode-digit money input
excess monetary fractional precision
negative authorization limit
minor-unit overflow
duplicate JSON keys before JSONB storage
unknown authority-relevant JSON field
legacy DENY → vNext ALLOW shadow inversion
stale revocation watermark during decision finalization
```

These findings are release-blocking until proven.


---

## Pre-Freeze Hardening Addendum 2

This addendum refines the five earlier hardening items and corrects implementation details that could otherwise create false confidence.

### H1-R — Finalization must not rely on a REPEATABLE READ snapshot refresh

A locking read under PostgreSQL `REPEATABLE READ` does **not** provide a magical "read newest committed values regardless of snapshot" semantic. If a target row changed after the transaction snapshot, PostgreSQL may instead raise a serialization failure when attempting to lock it.

Therefore the required production pattern is:

```text
EVALUATION PHASE
consistent read snapshot
→ compute candidate decision

FINALIZATION PHASE
fresh transaction
→ READ COMMITTED locking recheck
   OR SERIALIZABLE transaction with mandatory retry
→ compare all authority generations / revocation epochs
→ persist decision + receipt atomically
```

Preferred vNext baseline:

1. Perform potentially expensive policy evaluation outside the final lock-holding window.
2. Open a short **finalization transaction**.
3. Lock the exact authority roots that can invalidate the decision:

```sql
SELECT
    p.authority_generation,
    p.status,
    m.membership_generation,
    m.status,
    o.authority_generation,
    o.policy_generation,
    o.entitlement_generation,
    o.revocation_epoch,
    o.status
FROM anar_core.authority_contexts ctx
JOIN anar_core.principals p
  ON p.principal_id = ctx.principal_id
JOIN anar_core.memberships m
  ON m.membership_id = ctx.membership_id
JOIN anar_core.organizations o
  ON o.organization_id = ctx.organization_id
WHERE ctx.authority_context_id = $1
FOR SHARE OF p, m, o;
```

4. Re-check all relevant mutable authority roots inside that same finalization transaction:
   - principal generation/status;
   - membership generation/status;
   - organization authority generation/status;
   - policy generation;
   - entitlement generation;
   - credential revision;
   - revocation epoch;
   - delegation generation/status;
   - guardian/elevation generation/status where applicable.
5. If any value differs from the evaluation snapshot, discard the candidate decision.
6. Only then insert the decision and receipt.
7. Commit.
8. Any serialization/deadlock failure retries from evaluation or returns fail-closed according to risk policy.

**Critical refinement:** any mutation capable of invalidating authority must bump one of the locked/rechecked generations or the applicable revocation epoch in the **same transaction as the mutation**. Otherwise the finalization guard has a blind spot.

Required test:

```text
concurrent revocation begins after initial evaluation
→ finalization blocks or serialization-fails
→ stale ALLOW receipt is never committed
```

### H2-R — Delegation cycle detection must be branch-local and node-aware

Tracking only a global visited-node set can incorrectly reject valid diamond convergence.

Tracking only `delegation_id` edges is insufficient as the sole semantic loop detector because duplicate or semantically equivalent delegation rows can form cycles without immediately repeating the same database edge.

The evaluator must maintain **both**:

```rust
active_path_nodes: HashSet<(PrincipalId, OrganizationId, CapabilityId)>
active_path_edges: HashSet<DelegationId>
```

Rules:

- sets are **branch-local** / stack-scoped;
- a node tuple repeated in the active path means semantic recursion:
  `DELEGATION_LOOP_DETECTED`;
- an edge repeated in the active path means exact-edge recursion:
  `DELEGATION_EDGE_LOOP_DETECTED`;
- entries are removed when unwinding a branch;
- the same node may legitimately appear in a different completed branch of a diamond graph;
- depth counts across organization boundaries and cannot reset when context changes;
- cross-org traversal requires an explicit relationship policy for the exact delegation class;
- multiple valid parent paths may not union into broader authority.

Suggested traversal state:

```rust
struct DelegationTraversalState {
    active_nodes: HashSet<(PrincipalId, OrganizationId, CapabilityId)>,
    active_edges: HashSet<DelegationId>,
    path: Vec<DelegationId>,
    depth: u16,
}
```

This preserves valid diamond convergence while still rejecting cyclic authority derivation.

### H3-R — Typed checked arithmetic plus a separate non-negative limit type

The checked `i128` approach is accepted with two refinements.

First, transport parsing remains separate from arithmetic:

```text
raw bytes
→ ASCII/canonical lexical validator
→ currency/asset registry lookup
→ exact scale validation
→ checked integer conversion
→ typed value
```

Second, a general money amount and an authorization limit are not the same type.

```rust
struct MoneyAmount {
    currency: CurrencyId,
    minor_units: i128,
}

struct MoneyLimit {
    currency: CurrencyId,
    minor_units: u128,
}
```

This prevents negative authorization limits structurally.

Required arithmetic methods use checked operations only:

```text
checked_add
checked_sub
checked_mul
checked_abs where applicable
```

`usage > limit` returns a semantic `FINANCIAL_LIMIT_EXCEEDED`, not an arithmetic-underflow error.

`CurrencyId([u8; 4])` is acceptable only for a strictly ISO-only implementation. The platform requires a versioned currency/asset registry because non-ISO assets may exist. The canonical internal identifier should therefore be a validated registry key such as:

```text
iso4217:USD
asset:USDC
asset:ETH
```

with registry-defined scale and status.

No rounding occurs during authorization parsing. Excess scale is rejected.

### H5-R — Duplicate-key detection must happen during parsing, not after `serde_json::Value`

The proposed "parse into `serde_json::Value`, then scan for duplicates" approach is rejected.

Reason:

> `serde_json::Value` has already normalized the object map by the time traversal occurs, so duplicate-key evidence may already be lost.

Required implementation:

```text
raw HTTP body bytes
→ one authority-owned parser
→ custom serde Visitor / map-access validator
→ reject duplicate keys while tokens are consumed
→ decode directly into typed request structs
→ canonical normalized struct
→ hash
→ persist
→ evaluate
```

Authority-relevant structs must not contain unrestricted `serde_json::Value`.

Instead:

```rust
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NormalizedCapabilityRequest {
    authority_context_id: AuthorityContextId,
    capability: CapabilityRef,
    resource_scope: ResourceScope,
    effect_scope: EffectScope,
    constraints: ConstraintSet,
    evidence_refs: Vec<PolicyEvidenceRef>,
}
```

Extension payloads, where allowed, must use a separately typed/versioned extension envelope with an explicit semantic class.

**Single semantic object rule:**

```text
RAW BYTES
   ↓ one parse
TYPED NORMALIZED REQUEST
   ├── policy evaluation
   ├── semantic hash
   ├── decision receipt
   └── effective envelope derivation
```

No gateway, database layer, receipt generator, or executor may independently reinterpret the original raw JSON.

### H4-R — Shadow cutover compares authority lattices, not only top-level outcomes

The automatic cutover gate is accepted but must be stronger than:

```text
DENY vs ALLOW
```

A dangerous widening can occur even when both systems return `ALLOW`.

Example:

```text
legacy:
ALLOW up to $500 for resource A

vNext:
ALLOW up to $5,000 for resources A+B
```

Top-level outcome is identical; authority widened.

The shadow analyzer therefore compares:

```text
decision outcome
resource scope
effect scope
financial limits
time bounds
usage bounds
delegation bounds
approval requirements
evidence requirements
```

Define an authority partial order:

```text
DENY
  < REQUIRE_APPROVAL
  < ALLOW
```

with envelope scopes/constraints compared independently.

Any result where vNext is more permissive in **any authority-relevant dimension** is:

```text
CRITICAL_WIDENING
```

unless an explicitly adjudicated migration exception exists.

Mandatory critical cases include:

```text
legacy DENY             → vNext REQUIRE_APPROVAL
legacy DENY             → vNext ALLOW
legacy REQUIRE_APPROVAL → vNext ALLOW
legacy ERROR/UNKNOWN     → vNext ALLOW
legacy narrower ALLOW   → vNext broader ALLOW
```

Pipeline gate:

```text
critical_widening_count == 0
unadjudicated_scope_widening_count == 0
```

Narrowing remains review-required rather than automatically "correct".

### Additional release-blocking tests

Add these to M9:

```text
FOR SHARE under concurrent revocation finalization
serialization retry behavior
authority mutation without generation bump must fail invariant test
diamond convergence with shared destination but separate branches
semantic delegation cycle using distinct delegation rows
cross-org cycle with relationship switching
ALLOW-vs-ALLOW resource widening
ALLOW-vs-ALLOW financial-limit widening
DENY-vs-REQUIRE_APPROVAL widening
duplicate JSON key detected before any Value/JSONB normalization
typed request contains no unrestricted authority-relevant serde_json::Value
```



---

## Pre-Freeze Hardening Addendum 3

This addendum accepts the parser resource-exhaustion finding, refines delegation graph semantics, and clarifies the transaction-order semantics of decision finalization.

### H1-R2 — Decision finalization ordering and revocation serialization

The proposed `FOR SHARE` concern is useful, but the specific "out-of-order stale receipt" interpretation requires refinement.

If:

1. Tx A and Tx B both acquire compatible `FOR SHARE` locks,
2. an administrative revocation/update then blocks waiting for those locks,
3. Tx A and Tx B both commit before the revocation transaction can update the row,

then PostgreSQL has established a valid serialization order:

```text
Tx A decision
Tx B decision
revocation mutation
```

Both receipts were finalized **before the revocation became authoritative in the database**.

Therefore this sequence is not, by itself, a stale-generation bypass.

The real requirement is:

> **No receipt may commit after an authority mutation that is ordered before it, and no deferred/external effect may rely on an old receipt after a later revocation.**

The vNext baseline is therefore:

```text
decision finalization
→ short lock/freshness transaction

authority mutation
→ same authority root generation/epoch update transaction

effect execution
→ fresh effect-time reauthorization for consequential effects
```

For high/critical-risk capability classes, Anar-Core SHOULD additionally support a dedicated synchronization row:

```sql
CREATE TABLE anar_core.authority_sync_roots (
    organization_id UUID NOT NULL,
    principal_id UUID NOT NULL,
    decision_sequence BIGINT NOT NULL DEFAULT 0,
    revocation_epoch BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (organization_id, principal_id)
);
```

Finalization may:

```sql
SELECT decision_sequence, revocation_epoch
FROM anar_core.authority_sync_roots
WHERE organization_id = $1
  AND principal_id = $2
FOR UPDATE;
```

Then:

1. revalidate generations/epochs;
2. increment `decision_sequence`;
3. persist decision + receipt;
4. commit.

Authority-changing administrative transactions that must serialize against decision issuance lock/update the same sync root.

This provides strict subject/org ordering without locking unrelated organizations or principals.

**Important:** locking `authority_contexts` alone is insufficient to serialize multiple active contexts belonging to the same principal. Synchronization must occur at the authority root whose mutations invalidate all such contexts.

Receipt additions:

```text
authority_sync_sequence
revocation_epoch
```

Effect-time reauthorization remains mandatory for queued, retried, scheduled, offline, financial, privileged, publication, credential, child-sensitive, and irreversible effects.

### H2-R2 — Delegation graph identity vs evaluation-frame identity

The proposed addition of `PolicyBindingId` directly into the semantic loop-detection node is rejected as the sole cycle key.

Reason:

> A malicious delegation cycle could deliberately vary policy-binding identifiers on each hop and evade a loop detector whose node identity includes those policy IDs.

The evaluator must separate **semantic graph identity** from **evaluation-frame identity**.

#### Semantic cycle key

```rust
struct DelegationNodeKey {
    principal_id: PrincipalId,
    organization_id: OrganizationId,
    capability_id: CapabilityId,
}
```

If this key repeats in the **same active delegation path**, authority derivation is cyclic and fails closed.

#### Edge cycle key

```rust
DelegationId
```

Repeated edge in the same active path also fails closed.

#### Evaluation frame / memoization key

Policy/resource context belongs in a separate structure:

```rust
struct DelegationFrameKey {
    node: DelegationNodeKey,
    policy_binding_id: PolicyBindingId,
    normalized_resource_scope_hash: Hash,
    normalized_effect_scope_hash: Hash,
    normalized_constraint_hash: Hash,
}
```

This frame key may be used for:

- memoization;
- branch-local evaluation caching;
- proving that two rule applications are distinct;
- avoiding duplicate work in valid diamond graphs.

It must **not** weaken semantic cycle detection.

Required traversal state:

```rust
struct DelegationTraversalState {
    active_semantic_nodes: HashSet<DelegationNodeKey>,
    active_edges: HashSet<DelegationId>,
    active_frames: HashSet<DelegationFrameKey>,
    path: Vec<DelegationId>,
    depth: u16,
}
```

Rules:

- same semantic node repeated in active path → `DELEGATION_LOOP_DETECTED`;
- same edge repeated in active path → `DELEGATION_EDGE_LOOP_DETECTED`;
- same node in a separate completed branch is valid;
- different policy/resource frames may converge in a diamond graph after branch unwind;
- policy/resource differences never reset delegation depth;
- scope aggregation is intersection/narrowing only;
- a changed policy-binding ID never permits a semantic cycle.

### H5-R2 — Parser resource budgets and bounded duplicate-key tracking

Accepted.

Duplicate-key detection itself must not become an allocation-based denial-of-service surface.

The raw-byte authority parser must enforce limits **before and during token consumption**.

Required baseline limits are versioned in an `AnarCoreInputLimitsProfile` and include at minimum:

```text
max_body_bytes
max_nesting_depth
max_key_length_bytes
max_keys_per_object
max_total_object_keys
max_array_length
max_total_tokens
max_string_length_bytes
max_total_string_bytes
max_numeric_token_length
max_extensions
max_evidence_refs
max_resource_refs
max_constraint_count
```

Enforcement order:

```text
HTTP/body streaming byte limit
→ tokenizer budget
→ nesting limit
→ key-length limit
→ per-object duplicate-key tracker
→ per-object key-count limit
→ total-token/key/string budgets
→ typed decode
→ semantic validation
→ canonical hash
```

Duplicate-key tracking must be scoped per JSON object rather than one unbounded global `HashSet<String>`.

Implementations SHOULD avoid retaining full key strings when unnecessary; bounded key fingerprints may be used internally only if collision handling remains exact and fail-closed.

Exceeding any structural budget returns:

```text
INPUT_LIMIT_EXCEEDED
SEMANTIC_NORMALIZATION_FAILED
```

and the parser stops consuming authority semantics immediately.

The HTTP server must reject oversized bodies before buffering the complete payload in memory where practical.

### Additional M9 fracture tests

```text
two concurrent decision finalizers for same principal/org
decision finalizer racing principal revocation
decision finalizer racing membership revocation
multiple active authority contexts for same principal
sync-root sequence monotonicity
sync-root rollback attempt
semantic delegation cycle with changing PolicyBindingId values
valid diamond graph with distinct policy/resource frames
diamond branch failure followed by valid sibling branch
deep unique-key JSON object at max_keys_per_object + 1
overlong JSON key
nesting depth overflow
total token budget overflow
array cardinality overflow
body byte limit overflow before typed parse
```



---

## Pre-Freeze Hardening Addendum 4

This addendum accepts the strict-ordering, bounded-parser, split delegation-identity, and structural-shadow-comparison directions while correcting implementation defects that would otherwise leave exploitable seams.

### H1-R3 — Strict ordering requires exact-context recheck and two-level synchronization

The `authority_sync_roots` direction is accepted, but the synchronization object must match the scope of the mutation.

A `(organization_id, principal_id)` root correctly serializes organization-scoped authority changes. It is insufficient by itself for a **global principal revocation** affecting the same principal across multiple organizations.

vNext therefore defines two synchronization roots:

```sql
CREATE TABLE anar_core.principal_sync_roots (
    principal_id UUID PRIMARY KEY
        REFERENCES anar_core.principals(principal_id),
    global_sequence BIGINT NOT NULL DEFAULT 0,
    global_revocation_epoch BIGINT NOT NULL DEFAULT 1,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE anar_core.authority_sync_roots (
    organization_id UUID NOT NULL
        REFERENCES anar_core.organizations(organization_id),
    principal_id UUID NOT NULL
        REFERENCES anar_core.principals(principal_id),
    decision_sequence BIGINT NOT NULL DEFAULT 0,
    revocation_epoch BIGINT NOT NULL DEFAULT 1,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, principal_id)
);
```

Rules:

- organization-scoped finalization locks the relevant principal-global sync root and principal/org sync root in a **fixed order**;
- global principal revocation locks the principal-global sync root before mutating principal status/generation;
- org-scoped membership/policy/entitlement mutations lock the corresponding principal/org sync root where they can invalidate a principal's decision;
- lock order is globally fixed to avoid deadlocks;
- missing sync roots are created transactionally during principal/membership provisioning and are never silently auto-created during a high-risk decision finalizer.

Recommended lock order:

```text
principal_sync_root
→ authority_sync_root
→ principal row
→ organization row
→ exact membership row
→ optional delegation / guardian / elevation rows
```

The finalization recheck must use the **exact authority context membership**, not a join that can return another membership for the same principal:

```sql
SELECT
    p.authority_generation,
    p.status,
    m.membership_generation,
    m.status,
    o.authority_generation,
    o.policy_generation,
    o.entitlement_generation,
    o.revocation_epoch,
    o.status
FROM anar_core.authority_contexts ctx
JOIN anar_core.principals p
  ON p.principal_id = ctx.principal_id
JOIN anar_core.memberships m
  ON m.membership_id = ctx.membership_id
 AND m.principal_id = ctx.principal_id
 AND m.organization_id = ctx.organization_id
JOIN anar_core.organizations o
  ON o.organization_id = ctx.organization_id
WHERE ctx.authority_context_id = $1
  AND ctx.principal_id = $2
  AND ctx.organization_id = $3
FOR SHARE OF p, m, o;
```

Finalization then persists:

```text
principal_global_sequence
authority_sync_sequence
principal_global_revocation_epoch
organization_revocation_epoch
```

into the decision receipt.

**Invariant:**

> A finalizer must serialize against every authority root whose mutation can invalidate the decision, and must recheck the exact membership/context that was evaluated.

RLS on sync-root tables is defense-in-depth only. Decision-runtime database roles should access synchronization through narrowly granted SQL functions or explicit table privileges; an RLS policy must never substitute for the application-level authority decision.

### H5-R3 — Streaming parser must bound allocation before key materialization

The bounded single-pass parser direction is accepted, but this implementation detail is unsafe:

```rust
HashSet::with_capacity(max_keys_per_object)
```

At every nested object, preallocating the configured maximum can itself become an allocation-amplification vector.

Likewise:

```rust
JsonToken::ObjectKey(String)
```

means an arbitrarily long key may already have been allocated before `AuthorityParser` gets a chance to reject it.

Required parser layering:

```text
bounded HTTP body reader
→ tokenizer with max token/key/string byte limits
→ object-local duplicate tracker with small initial capacity
→ typed deserializer
→ semantic validator
```

Rules:

- never preallocate `max_keys_per_object`;
- use a small fixed initial capacity and grow only within the hard per-object budget;
- enforce `max_key_length_bytes` while scanning the key token, before materializing an unbounded `String`;
- enforce array nesting as well as object nesting;
- maintain `max_total_object_keys`, not only per-object count;
- maintain `max_total_string_bytes`;
- maintain `max_array_length`;
- maintain `max_numeric_token_length`;
- reject malformed object-stack underflow/unfinished objects;
- duplicate-key tracking is per object and released on object close;
- avoid cloning key strings solely for duplicate tracking;
- if fingerprints are used to reduce memory, collisions must be resolved exactly before accepting the request.

Minimum limits profile:

```rust
struct InputLimitsProfile {
    max_body_bytes: usize,
    max_nesting_depth: usize,
    max_key_length_bytes: usize,
    max_keys_per_object: usize,
    max_total_object_keys: usize,
    max_array_length: usize,
    max_total_tokens: usize,
    max_string_length_bytes: usize,
    max_total_string_bytes: usize,
    max_numeric_token_length: usize,
}
```

### H2-R3 — Delegation traversal entry must be atomic and frame hashes collision-resistant

The semantic-node / evaluation-frame split remains correct.

The sample `enter_delegation_node()` has a state-corruption hazard:

```text
insert semantic node succeeds
→ insert edge fails
→ function returns
→ semantic node remains active
```

Every traversal entry must either install **all** branch state or install none.

Use a guard/RAII pattern or explicit rollback on partial failure.

Additionally:

- `resource_scope_hash: u64` is too weak for an authority-relevant identity key;
- frame identity must include resource scope, effect scope, and constraints;
- all hashes use the same canonical semantic representation used by CAL/Anar-Core receipts.

Required frame:

```rust
struct DelegationFrameKey {
    node: DelegationNodeKey,
    policy_binding_id: PolicyBindingId,
    resource_scope_hash: SemanticHash,
    effect_scope_hash: SemanticHash,
    constraint_hash: SemanticHash,
}
```

`SemanticHash` must be collision-resistant (for example a 256-bit canonical digest), not a process-local `u64` hash.

Depth bookkeeping must also fail safely:

- no unchecked decrement;
- unwind may occur only for a successfully entered frame;
- branch guards unwind automatically on early return/panic-safe boundaries where practical.

### H4-R2 — Shadow lattice comparison must use semantic subset relations, never counts

The structural comparator direction is accepted, but `allowed_resource_count` is not a safe authority comparison.

These two envelopes both contain one resource:

```text
legacy: {project:A}
vNext:  {project:B}
```

They are not equivalent.

Likewise, financial limits cannot be compared as bare integers without currency/asset identity and constraint semantics.

The migration gate must compare normalized semantic scopes using explicit subset relations:

```text
vNext.resource_scope ⊆ legacy.resource_scope
vNext.effect_scope ⊆ legacy.effect_scope
vNext.time_window ⊆ legacy.time_window
vNext.usage_bound <= legacy.usage_bound
vNext.delegation_bound <= legacy.delegation_bound
vNext.financial_bound <= legacy.financial_bound
vNext.evidence_requirement >= legacy.evidence_requirement
vNext.approval_requirement >= legacy.approval_requirement
```

For resource wildcards, ranges, predicates, hierarchy scopes, or registered domain scope extensions, the relevant scope type must implement a deterministic `is_subset_of()` operation. If subset comparability is unknown:

```text
SHADOW_SCOPE_COMPARISON_UNRESOLVED
```

and cutover is blocked for that capability class.

Financial comparison requires:

```text
same currency/asset identifier
compatible registry version
same semantic direction
typed non-negative limit
```

If currencies differ without an explicitly frozen conversion rule, the comparison is unresolved and fails closed.

Top-level outcome comparison must also model non-success states:

```text
DENY
REQUIRE_APPROVAL
ALLOW
ERROR
UNKNOWN
UNSUPPORTED
```

For migration safety:

```text
legacy DENY/ERROR/UNKNOWN/UNSUPPORTED
→ vNext ALLOW
= CRITICAL_WIDENING
```

The sample enum variant typo is also corrected: use
`CriticalWideningDetected("OUTCOME_EXPANSION_DETECTED")`.

### Additional M9 fracture tests

```text
global principal revocation racing finalizers in two organizations
org-scoped membership revocation racing one finalizer
missing sync-root during high-risk finalization
sync-root lock-order deadlock test
authority-context membership mismatch
nested objects at high max_keys_per_object without preallocation explosion
key token exceeding max length before String materialization
object-stack underflow / unfinished-object stream
partial delegation-state insertion rollback
delegation frame hash collision-resistance fixture
same-count different-resource shadow comparison
wildcard resource subset comparison
different-currency financial shadow comparison
unknown scope comparator blocks cutover
```



---

## Pre-Freeze Hardening Addendum 5

This addendum rejects the claim that M10 is complete. The proposed implementations materially advance the design, but four release-blocking seams remain.

### H1-R4 — Synchronization must sequence globally, recheck the full context, and bind mutation protocol

The two-level synchronization model is accepted, but the proposed finalizer is incomplete.

#### Global sequence must advance

`SELECT ... FOR UPDATE` serializes on `principal_sync_roots`, but it does not advance `global_sequence`.

For high/critical-risk finalization:

```sql
UPDATE anar_core.principal_sync_roots
SET global_sequence = global_sequence + 1,
    updated_at = now()
WHERE principal_id = $1
RETURNING global_sequence, global_revocation_epoch;
```

Then lock/update the organization/principal sync root in the fixed order.

#### Finalization must recheck the entire evaluated authority context

The final gate must include:

```text
authority_context status / expiry / revocation
principal generation / status
membership generation / status
organization authority generation / status
policy generation
entitlement generation
credential revision
principal global revocation epoch
organization/principal revocation epoch
delegation generation/status where used
guardian generation/status where used
elevation generation/status where used
required assertion validity/revocation where used
```

A partial generation recheck is not sufficient.

#### Mutation protocol is mandatory

Every authority-invalidating mutation must:

```text
lock the same synchronization roots in the same order
→ mutate authoritative row(s)
→ bump the relevant generation/epoch
→ commit atomically
```

A mutation path that bypasses the synchronization protocol is a release-blocking defect.

#### Risk-scoped serialization

Global-principal serialization across organizations may become a contention point. Therefore:

```text
HIGH / CRITICAL effect classes
→ two-level strict serialization required

LOW / READ-ONLY classes
→ may use lighter freshness semantics if separately proven safe
```

The receipt records:

```text
principal_global_sequence
organization_decision_sequence
principal_global_revocation_epoch
organization_revocation_epoch
```

### H5-R4 — Tokenizer must enforce limits before allocation and after JSON escape decoding

The parser direction is accepted, but `ObjectKey(Vec<u8>)` is safe only if the tokenizer has already bounded the key before allocating that vector.

The tokenizer contract must guarantee:

```text
max_body_bytes before buffering
max token bytes while scanning
max key bytes before allocation
max string bytes before allocation
max numeric token bytes before allocation
max total decoded string bytes
max nesting across arrays AND objects
max array length
max object keys
max total tokens
```

Duplicate-key checks must occur on the **decoded semantic key**, not only raw source bytes.

Example:

```json
{"a": 1, "\u0061": 2}
```

must be treated as a duplicate key after escape decoding.

Authority field names SHOULD be restricted to canonical ASCII identifiers. Extension keys, if Unicode is allowed, must be normalized according to the CAL canonicalization profile before duplicate comparison.

The parser must also reject unfinished arrays/objects and stack underflow.

### H2-R4 — Delegation traversal requires scoped entry guards

The node/edge/frame model is accepted, but manual `enter_node()` / `unwind_node()` remains fragile.

Required implementation pattern:

```text
enter
→ validate all active-set collisions
→ insert state
→ return branch guard
→ guard automatically removes exactly the inserted state on scope exit
```

This prevents:

```text
early return
panic/unwind boundary
wrong unwind arguments
double unwind
depth drift
```

from corrupting traversal state.

`active_frames` is a memoization/evaluation structure, not a semantic authorization source.

The canonical digest must be versioned and domain-separated, e.g.:

```text
ANAR-DELEGATION-FRAME-HASH-1
```

and derived from the same normalized scope/effect/constraint semantics used by receipts.

### H4-R3 — Shadow comparator must be typed and complete

The proposed trait:

```rust
trait SemanticSubset {
    fn is_subset_of(&self, other: &Self) -> ...
}
```

cannot safely be used behind `Box<dyn SemanticSubset>` because the method depends on `Self`.

Use a typed scope enum or an object-safe erased comparator interface.

Example:

```rust
enum ResourceScope {
    ExplicitSet(...),
    Hierarchy(...),
    Prefix(...),
    RegisteredExtension(...),
}
```

with:

```rust
fn is_subset_of(&self, other: &ResourceScope) -> Result<bool, ScopeComparisonError>;
```

The comparator must evaluate **all authority-relevant dimensions**, not only resource and money:

```text
outcome
resource scope
effect scope
time window
usage count
delegation permission/depth
financial bounds
approval requirements
evidence requirements
risk-tier constraints
offline/deferred restrictions
```

Financial comparison must bind:

```text
asset/currency registry key
registry version
scale semantics
bound direction
bounded/unbounded state
```

Unknown or incomparable semantics return:

```text
SHADOW_COMPARISON_UNRESOLVED
```

and block cutover.

### M10 remains NOT READY

M10 cannot be declared complete until the following fixtures pass:

```text
global_sequence increments monotonically
full authority-context finalization recheck
mutation path missing sync-root lock is detected
cross-org high-risk finalizer contention test
escaped duplicate JSON key ("a" vs "\u0061")
array nesting and array cardinality limits
token length rejected before allocation
RAII delegation guard early-return test
RAII delegation guard panic/unwind restoration test
typed resource-scope comparator compiles without trait-object ambiguity
effect/time/usage/delegation widening detection
bounded-vs-unbounded financial comparison
registry-version mismatch blocks shadow cutover
```

**Status after this addendum: PRE-FREEZE HARDENED — M10 NOT YET SATISFIED.**



---

## Pre-Freeze Hardening Addendum 6

This addendum accepts the finalization/parser/traversal/shadow-comparison directions, corrects several implementation details, and classifies the proposed performance/security refinements into **required**, **recommended after measurement**, and **optional** work.

### H1-R5 — Finalization function contract and sequence exhaustion

The two-level finalization function is accepted in principle with the following corrections.

#### 1. Full context fields must be present

`authority_contexts` must explicitly carry and recheck:

```text
status
expires_at
revoked_at
principal_generation
membership_generation
organization_generation
policy_generation
entitlement_generation
credential_revision
```

The finalization function must compare the stored/evaluated expected values against current authoritative values and must reject if the context itself is revoked or expired.

#### 2. Credential revision must actually be rechecked

The function signature includes `p_eval_cred_rev`, but the sample query does not load the current authenticator/credential revision.

The finalizer must either:

```text
join the exact authenticator used by the authority context
```

or bind the context to an immutable `authenticator_id` / `credential_revision` pair and recheck that exact record.

#### 3. Delegation, guardian, elevation, and policy evidence are conditional roots

If the candidate decision depended on any of these, the finalizer must also recheck their current generation/status/digest:

```text
delegation
guardian relationship
elevation grant
external assertion / policy evidence
external trust / revocation fact watermark
```

The receipt must bind the identifiers/hashes of every conditional root actually consulted.

#### 4. PostgreSQL BIGINT does not wrap silently

PostgreSQL `BIGINT` arithmetic raises an overflow error rather than wrapping into negative values. Therefore the sequence risk is **exhaustion**, not silent sign-bit wrap.

Still require:

```sql
CHECK (global_sequence >= 0);
CHECK (global_revocation_epoch >= 0);
CHECK (decision_sequence >= 0);
CHECK (revocation_epoch >= 0);
```

and application/database guards that fail closed before exhaustion.

Recommended reserved maximum:

```text
MAX_SEQUENCE = 9223372036854775806
```

with:

```text
SEQUENCE_EXHAUSTION_IMMINENT
SEQUENCE_EXHAUSTED
```

as hard operational faults.

#### 5. SQL correctness

Use `END IF;`, not `END_IF;`.

A production function must also:

- check `SELECT ... INTO` row presence explicitly;
- reject more than one row where uniqueness is expected;
- use a `SECURITY DEFINER` function only if ownership/search-path privileges are hardened;
- set a fixed `search_path`;
- prevent arbitrary caller-controlled receipt bytes from bypassing canonical receipt construction;
- construct or verify the receipt hash inside the trusted boundary from canonical fields.

#### 6. Finalization must bind the sequence values into the receipt

The canonical receipt contains:

```text
principal_global_sequence
organization_decision_sequence
principal_global_revocation_epoch
organization_revocation_epoch
```

and the canonical hash is computed only after those values are known.

### H5-R5 — Escape-decoded duplicate detection

Accepted, with these corrections.

A valid JSON Unicode decoder must handle UTF-16 surrogate pairs in `\uXXXX` escapes. A decoder that independently applies `char::from_u32()` to each 16-bit escape will reject or mishandle legitimate non-BMP Unicode.

For authority field names, the simpler and safer rule is:

> **Core authority field names are ASCII-only and must match their canonical spelling exactly.**

Therefore:

```text
"a" vs "\u0061"
```

must be detected as duplicate semantic keys, but non-ASCII core field identifiers are rejected.

Extension namespaces may permit Unicode only if explicitly specified by CAL and normalized according to the canonicalization profile.

The parser budget must be enforced before and during escape decoding:

```text
raw key byte limit
decoded key byte/character limit
total decoded string budget
escape count budget
```

`Vec::with_capacity(max_nesting_depth)` should also be avoided if the configured nesting limit can be large; use a small fixed initial capacity.

### H2-R5 — RAII traversal guard borrowing model

The RAII direction is accepted.

However, a guard that owns `&mut SharedGraphState` for its full lifetime prevents ordinary recursive traversal from borrowing the same state again while the guard exists.

Production implementations should use one of:

```text
scoped closure API
index/token-based guard with interior mutability
explicit stack frame object managed by the traversal engine
carefully-audited raw-pointer guard isolated behind a safe API
```

Preferred safe shape:

```rust
state.with_delegation_frame(node, edge, frame, |state| {
    // recurse safely here
})
```

The helper performs:

```text
validate
→ insert
→ execute closure
→ guaranteed cleanup
```

including early-return cleanup.

The canonical delegation-frame digest remains:

```text
ANAR-DELEGATION-FRAME-HASH-1
```

or a later versioned domain-separated profile.

### H4-R4 — Strongly typed lattice comparator

The typed enum direction is accepted.

Corrections:

- use the same enum type in every return path (`ShadowCutoverGate`);
- `outcome: u8` is replaced with an enum, preventing invalid values;
- `HierarchyPath.starts_with()` is insufficient unless hierarchy segments are canonical and delimiter-aware (`/team/a` must not be considered parent of `/team/ab`);
- financial comparison must define both debit and credit semantics explicitly;
- effect, time, usage, delegation, approval, evidence, risk-tier, and offline/deferred constraints remain mandatory dimensions.

Recommended core interface:

```rust
trait AuthorityDimension {
    fn relation_to(&self, legacy: &Self) -> Result<SubsetRelation, ComparisonError>;
}

enum SubsetRelation {
    Equal,
    Narrower,
    Wider,
    Incomparable,
}
```

The complete envelope is accepted only if no authority dimension is `Wider` or `Incomparable`.

---

## Performance and Operational Refinements

### P1 — Request-scoped symbol interning: ACCEPT WITH BOUNDARY

String interning may improve evaluation throughput but must never alter canonical semantics.

Rules:

- interning occurs **after** strict normalization/canonical hashing inputs are established;
- interned IDs are process/request-local implementation details;
- integer symbol IDs are never persisted in receipts, federation messages, audit artifacts, or CAL hashes;
- do not use an unbounded global interner for attacker-controlled strings;
- registry-defined capability IDs may use stable preloaded numeric handles internally, but external canonical identity remains the registered string/hash;
- benchmark before adopting.

Classification:

```text
PERFORMANCE OPTIMIZATION
NOT AUTHORITY SEMANTICS
```

### P2 — Sequence-domain safety: REQUIRED

Accepted with the PostgreSQL correction above.

Rust must use an explicit checked sequence type:

```rust
struct AuthoritySequence(i64);
```

or equivalent with constructors rejecting negative values and checked increment semantics.

Do not cast database `BIGINT` blindly into `u64`.

### P3 — Evaluation arena: OPTIONAL AFTER BENCHMARKING

A request-local arena may reduce allocator churn, but it is not part of the correctness baseline.

Important correction:

> Dropping/resetting a bump arena is O(1) reclamation, but it does **not** securely wipe the underlying memory.

If sensitive data is ever stored in the arena and memory erasure is required, explicit zeroization is necessary.

Use an arena only if profiling shows meaningful benefit under realistic delegation-policy workloads.

### P4 — Constant-time cryptographic verification: REQUIRED WHERE SECRET-DEPENDENT

Use mature cryptographic libraries for:

```text
MAC verification
signature verification
secret-derived token comparison
key confirmation
```

and constant-time equality where the comparison is secret-dependent.

A public `receipt_hash` is normally not itself secret, so constant-time equality for two public hashes is defense-in-depth rather than a primary security boundary.

Never implement signature/MAC comparison manually.

### P5 — Payload-minimizing observability: REQUIRED

Accepted with refinement.

Operational logs must avoid raw:

```text
resource IDs
document names
message content
PII
financial account identifiers
customer secrets
raw policy evidence payloads
```

Logs should prefer:

```text
decision_id
receipt_id
principal pseudonym
organization pseudonym
capability_id
policy hash
reason codes
latency
risk/effect class
generation/epoch metadata
```

For low-entropy identifiers, plain SHA-256 may be dictionary-invertible. Use a keyed pseudonymization/HMAC domain for log correlation where reversible identity is not required.

Raw authority request bodies and resource scopes may still exist in tightly controlled authoritative storage if required by the product/decision model; the rule is that they do not leak into general operational telemetry.

Separate:

```text
SECURITY AUDIT EVENT
OPERATIONAL METRIC
SENSITIVE EVIDENCE STORE
```

with independent access and retention policies.

---

## M10 Gate Status After Addendum 6

M10 remains **NOT READY** until the following are proven:

```text
full finalization-context recheck including credential revision
conditional-root revalidation for delegation/guardian/elevation/assertions
receipt hash constructed after sequence/epoch finalization
PostgreSQL sequence exhaustion failure path
SQL function privilege/search_path hardening
escaped-key duplicate fixture including surrogate-pair decoder tests
safe recursive traversal cleanup API compiles and passes early-return/panic tests
delimiter-aware hierarchy subset comparison
complete multidimensional shadow lattice
log redaction/pseudonymization fixture
```

Status:

> **PRE-FREEZE HARDENED — architecture stable, implementation proof still pending.**



---

## Pre-Freeze Hardening Addendum 7

This addendum rejects the "Hard Freeze released" claim. The architecture is stable, but the submitted implementation fixtures still contain release-blocking correctness gaps. M10 remains **NOT READY**.

### H1-R6 — Trusted finalization must construct the receipt after synchronization

The two-level synchronization design is accepted, but `finalize_capability_decision_v2()` still accepts:

```text
p_receipt_bytes
p_receipt_hash
```

from the caller.

That violates the trusted-finalization invariant because the final receipt must bind values that do not exist until the function advances and reads:

```text
principal_global_sequence
organization_decision_sequence
principal_global_revocation_epoch
organization_revocation_epoch
```

Required change:

```text
caller supplies candidate decision material
→ trusted finalizer advances/locks synchronization roots
→ trusted finalizer revalidates all authority roots
→ trusted finalizer constructs canonical receipt fields
→ trusted finalizer canonicalizes
→ trusted finalizer hashes/signs
→ trusted finalizer inserts decision + receipt
```

Caller-provided canonical bytes or receipt hashes are prohibited for authoritative finalization.

### H1-R7 — Full context revalidation is still incomplete

The submitted function must also check:

```text
ctx.revoked_at IS NULL
exact authenticator is bound to this authority context
authenticator.status == ACTIVE
authenticator.valid_from <= now()
authenticator.valid_until IS NULL OR > now()
```

The authority context schema must therefore bind the authenticator actually used:

```sql
ALTER TABLE anar_core.authority_contexts
ADD COLUMN authenticator_id UUID
REFERENCES anar_core.principal_authenticators(authenticator_id);
```

Finalization joins:

```text
ctx.authenticator_id = pa.authenticator_id
AND pa.principal_id = ctx.principal_id
```

A caller-provided authenticator ID alone is not sufficient.

If the decision depended on delegation, guardian, elevation, assertion, or trust facts, those exact references/hashes/generations must also be revalidated in the same finalization protocol.

### H1-R8 — Synchronization is only correct if all invalidating mutations are forced through it

The finalizer can serialize perfectly and still lose if an administrative path updates:

```text
principals
memberships
organizations
policies
entitlements
delegations
guardian relationships
elevations
authenticators
assertions
revocations
```

without acquiring/bumping the relevant synchronization roots.

Therefore production database privileges must make the synchronization protocol non-optional.

Preferred enforcement:

```text
runtime roles
→ NO direct UPDATE/DELETE on authority root tables
→ EXECUTE-only access to narrowly scoped mutation functions
→ mutation functions acquire sync roots in canonical order
→ mutation + generation/epoch bump in same transaction
```

Direct table mutation by ordinary runtime roles is a release-blocking defect.

A database invariant test must prove that bypass mutation attempts fail.

### H1-R9 — Stored function hardening details

Production finalization function must:

- use a fixed `search_path`;
- be owned by a dedicated NOLOGIN owner role;
- revoke PUBLIC execute;
- grant EXECUTE only to the decision-runtime role;
- schema-qualify referenced objects;
- validate `p_decision_text` against a typed/checked decision domain;
- explicitly test `ctx.revoked_at`;
- explicitly verify one and only one authority context row;
- emit typed SQLSTATE/error mapping rather than relying on free-form exception strings;
- calculate canonical receipt material only after synchronization values are known.

Sequence exhaustion remains fail-closed. PostgreSQL `BIGINT` overflow is an error, not a silent negative wrap.

### H5-R6 — Duplicate-key validator must be object-scoped and grammar-bound

The surrogate-aware decoding direction is accepted, but the sample validator contains one semantic ambiguity:

```rust
seen_keys: HashSet<String>
```

If a single validator instance spans the full JSON document, it will incorrectly reject the same field name appearing in two different nested objects.

Duplicate-key state must be scoped to the currently open object.

For core authority fields, after JSON escape decoding the key must satisfy a canonical grammar, for example:

```text
[A-Za-z][A-Za-z0-9_]{0,N}
```

or an exact schema-derived field allowlist.

Decoded control characters such as:

```text
\n
\t
\b
```

must not be accepted as core authority field-name characters merely because they are ASCII.

Required pipeline:

```text
bounded token scan
→ JSON escape decode
→ surrogate validation
→ ASCII/canonical field grammar
→ per-object duplicate comparison
→ typed schema decode
```

### H2-R6 — Closure cleanup is not panic-safe as written

The submitted `scope_frame()` guarantees cleanup for ordinary `Result` returns, but not for a Rust panic:

```rust
let result = execute_branch(self);
// cleanup occurs here
```

If `execute_branch()` panics and unwinding is enabled, control never reaches the cleanup statements.

Therefore one of these explicit production contracts is required:

#### Option A — panic-abort service contract

```text
panic = abort
```

A panic terminates the process; no corrupted traversal state is reused.

#### Option B — unwind-safe scoped cleanup

Wrap the branch in a guaranteed cleanup mechanism such as:

```text
catch_unwind + cleanup + resume_unwind
```

or an audited scope guard implementation that does not prevent recursive traversal.

Do not claim panic-safe cleanup unless one of these mechanisms is actually implemented and tested.

Ordinary early-return cleanup remains required in all builds.

### H2-R7 — Frame identity must remain present

The latest traversal sample tracks:

```text
active_nodes
active_edges
```

but omits the previously required evaluation frame:

```text
policy_binding_id
resource_scope_hash
effect_scope_hash
constraint_hash
```

That frame is still required for safe diamond memoization/evaluation caching.

It is not part of semantic loop identity, but it remains part of evaluation-state correctness.

### H4-R5 — Segment-safe hierarchy comparison must not mix byte and character indices

The submitted comparator uses:

```rust
vnext.chars().nth(old.len())
```

`String::len()` is byte length, while `chars().nth()` indexes Unicode scalar values. These are incompatible units.

Core hierarchy scopes should instead be canonicalized into typed segments before comparison:

```rust
struct HierarchyScope {
    segments: Vec<ScopeSegment>,
}
```

Then:

```text
vNext is narrower-or-equal iff
legacy.segments is a prefix of vNext.segments
```

No raw string prefix comparison is used inside authority semantics.

### H4-R6 — The sample is not yet a multidimensional comparator

The submitted comparator implements only:

```text
resource hierarchy
financial debit cap
```

The M10 comparator must additionally implement and test:

```text
effect scope
time window
usage count
delegation permission
delegation depth
financial asset registry version
financial direction
bounded vs unbounded financial state
approval requirement
evidence requirement
risk-tier restriction
offline/deferred-effect restriction
```

Every dimension returns:

```text
Equal
Narrower
Wider
Incomparable
```

Any `Wider` or `Incomparable` result blocks cutover unless an explicit, reviewed migration exception exists.

### P1-R1 — String interning remains benchmark-gated

Request-local symbol interning is valid only after canonical normalization. Do not use process-local interned IDs in:

```text
receipts
CAL hashes
federation
audit artifacts
persistent authority records
```

Use it only as an internal optimization after profiling proves value.

### P3-R1 — Arena allocation remains optional

A request-scoped arena is permitted after benchmarking.

Arena reset/drop is O(1) reclamation but is not secure memory erasure.

### P4-R1 — Constant-time comparison boundary

Constant-time comparison is mandatory for:

```text
MACs
signatures where library verification requires it
secret-derived authentication tokens
key confirmation values
```

Public receipt-hash equality is not itself a secret-dependent comparison, though constant-time equality is harmless defense-in-depth.

### P5-R1 — Operational logging separation is accepted as REQUIRED

General telemetry must not contain raw:

```text
resource identifiers
message/document content
PII
account identifiers
raw evidence payloads
secrets
```

Use keyed pseudonymous identifiers for low-entropy identifiers when correlation is required.

Separate:

```text
operational metrics
security audit events
sensitive evidence storage
```

with independent access and retention policies.

---

## M10 Release Gate After Addendum 7

M10 remains **NOT READY** until all of the following are proven:

```text
receipt bytes/hash constructed inside trusted finalizer after sequence assignment
authority context binds exact authenticator
authenticator status/validity/revision rechecked
context revoked_at rechecked
conditional delegation/guardian/elevation/assertion roots rechecked
direct runtime table mutation paths are privilege-blocked
all authority mutations use canonical sync-root lock order
typed SQLSTATE/error mapping
per-object duplicate-key tracking
core key grammar rejects ASCII control characters
panic-abort or unwind-safe traversal cleanup contract proven
delegation evaluation frame restored
segment-typed hierarchy comparator
all multidimensional authority lattice dimensions implemented
```

Status:

> **PRE-FREEZE HARDENED — M10 NOT YET SATISFIED.**



---

## Pre-Freeze Hardening Addendum 8

This addendum resolves the latest adversarial findings. Several proposed hardening ideas are accepted, several are explicitly rejected because they would weaken correctness, and M10 remains **NOT READY**.

### H1-R10 — Compiler reordering is not an authority race

The proposed `compiler_fence(Ordering::SeqCst)` / `read_volatile()` gate is **rejected**.

Rust's compiler is allowed to reorder instructions only while preserving the language's observable semantics. If another thread mutates the same ordinary memory concurrently without synchronization, the program already contains a data race and is outside the valid Rust memory model.

The authority evaluator must therefore never depend on asynchronously mutable shared fields.

Required pattern:

```text
database/current-state read
→ immutable owned EvaluationSnapshot
→ pure deterministic evaluation
→ short synchronized finalization transaction
→ effect-time reauthorization where required
```

`EvaluationSnapshot` is immutable for the lifetime of one evaluation.

If any in-process shared mutable state is necessary, it must use ordinary synchronization primitives (`Arc`, `Mutex`, `RwLock`, atomics where semantically appropriate). `volatile` is not a concurrency primitive and compiler fences are not a substitute for synchronization.

**Invariant:**

> In-process evaluation operates on immutable snapshot values. Authority freshness is established by synchronized database finalization, not by CPU instruction ordering tricks.

### H1-R11 — Advisory locks are banned from authority serialization

Accepted.

PostgreSQL advisory locks exist in a separate synchronization namespace and do not coordinate with row-level locks.

Therefore:

```text
pg_advisory_lock
pg_advisory_xact_lock
```

must not participate in Anar-Core authority correctness.

They may be used only for unrelated operational coordination after explicit review.

Authority serialization must anchor to:

```text
principal_sync_roots
authority_sync_roots
```

using row-level transactional locks/updates.

### H1-R12 — Multi-root lock ordering is class-first, then key-sorted

The proposed function that changes lock class order based on comparing principal UUID text to organization UUID text is **rejected**.

That would reintroduce deadlocks because some transactions could lock:

```text
principal root → authority root
```

while others lock:

```text
authority root → principal root
```

The global order is immutable:

```text
1. all principal_sync_roots
2. all authority_sync_roots
3. principal rows
4. organization rows
5. membership rows
6. conditional authority roots
```

For bulk mutations:

```text
collect all required principal roots
→ sort by UUID bytes
→ lock in ascending order

collect all required authority roots
→ sort by (organization_id bytes, principal_id bytes)
→ lock in ascending order
```

No transaction may reverse the root-class order.

### H1-R13 — Local authority caches cannot finalize HIGH/CRITICAL effects

Accepted.

Local caches may accelerate:

```text
typed Policy IR loading
candidate-binding discovery
capability metadata lookup
non-authoritative projection assembly
```

They may not independently mint a HIGH/CRITICAL effective capability envelope.

Required path:

```text
cache-assisted evaluation
→ synchronized authoritative finalizer
→ bounded envelope
```

Queued/deferred/external effects still require effect-time reauthorization.

### H1-R14 — Trusted finalization v3 still has release blockers

The submitted database routine is **not production-ready**.

#### Incorrect receipt semantics

The routine inserts:

```text
request_id = p_context_id
membership_id = p_context_id
```

which are semantically incorrect identifiers.

`request_id` must reference the exact capability request.
`membership_id` must reference the exact membership from the authority context.

#### Placeholder hashes are prohibited

These are invalid:

```text
'N/A'
```

for:

```text
authority_context_hash
request_semantic_hash
effective_capability_hash
policy_bundle_hash
evidence_bundle_hash
```

A receipt cannot claim proof while omitting the proof material it is defined to bind.

#### PostgreSQL JSON text is not the CAL canonical serialization profile

This:

```sql
json_build_object(...)::text
```

must not be assumed equivalent to CAL canonical JSON.

Likewise:

```sql
decode(v_raw_receipt_json, 'escape')
```

is not the correct generic conversion from JSON text to UTF-8 receipt bytes.

The canonical receipt must be produced by a serializer that is conformance-tested against the CAL/Anar canonicalization fixtures.

Preferred production design:

```text
Rust decision service begins finalization transaction
→ locks/advances sync roots
→ rechecks all authority roots
→ obtains final sequence/epoch values
→ constructs canonical typed receipt in Rust
→ computes canonical hash
→ inserts decision + receipt in SAME open DB transaction
→ commits
```

The database locks remain held until the inserts commit.

This keeps canonical serialization in the same typed implementation used by CAL rather than inventing a second PL/pgSQL serializer.

A database-native canonicalizer is acceptable only if it passes the exact same golden fixtures.

#### `SECURITY DEFINER` mutation functions require authority proof

`p_admin_principal_id` being passed into a revocation function does not authorize that caller.

The mutation function must accept or resolve a bounded administrative authority decision/receipt and verify that it authorizes:

```text
principal.revoke
target principal
target organization/global scope
reason/purpose constraints
```

before performing the mutation.

No SECURITY DEFINER function may convert a caller-supplied principal UUID into administrative authority.

#### Direct-write prohibition expands to all roots

Ordinary runtime roles must not directly modify:

```text
principals
principal_authenticators
organizations
memberships
role_bindings
entitlement_bindings
policy_bindings
delegations
guardian_relationships
elevation_grants
authority_contexts
external_state_assertions
external_revocation_facts
sync roots
```

Mutations use audited functions/services following the synchronization protocol.

### H5-R7 — Do not replace exact duplicate detection with fixed-seed fingerprints

The fixed-seed `AHash`/`u64` fingerprint proposal is **rejected** as an authority correctness mechanism.

Reasons:

- collisions create false duplicate detection;
- a fixed public seed permits adversarial precomputation;
- storing only fingerprints destroys exact semantic identity;
- linear `Vec<u64>::contains()` becomes O(n).

Given strict parser bounds, exact comparison is preferable.

For core authority objects:

```text
small bounded key count
small bounded key length
ASCII canonical grammar
```

Use exact bounded key storage, such as:

```text
small Vec<SmallString>
BTreeSet<SmallString>
bounded HashSet with randomized standard hasher
```

after token/key limits are enforced.

Correctness outranks micro-optimization here.

### H5-R8 — Object-scoped key validation refinements

Accepted with two fixes:

- avoid `Vec::with_capacity(max_nesting)` if the configuration may be large; use a small initial capacity;
- the escape decoder/tokenizer remains responsible for raw and decoded length limits before the object tracker receives a key.

The object tracker compares exact decoded canonical ASCII keys per object scope.

### H2-R8 — Memoization keys must bind accumulated authority state

Accepted.

A diamond-graph cache entry must not be keyed only by local node/frame identity.

The cache key must include the **accumulated effective constraint vector** reaching that frame:

```text
capability
resource scope
effect scope
financial bound
time bound
usage bound
delegation depth/permission
approval state
evidence requirements
guardian restrictions
risk restrictions
offline/deferred restrictions
```

along with relevant policy/binding hashes and generations.

Safer baseline:

> Disable delegation-result memoization in the first production implementation unless profiling demonstrates that it is necessary.

If enabled, a cache hit is valid only for an identical canonical accumulator or a formally proven compatible subset relation.

### H2-R9 — Panic strategy must be explicit

The latest `catch_unwind` approach can provide cleanup before rethrow, but production policy must choose one model explicitly.

Preferred security-runtime default:

```text
panic = abort
```

for the authority evaluator process, combined with request/process isolation and restart supervision.

If unwind is retained, panic-safety tests must prove traversal state cleanup.

Note: normal Rust unwinding **does run `Drop` implementations**. The prior claim that panic unwinding inherently bypasses destructors is incorrect.

### P3-R2 — Zeroization boundary

Use mature zeroization for genuinely secret material:

```text
private keys
MAC keys
temporary decrypted credentials
secret-derived tokens
```

A general delegation traversal structure should not contain such secrets.

`zeroize` can reduce compiler-elision risk for explicit memory clearing, but:

```text
panic = abort
```

does not execute destructors before process termination.

Process termination delegates memory reclamation to the operating system; that is not the same thing as proving each byte was zeroized before exit.

Do not claim stronger erasure guarantees than the implementation provides.

### P3-R3 — Fixed cache-line alignment is not part of authority correctness

The `#[repr(align(64))]` in-memory counter proposal is **not part of the baseline**.

The authoritative synchronization counters live in PostgreSQL rows, not shared Rust atomics.

False-sharing optimization is relevant only to proven in-memory hot counters and only after profiling on target hardware.

Also, hardware cache-line size is not universally guaranteed to be 64 bytes.

Classification:

```text
OPTIONAL PERFORMANCE OPTIMIZATION
```

### H4-R7 — Shadow lattice remains incomplete

The segmented hierarchy direction is accepted, but the supplied `MultidimensionalLattice` is still only partially dimensional.

It currently covers:

```text
outcome
resource hierarchy
financial numeric bound
asset key
```

M10 additionally requires:

```text
effect scope
time window
usage count
delegation permission
delegation depth
asset registry version
financial direction
bounded/unbounded financial state
approval requirement
evidence requirement
risk-tier restriction
offline/deferred restriction
```

Do not cast an enum to `u8` for policy semantics. Implement an explicit relation function.

The comparator returns per-dimension:

```text
Equal
Narrower
Wider
Incomparable
```

and final cutover passes only when every dimension is `Equal` or `Narrower`.

### P5-R2 — Operational logging remains payload-minimized

Accepted.

General telemetry contains structural/pseudonymous information only.

Low-entropy IDs should use a keyed pseudonymization domain rather than raw hashing when correlation is required.

---

## M10 Gate After Addendum 8

M10 remains **NOT READY** until all of the following pass:

```text
immutable EvaluationSnapshot concurrency fixture
advisory-lock prohibition static/schema audit
bulk multi-principal multi-org canonical lock-order test
HIGH/CRITICAL cache cannot mint envelope without finalizer
receipt uses exact request_id and membership_id
no placeholder proof hashes
CAL-conformant canonical receipt serializer fixtures
receipt serialization/hash occurs after sync sequence assignment
SECURITY DEFINER mutation requires bounded admin authority proof
direct writes blocked for all authority root tables
exact duplicate-key detection retained
memoization accumulator included or memoization disabled
panic strategy documented and tested
complete multidimensional shadow lattice
```

Status:

> **PRE-FREEZE HARDENED — architecture stable; M10 implementation proof remains open.**



---

## Pre-Freeze Hardening Addendum 9 — Vault Boundary, Finalization Contract, and Remaining Proof Gaps

This addendum accepts Vault as the credential/pseudonymization broker boundary, accepts the immutable evaluation snapshot and fixed lock-class ordering, and corrects remaining implementation defects. M10 remains **NOT READY**.

### V1 — Vault is a broker, never an authority source

Vault may provide:

```text
dynamic PostgreSQL credentials
public verification trust material
Transit HMAC services
private key operations where separately required
```

Vault does **not** decide:

```text
principal authority
organization membership
delegation
entitlement
policy outcome
capability scope
```

A successful Vault operation proves only that the caller possessed a Vault capability at that moment.

### V2 — Prefer Vault Agent/Proxy lifecycle management over custom token/lease orchestration

The custom Rust AppRole bootstrap loop is not the production baseline.

Current HashiCorp Vault documentation provides Vault Agent auto-auth for AppRole and lifecycle management for managed tokens/leased secrets. The production baseline SHOULD therefore delegate authentication and renewal mechanics to Vault Agent/approved workload-native authentication where practical.

If direct application integration is retained, it must correctly implement all of:

```text
AppRole SecretID delivery / response wrapping
Vault auth-token lifecycle
token renewable vs non-renewable semantics
dynamic-secret renewable flag
renewed lease_duration parsing
max-TTL exhaustion
jitter/backoff
credential replacement in the DB pool
lease revocation
secret zeroization
HTTP/TLS validation
Vault namespace handling where applicable
```

The application must not assume that renewing a dynamic-secret lease also renews the Vault authentication token.

### V3 — AppRole bootstrap secrets are not ordinary configuration strings

`SecretID` is credential material.

Required:

```text
RoleID may be provisioned as non-secret identity material
SecretID delivered independently
SecretID short-lived / bounded-use
response wrapping preferred where AppRole is used
plaintext SecretID removed after consumption where practical
```

Do not persist `SecretID`, Vault tokens, or generated DB passwords in logs, panic messages, tracing spans, command lines, or long-lived ordinary `String` fields.

### V4 — Vault token model must be chosen explicitly

Two valid deployment profiles exist:

#### Profile A — renewable service token

Use when the runtime must maintain renewable Vault leases beyond one fixed auth-token TTL.

Requires:

```text
short token_ttl
bounded token_max_ttl
renew-self lifecycle
reauthentication before max TTL
least-privilege policy
```

#### Profile B — bounded batch token

Use when fixed-lifetime machine authentication is preferred.

Batch tokens are not renewable. Leases issued under them are constrained by token lifetime semantics, so the service must reauthenticate/reacquire credentials rather than assume infinite renewal.

The selected profile must be frozen per deployment environment.

### V5 — Vault policy refinement

The proposed policy direction is valid, but permissions must be reduced to the actual deployment path.

Minimum conceptual privileges:

```hcl
path "database/creds/anar-core-decision-runtime" {
  capabilities = ["read"]
}

path "secret/data/anar-core/vnext/authenticators" {
  capabilities = ["read"]
}

path "transit/hmac/anar-core-telemetry" {
  capabilities = ["update"]
}
```

`sys/leases/renew` is granted only when the application, rather than Vault Agent, owns lease renewal.

If Vault Agent owns renewal, the application policy should not gain renewal capability merely for convenience.

Public verification material is not secret, but its **integrity and provenance are authority-relevant**. The cached trust bundle must therefore bind:

```text
bundle version
source
retrieved_at
content hash
validity interval
issuer/key identifiers
revocation/freshness policy
```

### V6 — Vault outage semantics are risk-aware fail closed, not `process::exit()` on first packet loss

A transient Vault network failure must not automatically terminate the authority process.

Required behavior:

```text
existing still-valid DB credential
→ may continue until its bounded lease/DB validity expires

new secret-dependent operation while Vault unavailable
→ fail closed if required secret cannot be proven available/current

credential lease approaching unsafe expiry
→ stop admitting affected work
→ drain/reconnect pool
→ health state DEGRADED/NOT_READY

credential expired/revoked
→ affected DB connections rejected/closed
```

Use bounded retries with jitter/backoff and explicit readiness degradation.

No infinite retry may allow an expired credential to be treated as valid.

### V7 — Dynamic PostgreSQL credentials require pool rotation semantics

Fetching new credentials is not enough.

The database client layer must support:

```text
credential lease metadata
new pool/connection generation
drain old connections
establish new authenticated connections
stop creating connections with old credential
hard expiry deadline
revocation handling
```

A stale pooled PostgreSQL connection must not silently outlive the security contract intended by the credential lease.

### V8 — Transit HMAC telemetry is accepted with correlation-version semantics

Vault Transit HMAC is appropriate for keyed pseudonymization.

However:

- remote HMAC on every log event can make Vault a telemetry availability/latency dependency;
- batching or a bounded async redaction pipeline SHOULD be considered;
- raw identifiers must never be emitted as fallback when Transit is unavailable;
- telemetry may be dropped/degraded rather than leak raw identifiers;
- HMAC key rotation changes the versioned pseudonym output.

If longitudinal correlation must survive key rotation, define an explicit migration window or correlation-key version policy. Do not silently merge pseudonyms across key versions.

The HMAC value is pseudonymous, not anonymous. Access controls and retention policies still apply.

### V9 — Do not assume "Transit key in HSM" from ordinary Vault configuration

An HSM-backed or seal-wrapped deployment is an infrastructure choice, not an automatic property of Transit.

The spec therefore requires:

```text
Vault storage encryption/barrier protection
strict Transit ACL
key rotation policy
backup/recovery policy
optional HSM/seal-wrap according to deployment assurance tier
```

without claiming HSM protection unless the deployed Vault tier/configuration proves it.

---

### H1-R15 — `acquire_and_verify_locks()` contract corrections

The Rust-controlled finalization transaction is the accepted architecture:

```text
BEGIN
→ acquire/advance principal sync roots
→ acquire/advance authority sync roots
→ recheck exact authority context and conditional roots
→ return locked FinalizationState to Rust
→ Rust constructs canonical receipt using final sequence/epoch values
→ INSERT decision
→ INSERT receipt
→ COMMIT
```

All operations occur on the **same PostgreSQL transaction/connection**. If the function call commits independently, the design is broken because its row locks would be released before receipt insertion.

The function must return at minimum:

```text
principal_global_sequence
organization_decision_sequence
principal_global_revocation_epoch
organization_revocation_epoch
membership_id
authenticator_id
current generation vector
conditional-root digest/watermark
```

The sample epoch check:

```text
v_decision_seq != p_expected_org_epoch
```

is incorrect. `decision_sequence` is not a revocation epoch. Compare `v_org_epoch` directly to `p_expected_org_epoch`.

The stray `END_IF` syntax is also corrected to `END IF`.

### H1-R16 — Conditional authority roots cannot remain outside finalization

If evaluation depended upon:

```text
delegation
guardian relationship
elevation
external state assertion
external trust fact
external revocation fact
approval/evidence reference
```

the immutable `EvaluationSnapshot` carries exact IDs/hashes/generations for those roots.

Finalization rechecks them or rechecks a monotonic aggregate generation/watermark whose mutation protocol is proven to cover them.

No evaluated conditional root may disappear between policy evaluation and canonical receipt insertion without causing finalization failure.

### H1-R17 — Administrative mutation wrappers require administrative authority

The sample:

```text
execute_principal_revocation(p_admin_principal_id, ...)
```

must never treat `p_admin_principal_id` as proof.

Required input is a bounded administrative authorization reference, for example:

```text
admin_decision_receipt_id
target principal
capability = principal.revoke
scope
purpose/reason
expiry/single-use bounds where applicable
```

The mutation boundary verifies that authorization before acquiring sync roots and performing the mutation.

Internal revocation history SHOULD use a first-party append-only revocation/security-event table. `external_revocation_facts` remains reserved for externally sourced revocation facts.

### H1-R18 — Advisory-lock prohibition is testable policy

CI/schema review must fail if authority code or migrations introduce:

```text
pg_advisory_lock
pg_advisory_xact_lock
pg_try_advisory_lock
pg_try_advisory_xact_lock
```

inside Anar-Core authority synchronization paths.

### H1-R19 — Bulk lock algorithm

For a transaction touching multiple principals/organizations:

```text
principal keys = DISTINCT + bytewise sort
lock all principal_sync_roots

authority keys = DISTINCT + sort by (organization UUID bytes, principal UUID bytes)
lock all authority_sync_roots

then lock/read concrete authority rows in documented class order
```

No UUID comparison may change the class ordering itself.

---

### H5-R9 — Exact bounded duplicate-key parser remains baseline

The `BTreeSet<String>` object-local approach is acceptable after strict raw/decoded key limits.

The complete limits profile from prior addenda remains required:

```text
max_body_bytes
max_nesting_depth
max_key_length_bytes
max_keys_per_object
max_total_object_keys
max_array_length
max_total_tokens
max_string_length_bytes
max_total_string_bytes
max_numeric_token_length
max_extensions
max_evidence_refs
max_resource_refs
max_constraint_count
```

Do not regress to a reduced limits profile merely because duplicate detection is now exact.

### H2-R10 — Memoization remains disabled for vNext baseline

Accepted.

The safest initial implementation is:

```text
delegation-result memoization = OFF
```

If later enabled, the key binds the complete canonical accumulated constraint state and all relevant generation/policy hashes.

The submitted fixed edge buffer:

```rust
[[u8; 16]; 16]
```

is not safe when `max_depth > 16` and does not independently detect repeated edges.

If a fixed-capacity representation is used, compile/runtime constraints must prove:

```text
max_depth <= capacity
```

and edge-loop detection remains explicit.

### H4-R8 — "Complete" shadow lattice still requires all dimensions

The current sample remains partial.

Before M10 it must compare:

```text
decision outcome
resource scope
effect scope
financial bound + asset + registry version + direction
time window
usage bound
delegation permission/depth
approval requirement
evidence requirement
risk-tier constraints
offline/deferred-effect constraints
```

Every dimension yields:

```text
Equal
Narrower
Wider
Incomparable
```

M10 permits only `Equal` or `Narrower`.

---

## M10 Gate After Addendum 9

M10 remains **NOT READY** until these additional proofs pass:

```text
Vault auth profile frozen (service-renewable or bounded-batch)
SecretID delivery/wrapping fixture
Vault token and DB-secret lifecycle fixture
DB pool credential rotation / stale-connection expiry test
Vault transient-outage readiness test
Transit-HMAC outage never falls back to raw identifiers
Transit key-version correlation behavior test
same-transaction finalization lock-retention test
correct org-epoch comparison fixture
conditional-root race fixture
administrative revocation requires bounded admin authority
advisory-lock prohibition static scan
complete parser-limit regression suite
delegation memoization disabled in baseline
complete shadow-lattice dimensions implemented
```

Status:

> **PRE-FREEZE HARDENED — architecture stable; operational trust-boundary proof remains open.**


---

## Pre-Freeze Hardening Addendum 10 — Dependency Vectors, One-Shot Internal Mutations, and Vault Pool Rotation

This addendum accepts the latest SQL/Vault/runtime direction, fixes remaining semantic inversions, and introduces two refinements that simplify the final architecture:

```text
AuthorityDependencyVector
InternalMutationGrant
```

M10 remains **NOT READY**, but the remaining blockers are implementation-proof issues rather than architectural uncertainty.

### H1-R20 — `acquire_and_verify_locks_v3()` is accepted with required return-state expansion

The transaction-bound locking function is directionally correct.

The caller must execute it inside the **same open PostgreSQL transaction** that later inserts the decision and canonical receipt.

The function must return all synchronization state required by the receipt:

```text
current_global_sequence
current_decision_sequence
current_global_revocation_epoch
current_organization_revocation_epoch
bound_membership_id
bound_authenticator_id
current principal generation
current membership generation
current organization generation
current policy generation
current entitlement generation
current credential revision
```

Returning only the two sequences plus membership/authenticator IDs is insufficient for a receipt defined to prove final authority freshness.

The query SHOULD also lock the authority-context row itself:

```sql
FOR SHARE OF ctx, p, m, o, pa
```

as defense in depth.

`SELECT INTO STRICT` is preferred over post-hoc row-count checking for an exact-context lookup that must return exactly one row.

### H1-R21 — Generalize conditional-root finalization into an `AuthorityDependencyVector`

Hard-coding every possible conditional root into the finalizer will become brittle as Anar-Core grows.

The evaluator therefore produces a typed dependency vector:

```rust
struct AuthorityDependencyRef {
    dependency_type: AuthorityDependencyType,
    dependency_id: Uuid,
    organization_id: Option<Uuid>,
    expected_generation: Option<i64>,
    expected_digest: Option<SemanticDigest>,
    expected_status: Option<AuthorityStatus>,
}

enum AuthorityDependencyType {
    Delegation,
    GuardianRelationship,
    ElevationGrant,
    ExternalStateAssertion,
    ExternalTrustFact,
    ExternalRevocationWatermark,
    EntitlementBinding,
    PolicyBinding,
}
```

Before finalization:

```text
normalize dependency vector
→ deduplicate
→ sort by canonical dependency class + UUID bytes
→ recheck/lock each applicable mutable root
→ fail if any generation/hash/status differs
→ hash canonical dependency vector
→ bind dependency_bundle_hash into receipt
```

This gives the finalizer a stable extension mechanism without allowing product-domain semantics into Anar-Core.

**Invariant:**

> Every mutable fact that contributed to an ALLOW is represented in the finalization dependency vector or covered by a proven monotonic aggregate generation/watermark.

### H1-R22 — Administrative revocation cannot be authorized by capability name alone

The proposed administrative mutation function remains unsafe if it validates only:

```text
capability_id == identity.principal.revoke
decision == ALLOW
valid_until > now()
```

That allows a receipt scoped to Principal X to be replayed against Principal Y unless the target scope is checked.

Administrative mutation must verify:

```text
capability = identity.principal.revoke
exact target principal is inside effective_resource_scope
effect scope permits revocation
current admin authority is still valid at effect time
receipt/grant has not been consumed
purpose/reason constraints are satisfied
organization/global scope matches
```

The safer internal pattern is a one-shot grant.

```sql
CREATE TABLE anar_core.internal_mutation_grants (
    mutation_grant_id UUID PRIMARY KEY,
    decision_receipt_id UUID NOT NULL
        REFERENCES anar_core.decision_receipts(receipt_id),
    capability_id TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_ref TEXT NOT NULL,
    target_digest TEXT NOT NULL,
    purpose_code TEXT NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ NULL,
    revoked_at TIMESTAMPTZ NULL
);
```

Mutation execution atomically:

```text
lock grant
→ require unconsumed/unrevoked/unexpired
→ effect-time authority recheck
→ verify exact target
→ acquire synchronization roots
→ perform mutation + generation/epoch bump
→ append internal security event
→ mark grant consumed
→ commit
```

`external_revocation_facts` is **not** the table for first-party administrative mutations. Add an internal append-only table such as:

```text
security_events
authority_mutation_events
```

and reserve `external_revocation_facts` for externally sourced facts.

### H1-R23 — SECURITY DEFINER is a narrow privilege bridge

Every SECURITY DEFINER function must have:

```text
dedicated NOLOGIN owner
fixed search_path
PUBLIC EXECUTE revoked
minimal runtime EXECUTE grants
schema-qualified objects
typed inputs
bounded behavior
append-only audit event
```

No SECURITY DEFINER routine may infer administrative authority from a caller-supplied principal UUID.

### H4-R9 — Financial lattice inversion corrected

The latest comparator contains a reversed `Option` interpretation.

When `self` is vNext and `legacy` is the old envelope:

```text
vNext Some(bound), legacy None
```

means vNext **added a financial restriction** and is therefore narrower.

```text
vNext None, legacy Some(bound)
```

means vNext **removed a financial restriction** and is therefore wider.

Correct semantic matrix:

```rust
match (&self.financial_bound, &legacy.financial_bound) {
    (None, None) => {}
    (Some(_), None) => {
        // vNext added a bound: narrowing
    }
    (None, Some(_)) => {
        return CriticalWidening("FINANCIAL_RESTRICTION_REMOVED");
    }
    (Some(vnext), Some(old)) => {
        // typed comparison
    }
}
```

`is_credit: bool` is also too ambiguous for authority semantics.

Replace it with a typed bound semantic:

```rust
enum FinancialBoundKind {
    MaximumDebit,
    MaximumCredit,
    MaximumAbsoluteTransfer,
}
```

Each bound kind defines its own `relation_to()` function.

No generic assumption such as "smaller credit is wider" is permitted without an explicit semantic definition.

### H4-R10 — Complete lattice still needs the final dimensions

The current comparator correctly adds:

```text
outcome
resource
effect
money
time
usage
delegation depth
evidence
```

but M10 still requires explicit comparison for:

```text
delegation allowed vs prohibited
approval requirement
risk-tier restriction
offline/deferred-effect restriction
financial bound kind
financial registry version
```

Evidence comparison SHOULD use requirement identities/types rather than only hashes of one observed evidence instance.

### V10 — Vault-backed DB rotation must use returned lease metadata

The proposed pool rotation manager is not yet safe because it accepts one fixed `lease_duration_secs` and reuses it forever.

Every credential acquisition must return:

```rust
struct LeasedDbCredential {
    username: SecretString,
    password: SecretString,
    lease_id: String,
    lease_duration: Duration,
    renewable: bool,
    acquired_at: Instant,
    hard_expiry: Instant,
}
```

Rotation timing is recalculated from the **new lease** every cycle.

Do not assume the next lease has the same TTL as the previous lease.

### V11 — Do not interpolate database credentials into a URL string

This is unsafe and fragile:

```text
postgres://{username}:{password}@...
```

because credentials may require URL escaping and the resulting connection string becomes another secret-bearing allocation.

Use typed connection options:

```text
PgConnectOptions
  .username(...)
  .password(...)
  .host(...)
  .port(...)
  .database(...)
  .ssl_mode(...)
```

and zeroize secret-bearing temporary values where practical.

### V12 — Pool access must not let callers retain stale generations indefinitely

Returning a cloned `PgPool` from:

```rust
acquire_handle()
```

allows arbitrary consumers to hold an old pool generation.

Preferred API:

```text
PoolManager::acquire()
PoolManager::with_connection(...)
```

which returns a connection/guard associated with a pool generation and bounded expiry metadata.

Rotation lifecycle:

```text
fetch new credential
→ validate lease metadata
→ build/test new pool
→ atomically mark new generation ACTIVE
→ mark old generation DRAINING
→ reject new acquisitions from old generation
→ close/drain old pool before hard credential expiry
→ if drain deadline exceeded, force readiness failure / terminate affected connections
```

### V13 — Vault renewal and replacement are distinct

Vault dynamic secrets are leased. A consumer may renew a renewable lease or obtain a replacement credential.

The runtime must inspect lease metadata rather than assuming renewability.

When Vault Agent manages authentication/secret lifecycle, prefer consuming Agent-managed output/API behavior rather than recreating renewal logic in the application.

Vault authentication token lifetime and database-secret lifetime are separate lifecycle objects.

### V14 — Vault outage state machine

Required runtime state:

```text
READY
DEGRADED
DRAINING
NOT_READY
```

Example transition:

```text
Vault unreachable
+ current DB credential comfortably valid
→ DEGRADED

rotation deadline approaching
+ cannot obtain replacement
→ DRAINING / stop admitting high-risk work

credential hard expiry reached
→ NOT_READY
```

A transient Vault packet loss does not justify immediate process termination.

An expired or revoked credential never receives a grace authorization extension.

### V15 — Telemetry HMAC must never become an inline authority dependency

Transit HMAC remains accepted for pseudonymous operational correlation.

However, high-rate request processing must not synchronously block authority decisions on a telemetry call.

Preferred:

```text
authority decision
→ bounded structured telemetry event containing no raw secret payload
→ async pseudonymization/export pipeline
```

If pseudonymization cannot be performed safely:

```text
drop/defer telemetry
```

not:

```text
emit raw identifier
```

Telemetry failure must not alter the authority decision itself.

### V16 — Trust-material cache is integrity/freshness bounded

Public CA chains and verification keys can be cached, but cached verification material must carry:

```text
source path
bundle version
content digest
retrieved_at
valid_from
valid_until
revocation/freshness state
```

Unknown/stale trust material for a capability whose policy requires current verification fails closed.

---

## M10 Gate After Addendum 10

M10 remains **NOT READY** until:

```text
acquire_and_verify_locks returns final epochs/generation matrix
same-transaction Rust canonical receipt fixture
AuthorityDependencyVector implemented and canonicalized
conditional-root race fixtures pass
one-shot InternalMutationGrant implemented
admin mutation target-scope replay test passes
first-party authority mutation event table exists
financial Option inversion test passes
typed financial bound-kind tests pass
approval/risk/offline/delegation-permission lattice dimensions pass
Vault credential struct uses returned lease metadata
typed PgConnectOptions path contains no credential URL interpolation
old pool generation cannot be reacquired after rotation
hard-expiry drain test passes
Vault outage READY→DEGRADED→DRAINING→NOT_READY fixture passes
telemetry HMAC outage never emits raw IDs
```

Status:

> **PRE-FREEZE HARDENED — architecture stable; final implementation proofs are now concentrated in finalization dependencies, internal mutation consumption, lattice completeness, and Vault lease/pool lifecycle.**


---

## Pre-Freeze Hardening Addendum 11 — Final Dependency Closure, Internal-Mutation Atomicity, Lattice Completion, and Vault Deadline Semantics

This addendum accepts the overall direction of the latest implementation pass, corrects the remaining semantic and transaction-bound defects, and narrows the M10 gate further.

Status remains:

> **PRE-FREEZE HARDENED — M10 NOT YET SATISFIED.**

### H1-R24 — `acquire_and_verify_locks_v4()` corrections

The function is close to the required contract, but four corrections are mandatory.

#### Exact authenticator binding

`p_authenticator_id` is currently passed but not used in the `WHERE` predicate.

Required:

```sql
AND ctx.authenticator_id = p_authenticator_id
```

or remove the parameter entirely and trust only the authenticator bound inside the context.

The preferred contract is to require exact match.

#### `SELECT INTO STRICT` error mapping

`INTO STRICT` raises PostgreSQL/PLpgSQL exceptions for zero/multiple rows. These must be caught and mapped to Anar-Core-owned SQLSTATE/reason codes rather than relying on default exception identities that may collide with custom `P000x` codes already used elsewhere.

#### Return the complete receipt-binding matrix

The current return matrix is accepted and must remain part of the canonical receipt input:

```text
current_global_sequence
current_decision_sequence
current_global_revocation_epoch
current_organization_revocation_epoch
bound_membership_id
bound_authenticator_id
live_principal_generation
live_membership_generation
live_organization_generation
live_policy_generation
live_entitlement_generation
live_credential_revision
```

#### Same transaction invariant

The Rust caller must prove:

```text
BEGIN
→ acquire_and_verify_locks_v4()
→ conditional dependency recheck
→ canonical receipt construction
→ decision INSERT
→ receipt INSERT
→ COMMIT
```

on the **same SQLx transaction / PostgreSQL backend session**.

No connection return to pool, savepoint release that changes lock semantics, or independent helper transaction may occur between lock verification and receipt commit.

### H1-R25 — `AuthorityDependencyVector` must be canonical, complete, and actually revalidated

The dependency-vector concept is accepted, but the submitted implementation currently only sorts and hashes references. That does not establish current truth.

Required dependency lifecycle:

```text
evaluation
→ capture exact dependency refs
→ canonicalize + deduplicate
→ sort by dependency class + canonical identifier
→ begin finalization transaction
→ lock/recheck all mutable dependency roots in fixed class order
→ compare generation/status/digest
→ canonicalize verified dependency vector
→ compute dependency_bundle_hash
→ bind hash into decision receipt
```

The dependency reference must include:

```rust
expected_status: Option<AuthorityStatus>
```

where status is authority-relevant.

An empty conditional dependency vector is valid. Core principal/membership/org/authenticator roots are already mandatory dependencies, so:

```text
EMPTY_DEPENDENCY_VECTOR_PROHIBITED
```

is removed.

Instead, the empty vector has a deterministic canonical representation and hash.

#### Canonical hashing

This is not sufficient:

```rust
serde_json::to_vec(dep)
```

unless that exact serialization is itself the frozen Anar canonical profile.

Required:

```text
ANAR-AUTHORITY-DEPENDENCY-BUNDLE-1
domain separator
+ canonical versioned encoding
+ deterministic list framing
+ canonical dependency records
```

The hash must use the same canonicalization rules and golden fixtures used by Anar-Core receipts/CAL boundary semantics.

### H1-R26 — Prefer a unified dependency-state projection

To prevent finalization logic from becoming a table-specific branch explosion, vNext SHOULD expose a normalized internal dependency-state projection.

Conceptually:

```text
dependency_type
dependency_id
organization_id
generation
status
semantic_digest
revocation_epoch
updated_at
```

The projection may be materialized or assembled through deterministic SQL views/functions.

It is not a new authority source. It is a normalized read surface over authoritative tables.

This allows the finalizer to verify heterogeneous dependency classes without importing product-domain semantics.

### H1-R27 — Internal privileged DB mutations should be atomic with effect-time authorization where possible

The one-shot grant pattern remains useful for deferred/internal handoffs, but synchronous Anar-Core administrative mutations have a stronger option:

```text
same PostgreSQL transaction:
fresh high-risk authority finalization
→ exact mutation target verification
→ mutation
→ generation/epoch bump
→ append security event
→ decision/receipt commit
```

This eliminates the authorization-to-effect gap for first-party DB mutations.

For deferred mutations, `InternalMutationGrant` is used and must be revalidated/consumed at effect time.

### H1-R28 — `InternalMutationGrant` execution corrections

The submitted one-shot revocation function is not yet safe.

It must verify all of:

```text
grant capability
grant target_type
grant exact target_ref
grant target_digest/version where applicable
grant purpose_code == requested purpose
grant actor_principal_id == executing actor
grant organization/global scope
grant unexpired
grant unrevoked
grant unconsumed
underlying decision receipt identity
current effect-time authority freshness
```

`p_actor_principal_id` is not trusted simply because the caller supplied it.

The grant schema SHOULD therefore include:

```text
actor_principal_id
organization_id / global_scope
effect_scope_hash
authority_context_ref or effect-time reauth reference
```

The target sync-root update and principal update must each test `FOUND`/row count.

The mutation event table must carry at minimum:

```text
event_id
mutation_grant_id
decision_receipt_id
actor_principal_id
target_type
target_ref
capability_id
purpose_code
pre_generation
post_generation
pre_revocation_epoch
post_revocation_epoch
recorded_at
```

### H4-R11 — Financial `MaximumCredit` semantics corrected

The submitted lattice still contains an ambiguous inversion for:

```text
MaximumCredit
```

If the semantic meaning is:

> may perform a credit effect up to amount X

then a **smaller** maximum is narrower, exactly like a debit maximum.

Therefore all "maximum amount" capability bounds use:

```text
vNext.max <= legacy.max
```

for narrowing.

If a different semantic is required, such as a **minimum guaranteed credit**, that must be a different bound type.

Recommended types:

```rust
enum FinancialBoundKind {
    MaximumDebit,
    MaximumCredit,
    MaximumAbsoluteTransfer,
    MinimumRequiredCredit,
}
```

Each type owns an explicit monotonic comparison rule.

No boolean or name-based inference is allowed.

### H4-R12 — Final lattice dimensions

The submitted production lattice now covers most of the required dimensions, but hard freeze still requires explicit typed fields for:

```text
approval requirement
evidence requirement
```

and the following refinements:

- `risk_tier_ceiling: u8` becomes a registered ordered `RiskTier`;
- `effect_scope_classes: HashSet<String>` becomes canonical registered effect identifiers/enums;
- time windows validate `start <= end`;
- unbounded time is represented explicitly rather than by sentinel integers;
- financial registry version remains part of comparison;
- evidence requirements compare required **evidence classes/types**, not only observed evidence-instance hashes.

M10 passes only if every authority dimension returns:

```text
Equal
Narrower
Wider
Incomparable
```

and the final result contains no `Wider` or `Incomparable`.

### V17 — Vault lease representation uses absolute deadlines

This is too ambiguous:

```rust
lease_expiry_deadline: Duration
```

A lease must carry an absolute monotonic deadline:

```rust
struct LeasedDbCredential {
    username: SecretString,
    password: SecretString,
    lease_id: String,
    renewable: bool,
    acquired_at: Instant,
    hard_expiry: Instant,
    rotate_after: Instant,
}
```

`rotate_after` is computed from the actual lease metadata returned for that credential.

No fixed TTL is carried across rotations.

### V18 — Rotation supervisor must be deadline-driven, not "3 retries then sleep another 3/4 TTL"

The submitted loop has a serious timing defect:

```text
sleep 3/4 TTL
→ fail 3 retries
→ enter Draining
→ outer loop repeats
→ sleep another 3/4 of the SAME lease lifetime
```

That can sleep past hard expiry.

Required supervisor:

```text
while now < hard_expiry:
    if now < rotate_after:
        sleep_until(rotate_after)

    attempt replacement
    if success:
        switch generation
        current_lease = new_lease
        recompute rotate_after/hard_expiry
        continue

    set DEGRADED or DRAINING according to remaining lifetime
    retry with bounded exponential backoff + jitter
    cap next retry to before hard_expiry

at hard_expiry:
    NOT_READY
    reject new DB work
    force old-generation closure
```

### V19 — Do not expose cloneable `PgPool` as the public runtime contract

The latest implementation regresses the earlier pool-generation boundary:

```rust
pub async fn acquire_active_pool(...) -> Result<PgPool, ...>
```

A caller can retain that pool handle longer than intended.

Preferred interfaces:

```rust
with_connection(risk_tier, |conn| ...)
```

or a generation-bound connection guard carrying:

```text
pool_generation
credential_hard_expiry
health_state_at_acquire
```

No new acquisition may occur from a `DRAINING` old generation.

### V20 — Pool generations need explicit metadata and hard-drain deadline

Model:

```rust
struct PoolGeneration {
    generation_id: u64,
    pool: PgPool,
    credential_lease_id: String,
    activated_at: Instant,
    hard_expiry: Instant,
    state: ACTIVE | DRAINING | CLOSED,
}
```

Rotation:

```text
build new pool
→ prove connectivity
→ atomically ACTIVE(new)
→ DRAINING(old)
→ reject old-generation acquisitions
→ close old pool before old credential hard_expiry
→ if connections fail to drain by deadline:
     cancel/terminate affected work
     NOT_READY if safety cannot be proven
```

SQLx pool configuration SHOULD also use bounded connection lifetime/idle settings compatible with credential lifetime.

### V21 — Credential material uses secret-bearing types

Do not keep Vault-generated DB passwords as ordinary long-lived `String`.

Use a secret-bearing type such as:

```text
SecretString / SecretBox
```

or equivalent, with redaction and zeroization behavior appropriate to the implementation.

Never log connection options containing credentials.

### V22 — Health state controls admission, not authorization semantics

`Ready/Degraded/Draining/NotReady` is an operational availability state.

It may prevent admission of work.

It must not broaden or narrow the semantic authority envelope itself.

For example:

```text
ALLOW from Anar-Core
+ substrate NOT_READY
→ execution unavailable / fail closed

not:
→ semantic DENY rewritten as policy truth
```

This preserves the distinction between:

```text
authority
availability
execution outcome
```

---

## M10 Gate After Addendum 11

M10 remains **NOT READY** until:

```text
exact authenticator predicate fixed in v4 finalizer
STRICT exception mapping fixture
same-SQLx-transaction lock retention fixture
dependency vector empty-case canonical hash fixture
dependency bundle uses domain-separated canonical encoding
dependency roots are actually rechecked, not merely hashed
dependency-state projection/view contract implemented
internal synchronous mutation atomic-finalization fixture
deferred mutation grant actor/purpose/target/effect-time replay tests
mutation row-count assertions
MaximumCredit monotonicity test
approval/evidence lattice dimensions implemented
registered RiskTier/effect IDs replace raw numeric/string ordering
absolute Vault hard_expiry/rotate_after model
rotation retry loop proven never to sleep past hard expiry
cloneable PgPool removed from public acquisition API
pool generation hard-drain test
secret-bearing DB credential type fixture
```

Status:

> **PRE-FREEZE HARDENED — remaining proof surface is now narrowly bounded to dependency revalidation, privileged-mutation atomicity, final lattice semantics, and deadline-correct Vault pool rotation.**


---

## Pre-Freeze Hardening Addendum 12 — Finalizer Closure, Dependency Revalidation, Mutation Ordering, and Lease-Safe Pool Generations

This addendum accepts the latest implementation direction but keeps M10 **NOT READY** because four proof gaps remain:

```text
dependency refs are hashed but not yet revalidated
one-shot mutation still violates canonical lock-class order
shadow comparator still compares satisfaction state instead of requirement state
pool API still permits stale generation retention / in-flight overrun
```

### H1-R29 — `acquire_and_verify_locks_v5()` is close, with two required corrections

The exact authenticator predicate, `SELECT INTO STRICT`, context-row lock, sequence/epoch return matrix, and generation checks are accepted.

#### PL/pgSQL syntax correction

Use:

```sql
END IF;
```

not:

```sql
END_IF;
```

#### STRICT error mapping must use non-colliding Anar error codes

`NO_DATA_FOUND` / `TOO_MANY_ROWS` interception is correct.

The production error-code registry must guarantee that:

```text
P0004
P0016
...
```

are unique across all Anar-Core functions and map deterministically to API reason codes.

No caller should reason from free-form exception message text.

### H1-R30 — The dependency bundle encoder is not yet canonical

This remains unsafe as the final canonical format:

```rust
serde_json::to_vec(dep)
```

A serde-derived JSON encoding is deterministic for this exact Rust struct today, but it is not by itself the frozen Anar canonical wire profile.

Required encoding:

```text
domain = "ANAR-AUTHORITY-DEPENDENCY-BUNDLE-1"
version
record_count
for each sorted dependency:
    dependency_type stable wire code
    dependency_id canonical 16 bytes
    organization presence + canonical 16 bytes
    generation presence + signed canonical integer
    digest presence + exact 32 bytes
    expected_status presence + stable status wire code
```

Each variable/optional field must be explicitly framed.

Do not depend on Rust enum declaration order or serde's textual enum representation as the cryptographic contract.

The empty dependency list is valid and hashes to the domain-separated canonical empty-list representation.

### H1-R31 — Dependency revalidation is the remaining finalizer correctness gate

Hashing an `AuthorityDependencyVector` does not establish freshness.

Within the same finalization transaction:

```text
mandatory roots locked/rechecked
→ dependency vector normalized
→ dependency roots loaded in canonical class/key order
→ current generation/status/digest compared
→ verified canonical dependency vector encoded
→ dependency_bundle_hash computed
→ receipt constructed
→ decision + receipt inserted
→ commit
```

Recommended normalized internal verifier contract:

```rust
trait AuthorityDependencyVerifier {
    async fn verify_locked(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        dependency: &AuthorityDependencyRef,
    ) -> Result<VerifiedDependency, AuthorityError>;
}
```

Product-domain data must not enter this interface.

### H1-R32 — Dependency locking order is part of deadlock freedom

The dependency vector must define a stable class order, for example:

```text
PolicyBinding
EntitlementBinding
Delegation
GuardianRelationship
ElevationGrant
ExternalStateAssertion
ExternalTrustFact
ExternalRevocationWatermark
```

Within a class:

```text
organization UUID bytes
→ dependency UUID bytes
```

The exact class order may differ, but once frozen it is global and must be used by both decision finalization and mutation paths.

---

### H1-R33 — One-shot principal revocation currently locks in the wrong order

The submitted function does:

```text
mutation grant FOR UPDATE
→ principal_sync_root UPDATE
```

This violates the previously frozen class-first protocol:

```text
principal_sync_roots
→ authority_sync_roots
→ concrete authority rows
→ conditional roots / mutation grant
```

That can deadlock with a transaction that already holds the principal root and later needs the mutation grant.

Required two-phase pattern:

```text
1. read grant non-locking to discover canonical target/scope
2. verify identifiers are structurally valid
3. lock principal sync root
4. lock any authority sync roots
5. lock mutation grant FOR UPDATE
6. re-read/revalidate grant completely
7. effect-time authority revalidation
8. mutate target + generation/epoch
9. mark grant consumed with conditional UPDATE
10. append event
11. commit
```

The non-locking first read grants no authority; it exists only to discover the lock set.

### H1-R34 — Grant consumption must be conditional and row-count checked

Use:

```sql
UPDATE anar_core.internal_mutation_grants
SET consumed_at = now()
WHERE mutation_grant_id = $1
  AND consumed_at IS NULL
  AND revoked_at IS NULL
  AND expires_at > now();
```

Then require:

```text
ROW_COUNT == 1
```

The grant must bind and recheck:

```text
actor principal
decision receipt
capability
target type/ref/digest
purpose
organization/global scope
effect scope
expiry
revocation state
```

For synchronous first-party mutations, same-transaction fresh authority + mutation remains preferred over introducing a deferred grant.

---

### H4-R13 — Approval and evidence are requirements, not observed satisfaction state

These fields are semantically wrong for shadow comparison:

```rust
approval_requirements_met: bool
verified_evidence_classes: HashSet<String>
```

The migration lattice compares **what authority requires**, not whether one historical request happened to satisfy it.

Use:

```rust
enum ApprovalRequirement {
    None,
    OneAuthorizedApprover,
    MultiParty { quorum: u16 },
    RegisteredPolicy { policy_hash: SemanticDigest },
}

struct EvidenceRequirementSet {
    required_classes: BTreeSet<EvidenceClassId>,
}
```

Shadow safety compares:

```text
vNext approval requirement >= legacy requirement
vNext evidence requirements ⊇ legacy requirements
```

where the ordering is explicitly defined by type.

Observed approvals/evidence remain decision inputs, not envelope-policy dimensions.

### H4-R14 — Risk/effect identifiers must be registered types

Replace:

```text
HashSet<String>
```

for effect classes with canonical registered IDs/enums.

`RiskTier` ordering is accepted only after the registry formally defines that a greater ceiling means more authority.

No raw numeric cast should be the sole definition of security ordering; implement explicit `relation_to()`.

### H4-R15 — Time windows need structural validation

Before comparison:

```text
if start and end are both bounded:
    require start <= end
```

Invalid intervals are `Incomparable`/invalid, never silently narrowed.

---

### V23 — Absolute deadline model accepted; lease metadata remains incomplete

The move to `rotate_after: Instant` and `hard_expiry: Instant` is accepted.

Vault's database secrets engine returns lease metadata such as lease ID, duration, and renewability; consumers must respect lease validity/renewal/replacement rather than assuming a permanent credential. citeturn830051search0turn830051search1turn830051search2

The credential object must still include:

```rust
lease_id: String,
renewable: bool,
```

because replacement/renewal/revocation behavior depends on the actual lease.

### V24 — The public pool API still retains stale-generation risk

This still exposes the pool object:

```rust
FnOnce(&PgPool)
```

and callers can clone `PgPool` inside the closure.

The public contract must hand out a checked-out connection or an opaque generation-bound executor, not a pool.

Preferred conceptual API:

```rust
async fn with_connection<F, Fut, R>(
    &self,
    risk: RiskTier,
    f: F
) -> Result<R, DbError>
where
    F: for<'c> FnOnce(&'c mut PgConnection) -> Fut;
```

or an equivalent safe executor abstraction.

The manager:

```text
checks health/generation
→ acquires a connection from ACTIVE generation
→ releases manager lock
→ executes bounded operation
```

No caller receives cloneable ownership of the pool.

### V25 — Holding the manager `RwLock` during DB work blocks rotation

The submitted implementation keeps:

```text
active_pool.read()
```

alive for the entire closure.

Long database work can therefore prevent the supervisor from acquiring the write lock needed to swap generations.

Required:

```text
read ACTIVE generation metadata
→ acquire connection
→ release manager lock
→ execute operation
```

The checked-out connection is tagged with its generation/hard-expiry.

### V26 — In-flight DB work must not survive credential hard-expiry without policy

Vault documents that leases have bounded TTLs and that consumers can no longer assume a dynamic secret remains valid once its lease expires/revokes. citeturn830051search2turn830051search3

Application safety therefore cannot be based only on stopping *new* acquisitions.

For high/critical operations:

```text
operation deadline <= credential hard_expiry - safety_margin
```

If the deadline cannot be guaranteed:

```text
do not admit the operation
```

When an old pool generation reaches its hard-drain deadline:

```text
cancel affected operations where supported
close pool
mark NOT_READY if safety cannot be proven
```

SQLx pool shutdown/drain behavior must be tested with checked-out connections; the architecture must not assume `close()` instantly terminates every in-flight operation.

### V27 — PoolGeneration becomes explicit

Required runtime model:

```rust
struct PoolGeneration {
    generation_id: u64,
    pool: PgPool,
    lease_id: String,
    activated_at: Instant,
    rotate_after: Instant,
    hard_expiry: Instant,
    state: PoolGenerationState,
}

enum PoolGenerationState {
    Active,
    Draining,
    Closed,
}
```

Only `Active` may satisfy new connection acquisition.

### V28 — Retry loop must handle pool-build failure as well as Vault-fetch failure

The latest code only updates `Degraded/Draining` inside the Vault-fetch `Err` branch.

A successful credential fetch followed by:

```text
new pool connect failure
```

must enter the same bounded deadline-aware retry state machine.

Every failed rotation attempt—Vault fetch or DB pool validation—updates operational health based on remaining lifetime.

### V29 — Secret-bearing username policy

Vault-generated usernames are usually not high-value secrets; passwords are.

The current:

```rust
password: SecretString
```

direction is accepted.

Do not claim that merely using a wrapper proves every transient copy is zeroized; minimize exposure and avoid logging/formatting.

---

## M10 Gate After Addendum 12

M10 remains **NOT READY** until:

```text
v5 PL/pgSQL syntax corrected
Anar SQLSTATE registry uniqueness fixture
dependency bundle replaces serde_json cryptographic encoding
expected_status restored in dependency records
all dependency roots actually revalidated under lock
dependency class/key lock order fixture
one-shot mutation lock-order inversion fixed
conditional grant consumption row-count fixture
approval lattice compares requirements, not satisfaction
evidence lattice compares requirement classes
registered effect IDs + explicit RiskTier relation
invalid time-window fixture
Vault lease_id/renewable retained in generation metadata
public API cannot expose/clone PgPool
manager lock released before DB operation
pool-build failure enters deadline state machine
high-risk DB operation cannot overrun credential hard expiry
checked-out-connection hard-drain fixture
```

Status:

> **PRE-FREEZE HARDENED — final blockers are now concrete implementation invariants, not open architecture.**

## Need Professional Help in Developing Your Architecture?

Please contact me at [sammuti.com](https://sammuti.com) :)
