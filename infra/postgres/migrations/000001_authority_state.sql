BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE SCHEMA IF NOT EXISTS anar_core;

CREATE TABLE anar_core.principals (
    principal_id uuid PRIMARY KEY,
    principal_kind text NOT NULL CHECK (principal_kind IN ('HUMAN', 'AGENT', 'SERVICE', 'WORKLOAD', 'DEVICE')),
    status text NOT NULL CHECK (status IN ('ACTIVE', 'SUSPENDED', 'REVOKED', 'EXPIRED')),
    generation bigint NOT NULL DEFAULT 0 CHECK (generation BETWEEN 0 AND 9223372036854775806),
    global_revocation_epoch bigint NOT NULL DEFAULT 0 CHECK (global_revocation_epoch BETWEEN 0 AND 9223372036854775806)
);

CREATE TABLE anar_core.organizations (
    organization_id uuid PRIMARY KEY,
    status text NOT NULL CHECK (status IN ('ACTIVE', 'SUSPENDED', 'REVOKED', 'EXPIRED')),
    generation bigint NOT NULL DEFAULT 0 CHECK (generation BETWEEN 0 AND 9223372036854775806),
    revocation_epoch bigint NOT NULL DEFAULT 0 CHECK (revocation_epoch BETWEEN 0 AND 9223372036854775806)
);

CREATE TABLE anar_core.memberships (
    membership_id uuid PRIMARY KEY,
    principal_id uuid NOT NULL REFERENCES anar_core.principals(principal_id),
    organization_id uuid NOT NULL REFERENCES anar_core.organizations(organization_id),
    status text NOT NULL CHECK (status IN ('ACTIVE', 'SUSPENDED', 'REVOKED', 'EXPIRED')),
    generation bigint NOT NULL DEFAULT 0 CHECK (generation BETWEEN 0 AND 9223372036854775806),
    UNIQUE (membership_id, principal_id, organization_id)
);

CREATE TABLE anar_core.authenticators (
    authenticator_id uuid PRIMARY KEY,
    principal_id uuid NOT NULL REFERENCES anar_core.principals(principal_id),
    status text NOT NULL CHECK (status IN ('ACTIVE', 'SUSPENDED', 'REVOKED', 'EXPIRED')),
    generation bigint NOT NULL DEFAULT 0 CHECK (generation BETWEEN 0 AND 9223372036854775806),
    expires_at_epoch_ms bigint
);

CREATE TABLE anar_core.authority_contexts (
    authority_context_id uuid PRIMARY KEY,
    principal_id uuid NOT NULL REFERENCES anar_core.principals(principal_id),
    organization_id uuid NOT NULL REFERENCES anar_core.organizations(organization_id),
    membership_id uuid NOT NULL,
    authenticator_id uuid NOT NULL REFERENCES anar_core.authenticators(authenticator_id),
    purpose_code text NOT NULL CHECK (purpose_code ~ '^[a-z][a-z0-9._:-]{0,127}$'),
    capability_id text NOT NULL CHECK (capability_id ~ '^[a-z][a-z0-9._:-]{0,127}$'),
    capability_version integer NOT NULL CHECK (capability_version > 0),
    cal_semantic_hash bytea NOT NULL CHECK (octet_length(cal_semantic_hash) = 32),
    status text NOT NULL CHECK (status IN ('ACTIVE', 'SUSPENDED', 'REVOKED', 'EXPIRED')),
    generation bigint NOT NULL DEFAULT 0 CHECK (generation BETWEEN 0 AND 9223372036854775806),
    expires_at_epoch_ms bigint NOT NULL,
    FOREIGN KEY (membership_id, principal_id, organization_id)
      REFERENCES anar_core.memberships(membership_id, principal_id, organization_id)
);

CREATE TABLE anar_core.principal_authority_sync (
    principal_id uuid PRIMARY KEY REFERENCES anar_core.principals(principal_id),
    global_sequence bigint NOT NULL DEFAULT 0 CHECK (global_sequence BETWEEN 0 AND 9223372036854775806)
);

CREATE TABLE anar_core.organization_authority_sync (
    organization_id uuid PRIMARY KEY REFERENCES anar_core.organizations(organization_id),
    decision_sequence bigint NOT NULL DEFAULT 0 CHECK (decision_sequence BETWEEN 0 AND 9223372036854775806)
);

CREATE TABLE anar_core.authority_dependency_state (
    dependency_row_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    dependency_type smallint NOT NULL CHECK (dependency_type BETWEEN 1 AND 8),
    organization_id uuid,
    dependency_id uuid NOT NULL,
    generation bigint CHECK (generation BETWEEN 0 AND 9223372036854775806),
    semantic_hash bytea CHECK (semantic_hash IS NULL OR octet_length(semantic_hash) = 32),
    status text CHECK (status IS NULL OR status IN ('ACTIVE', 'SUSPENDED', 'REVOKED', 'EXPIRED')),
    UNIQUE NULLS NOT DISTINCT (dependency_type, organization_id, dependency_id)
);

CREATE TABLE anar_core.decisions (
    decision_id uuid PRIMARY KEY,
    receipt_id uuid NOT NULL UNIQUE,
    request_id uuid NOT NULL,
    idempotency_key text NOT NULL CHECK (idempotency_key ~ '^[a-zA-Z0-9._:-]{1,160}$'),
    principal_id uuid NOT NULL REFERENCES anar_core.principals(principal_id),
    organization_id uuid NOT NULL REFERENCES anar_core.organizations(organization_id),
    membership_id uuid NOT NULL REFERENCES anar_core.memberships(membership_id),
    authenticator_id uuid NOT NULL REFERENCES anar_core.authenticators(authenticator_id),
    authority_context_id uuid NOT NULL REFERENCES anar_core.authority_contexts(authority_context_id),
    purpose_code text NOT NULL CHECK (purpose_code ~ '^[a-z][a-z0-9._:-]{0,127}$'),
    capability_id text NOT NULL,
    capability_version integer NOT NULL CHECK (capability_version > 0),
    cal_semantic_hash bytea NOT NULL CHECK (octet_length(cal_semantic_hash) = 32),
    outcome text NOT NULL CHECK (outcome IN ('ALLOW', 'DENY', 'REQUIRE_APPROVAL')),
    reason_codes text[] NOT NULL CHECK (cardinality(reason_codes) > 0),
    request_semantic_hash bytea NOT NULL CHECK (octet_length(request_semantic_hash) = 32),
    evaluation_snapshot_hash bytea NOT NULL CHECK (octet_length(evaluation_snapshot_hash) = 32),
    policy_bundle_hash bytea NOT NULL CHECK (octet_length(policy_bundle_hash) = 32),
    evidence_bundle_hash bytea NOT NULL CHECK (octet_length(evidence_bundle_hash) = 32),
    dependency_bundle_hash bytea NOT NULL CHECK (octet_length(dependency_bundle_hash) = 32),
    principal_generation bigint NOT NULL CHECK (principal_generation >= 0),
    organization_generation bigint NOT NULL CHECK (organization_generation >= 0),
    membership_generation bigint NOT NULL CHECK (membership_generation >= 0),
    authenticator_generation bigint NOT NULL CHECK (authenticator_generation >= 0),
    authority_context_generation bigint NOT NULL CHECK (authority_context_generation >= 0),
    principal_global_sequence bigint NOT NULL CHECK (principal_global_sequence > 0),
    organization_decision_sequence bigint NOT NULL CHECK (organization_decision_sequence > 0),
    principal_global_revocation_epoch bigint NOT NULL CHECK (principal_global_revocation_epoch >= 0),
    organization_revocation_epoch bigint NOT NULL CHECK (organization_revocation_epoch >= 0),
    issued_at_epoch_ms bigint NOT NULL,
    UNIQUE (organization_id, idempotency_key),
    UNIQUE (principal_id, principal_global_sequence),
    UNIQUE (organization_id, organization_decision_sequence)
);

CREATE TABLE anar_core.decision_receipts (
    receipt_id uuid PRIMARY KEY,
    decision_id uuid NOT NULL UNIQUE REFERENCES anar_core.decisions(decision_id) ON DELETE RESTRICT,
    organization_id uuid NOT NULL REFERENCES anar_core.organizations(organization_id),
    canonical_receipt jsonb NOT NULL,
    canonical_receipt_sha256 bytea NOT NULL CHECK (octet_length(canonical_receipt_sha256) = 32),
    created_at_epoch_ms bigint NOT NULL
);

CREATE TABLE anar_core.internal_mutation_grants (
    mutation_grant_id uuid PRIMARY KEY,
    decision_receipt_id uuid NOT NULL REFERENCES anar_core.decision_receipts(receipt_id),
    actor_principal_id uuid NOT NULL REFERENCES anar_core.principals(principal_id),
    organization_id uuid NOT NULL REFERENCES anar_core.organizations(organization_id),
    capability_id text NOT NULL,
    target_type text NOT NULL CHECK (target_type ~ '^[a-z][a-z0-9._:-]{0,127}$'),
    target_ref uuid NOT NULL,
    target_digest bytea NOT NULL CHECK (octet_length(target_digest) = 32),
    purpose_code text NOT NULL CHECK (purpose_code ~ '^[a-z][a-z0-9._:-]{0,127}$'),
    effect_scope_hash bytea NOT NULL CHECK (octet_length(effect_scope_hash) = 32),
    issued_at_epoch_ms bigint NOT NULL,
    expires_at_epoch_ms bigint NOT NULL CHECK (expires_at_epoch_ms > issued_at_epoch_ms),
    consumed_at_epoch_ms bigint,
    revoked_at_epoch_ms bigint
);

CREATE TABLE anar_core.authority_mutation_events (
    event_id uuid PRIMARY KEY,
    mutation_grant_id uuid NOT NULL UNIQUE REFERENCES anar_core.internal_mutation_grants(mutation_grant_id),
    decision_receipt_id uuid NOT NULL REFERENCES anar_core.decision_receipts(receipt_id),
    actor_principal_id uuid NOT NULL REFERENCES anar_core.principals(principal_id),
    organization_id uuid NOT NULL REFERENCES anar_core.organizations(organization_id),
    target_type text NOT NULL,
    target_ref uuid NOT NULL,
    capability_id text NOT NULL,
    purpose_code text NOT NULL,
    pre_generation bigint NOT NULL,
    post_generation bigint NOT NULL CHECK (post_generation = pre_generation + 1),
    pre_revocation_epoch bigint NOT NULL,
    post_revocation_epoch bigint NOT NULL CHECK (post_revocation_epoch = pre_revocation_epoch + 1),
    recorded_at_epoch_ms bigint NOT NULL
);

COMMIT;
