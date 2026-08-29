BEGIN;

CREATE TABLE anar_core.identities (
    identity_id uuid PRIMARY KEY,
    canonical_name text NOT NULL CHECK (length(canonical_name) BETWEEN 1 AND 256),
    status text NOT NULL CHECK (status IN ('ACTIVE', 'SUSPENDED', 'REVOKED')),
    created_at_epoch_ms bigint NOT NULL
);

ALTER TABLE anar_core.principals
    ADD COLUMN identity_id uuid REFERENCES anar_core.identities(identity_id),
    ADD COLUMN canonical_name text NOT NULL DEFAULT 'rehearsal-principal' CHECK (length(canonical_name) BETWEEN 1 AND 256),
    ADD COLUMN suspended_at_epoch_ms bigint,
    ADD COLUMN revoked_at_epoch_ms bigint;
ALTER TABLE anar_core.principals ALTER COLUMN canonical_name DROP DEFAULT;

ALTER TABLE anar_core.authenticators
    ADD COLUMN authenticator_type text NOT NULL DEFAULT 'rehearsal' CHECK (authenticator_type ~ '^[a-z][a-z0-9._:-]{0,127}$'),
    ADD COLUMN issuer text,
    ADD COLUMN subject text,
    ADD COLUMN public_key_fingerprint text,
    ADD COLUMN device_binding_ref text,
    ADD COLUMN valid_from_epoch_ms bigint NOT NULL DEFAULT 0;
ALTER TABLE anar_core.authenticators ALTER COLUMN authenticator_type DROP DEFAULT;
ALTER TABLE anar_core.authenticators ALTER COLUMN valid_from_epoch_ms DROP DEFAULT;
CREATE UNIQUE INDEX authenticators_issuer_subject_unique
    ON anar_core.authenticators (issuer, subject)
    WHERE issuer IS NOT NULL AND subject IS NOT NULL;

ALTER TABLE anar_core.organizations
    ADD COLUMN canonical_name text NOT NULL DEFAULT 'rehearsal-organization' CHECK (length(canonical_name) BETWEEN 1 AND 256),
    ADD COLUMN organization_type text NOT NULL DEFAULT 'STANDARD' CHECK (organization_type ~ '^[A-Z][A-Z0-9_]{0,63}$'),
    ADD COLUMN policy_generation bigint NOT NULL DEFAULT 0 CHECK (policy_generation BETWEEN 0 AND 9223372036854775806),
    ADD COLUMN entitlement_generation bigint NOT NULL DEFAULT 0 CHECK (entitlement_generation BETWEEN 0 AND 9223372036854775806);
ALTER TABLE anar_core.organizations ALTER COLUMN canonical_name DROP DEFAULT;

ALTER TABLE anar_core.memberships
    ADD COLUMN membership_class text NOT NULL DEFAULT 'STANDARD' CHECK (membership_class IN ('STANDARD', 'GUEST', 'SERVICE', 'EXTERNAL_COLLABORATOR', 'CHILD')),
    ADD COLUMN valid_from_epoch_ms bigint NOT NULL DEFAULT 0,
    ADD COLUMN valid_until_epoch_ms bigint,
    ADD CONSTRAINT membership_validity_window CHECK (valid_until_epoch_ms IS NULL OR valid_from_epoch_ms < valid_until_epoch_ms);
ALTER TABLE anar_core.memberships ALTER COLUMN membership_class DROP DEFAULT;
ALTER TABLE anar_core.memberships ALTER COLUMN valid_from_epoch_ms DROP DEFAULT;

CREATE TABLE anar_core.organization_external_refs (
    organization_id uuid NOT NULL REFERENCES anar_core.organizations(organization_id),
    provider text NOT NULL CHECK (provider ~ '^[a-z][a-z0-9._:-]{0,127}$'),
    external_tenant_id text NOT NULL CHECK (length(external_tenant_id) BETWEEN 1 AND 512),
    provenance_digest bytea NOT NULL CHECK (octet_length(provenance_digest) = 32),
    PRIMARY KEY (provider, external_tenant_id)
);

CREATE TABLE anar_core.organization_relationships (
    relationship_id uuid PRIMARY KEY,
    source_organization_id uuid NOT NULL REFERENCES anar_core.organizations(organization_id),
    target_organization_id uuid NOT NULL REFERENCES anar_core.organizations(organization_id),
    relationship_type text NOT NULL CHECK (relationship_type ~ '^[a-z][a-z0-9._:-]{0,127}$'),
    status text NOT NULL CHECK (status IN ('ACTIVE', 'SUSPENDED', 'REVOKED', 'EXPIRED')),
    valid_from_epoch_ms bigint NOT NULL,
    valid_until_epoch_ms bigint,
    policy_binding_id uuid,
    generation bigint NOT NULL DEFAULT 0 CHECK (generation BETWEEN 0 AND 9223372036854775806),
    CHECK (source_organization_id <> target_organization_id),
    CHECK (valid_until_epoch_ms IS NULL OR valid_from_epoch_ms < valid_until_epoch_ms)
);

CREATE TABLE anar_core.organization_units (
    unit_id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES anar_core.organizations(organization_id),
    unit_type text NOT NULL CHECK (unit_type ~ '^[a-z][a-z0-9._:-]{0,127}$'),
    canonical_name text NOT NULL CHECK (length(canonical_name) BETWEEN 1 AND 256),
    status text NOT NULL CHECK (status IN ('ACTIVE', 'SUSPENDED', 'REVOKED', 'EXPIRED')),
    generation bigint NOT NULL DEFAULT 0 CHECK (generation BETWEEN 0 AND 9223372036854775806),
    UNIQUE (organization_id, canonical_name)
);

CREATE TABLE anar_core.organization_unit_memberships (
    unit_membership_id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES anar_core.organizations(organization_id),
    unit_id uuid NOT NULL REFERENCES anar_core.organization_units(unit_id),
    membership_id uuid NOT NULL REFERENCES anar_core.memberships(membership_id),
    relation_type text NOT NULL CHECK (relation_type IN ('MEMBER', 'LEAD', 'ADMIN')),
    status text NOT NULL CHECK (status IN ('ACTIVE', 'SUSPENDED', 'REVOKED', 'EXPIRED')),
    valid_from_epoch_ms bigint NOT NULL,
    valid_until_epoch_ms bigint,
    generation bigint NOT NULL DEFAULT 0 CHECK (generation BETWEEN 0 AND 9223372036854775806),
    CHECK (valid_until_epoch_ms IS NULL OR valid_from_epoch_ms < valid_until_epoch_ms),
    UNIQUE (organization_id, unit_id, membership_id, relation_type)
);

CREATE TABLE anar_core.role_definitions (
    role_definition_id uuid PRIMARY KEY,
    namespace text NOT NULL CHECK (namespace ~ '^[a-z][a-z0-9._:-]{0,127}$'),
    symbolic_name text NOT NULL CHECK (symbolic_name ~ '^[a-z][a-z0-9._:-]{0,127}$'),
    version integer NOT NULL CHECK (version > 0),
    status text NOT NULL CHECK (status IN ('ACTIVE', 'SUSPENDED', 'REVOKED', 'EXPIRED')),
    metadata_digest bytea NOT NULL CHECK (octet_length(metadata_digest) = 32),
    UNIQUE (namespace, symbolic_name, version)
);

CREATE TABLE anar_core.role_bindings (
    role_binding_id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES anar_core.organizations(organization_id),
    membership_id uuid REFERENCES anar_core.memberships(membership_id),
    unit_id uuid REFERENCES anar_core.organization_units(unit_id),
    role_definition_id uuid NOT NULL REFERENCES anar_core.role_definitions(role_definition_id),
    status text NOT NULL CHECK (status IN ('ACTIVE', 'SUSPENDED', 'REVOKED', 'EXPIRED')),
    valid_from_epoch_ms bigint NOT NULL,
    valid_until_epoch_ms bigint,
    generation bigint NOT NULL DEFAULT 0 CHECK (generation BETWEEN 0 AND 9223372036854775806),
    CHECK ((membership_id IS NOT NULL)::integer + (unit_id IS NOT NULL)::integer = 1),
    CHECK (valid_until_epoch_ms IS NULL OR valid_from_epoch_ms < valid_until_epoch_ms)
);

CREATE TABLE anar_core.entitlement_bindings (
    entitlement_binding_id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES anar_core.organizations(organization_id),
    membership_id uuid REFERENCES anar_core.memberships(membership_id),
    principal_id uuid REFERENCES anar_core.principals(principal_id),
    package_ref text NOT NULL CHECK (package_ref ~ '^[a-z][a-z0-9._:-]{0,127}$'),
    entitlement_ref text NOT NULL CHECK (entitlement_ref ~ '^[a-z][a-z0-9._:-]{0,127}$'),
    source_system text NOT NULL CHECK (source_system ~ '^[a-z][a-z0-9._:-]{0,127}$'),
    source_digest bytea NOT NULL CHECK (octet_length(source_digest) = 32),
    status text NOT NULL CHECK (status IN ('ACTIVE', 'SUSPENDED', 'REVOKED', 'EXPIRED')),
    valid_from_epoch_ms bigint NOT NULL,
    valid_until_epoch_ms bigint,
    generation bigint NOT NULL DEFAULT 0 CHECK (generation BETWEEN 0 AND 9223372036854775806),
    CHECK (valid_until_epoch_ms IS NULL OR valid_from_epoch_ms < valid_until_epoch_ms)
);

CREATE TABLE anar_core.policy_bindings (
    policy_binding_id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES anar_core.organizations(organization_id),
    policy_ref text NOT NULL CHECK (policy_ref ~ '^[a-z][a-z0-9._:-]{0,127}$'),
    policy_version integer NOT NULL CHECK (policy_version > 0),
    compiled_policy_hash bytea NOT NULL CHECK (octet_length(compiled_policy_hash) = 32),
    policy_ir_json jsonb NOT NULL CHECK (jsonb_typeof(policy_ir_json) = 'object'),
    status text NOT NULL CHECK (status IN ('ACTIVE', 'SUSPENDED', 'REVOKED', 'EXPIRED')),
    valid_from_epoch_ms bigint NOT NULL,
    valid_until_epoch_ms bigint,
    generation bigint NOT NULL DEFAULT 0 CHECK (generation BETWEEN 0 AND 9223372036854775806),
    CHECK (valid_until_epoch_ms IS NULL OR valid_from_epoch_ms < valid_until_epoch_ms),
    UNIQUE (organization_id, policy_ref, policy_version)
);

ALTER TABLE anar_core.organization_relationships
    ADD CONSTRAINT organization_relationship_policy_fk
    FOREIGN KEY (policy_binding_id) REFERENCES anar_core.policy_bindings(policy_binding_id);

CREATE TABLE anar_core.capability_bindings (
    capability_binding_id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES anar_core.organizations(organization_id),
    capability_id text NOT NULL CHECK (capability_id ~ '^[a-z][a-z0-9._:-]{0,127}$'),
    capability_version integer NOT NULL CHECK (capability_version > 0),
    source_type text NOT NULL CHECK (source_type IN ('ROLE_BINDING', 'DELEGATION', 'GUARDIAN', 'POLICY_BINDING', 'INTERNAL_SYSTEM')),
    source_id uuid NOT NULL,
    resource_scope_json jsonb NOT NULL CHECK (jsonb_typeof(resource_scope_json) = 'object'),
    effect_scope_json jsonb NOT NULL CHECK (jsonb_typeof(effect_scope_json) = 'object'),
    constraints_json jsonb NOT NULL CHECK (jsonb_typeof(constraints_json) = 'object'),
    effective_envelope_hash bytea NOT NULL CHECK (octet_length(effective_envelope_hash) = 32),
    policy_binding_id uuid REFERENCES anar_core.policy_bindings(policy_binding_id),
    status text NOT NULL CHECK (status IN ('ACTIVE', 'SUSPENDED', 'REVOKED', 'EXPIRED')),
    valid_from_epoch_ms bigint NOT NULL,
    valid_until_epoch_ms bigint,
    generation bigint NOT NULL DEFAULT 0 CHECK (generation BETWEEN 0 AND 9223372036854775806),
    CHECK (valid_until_epoch_ms IS NULL OR valid_from_epoch_ms < valid_until_epoch_ms)
);

CREATE TABLE anar_core.delegations (
    delegation_id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES anar_core.organizations(organization_id),
    delegator_principal_id uuid NOT NULL REFERENCES anar_core.principals(principal_id),
    delegate_principal_id uuid NOT NULL REFERENCES anar_core.principals(principal_id),
    capability_id text NOT NULL CHECK (capability_id ~ '^[a-z][a-z0-9._:-]{0,127}$'),
    capability_version integer NOT NULL CHECK (capability_version > 0),
    effective_envelope_hash bytea NOT NULL CHECK (octet_length(effective_envelope_hash) = 32),
    max_uses bigint CHECK (max_uses IS NULL OR max_uses > 0),
    uses_consumed bigint NOT NULL DEFAULT 0 CHECK (uses_consumed >= 0),
    delegable boolean NOT NULL DEFAULT false,
    max_delegation_depth smallint NOT NULL DEFAULT 0 CHECK (max_delegation_depth >= 0),
    status text NOT NULL CHECK (status IN ('ACTIVE', 'SUSPENDED', 'REVOKED', 'EXPIRED')),
    issued_at_epoch_ms bigint NOT NULL,
    expires_at_epoch_ms bigint NOT NULL,
    revoked_at_epoch_ms bigint,
    generation bigint NOT NULL DEFAULT 0 CHECK (generation BETWEEN 0 AND 9223372036854775806),
    CHECK (delegator_principal_id <> delegate_principal_id),
    CHECK (uses_consumed <= coalesce(max_uses, 9223372036854775806)),
    CHECK (issued_at_epoch_ms < expires_at_epoch_ms)
);

CREATE TABLE anar_core.guardian_relationships (
    guardian_relationship_id uuid PRIMARY KEY,
    organization_id uuid REFERENCES anar_core.organizations(organization_id),
    guardian_principal_id uuid NOT NULL REFERENCES anar_core.principals(principal_id),
    protected_principal_id uuid NOT NULL REFERENCES anar_core.principals(principal_id),
    relationship_type text NOT NULL CHECK (relationship_type ~ '^[a-z][a-z0-9._:-]{0,127}$'),
    policy_ref text NOT NULL CHECK (policy_ref ~ '^[a-z][a-z0-9._:-]{0,127}$'),
    status text NOT NULL CHECK (status IN ('ACTIVE', 'SUSPENDED', 'REVOKED', 'EXPIRED')),
    valid_from_epoch_ms bigint NOT NULL,
    valid_until_epoch_ms bigint,
    generation bigint NOT NULL DEFAULT 0 CHECK (generation BETWEEN 0 AND 9223372036854775806),
    CHECK (guardian_principal_id <> protected_principal_id),
    CHECK (valid_until_epoch_ms IS NULL OR valid_from_epoch_ms < valid_until_epoch_ms)
);

CREATE TABLE anar_core.external_state_assertions (
    assertion_id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES anar_core.organizations(organization_id),
    assertion_type text NOT NULL CHECK (assertion_type ~ '^[a-z][a-z0-9._:-]{0,127}$'),
    object_ref text NOT NULL CHECK (object_ref ~ '^[a-z][a-z0-9._:-]{0,127}$'),
    object_digest bytea NOT NULL CHECK (octet_length(object_digest) = 32),
    issuer_principal_id uuid NOT NULL REFERENCES anar_core.principals(principal_id),
    issuer_class text NOT NULL CHECK (issuer_class ~ '^[a-z][a-z0-9._:-]{0,127}$'),
    issuer_system_ref text,
    assertion_payload_json jsonb NOT NULL CHECK (jsonb_typeof(assertion_payload_json) = 'object'),
    payload_digest bytea NOT NULL CHECK (octet_length(payload_digest) = 32),
    issued_at_epoch_ms bigint NOT NULL,
    valid_until_epoch_ms bigint,
    revoked_at_epoch_ms bigint,
    provenance_digest bytea NOT NULL CHECK (octet_length(provenance_digest) = 32),
    CHECK (valid_until_epoch_ms IS NULL OR issued_at_epoch_ms < valid_until_epoch_ms)
);

CREATE TABLE anar_core.evidence_issuer_allowlists (
    organization_id uuid REFERENCES anar_core.organizations(organization_id),
    assertion_type text NOT NULL CHECK (assertion_type ~ '^[a-z][a-z0-9._:-]{0,127}$'),
    issuer_class text NOT NULL CHECK (issuer_class ~ '^[a-z][a-z0-9._:-]{0,127}$'),
    status text NOT NULL CHECK (status IN ('ACTIVE', 'SUSPENDED', 'REVOKED', 'EXPIRED')),
    generation bigint NOT NULL DEFAULT 0 CHECK (generation BETWEEN 0 AND 9223372036854775806),
    UNIQUE NULLS NOT DISTINCT (organization_id, assertion_type, issuer_class)
);

CREATE TABLE anar_core.external_trust_facts (
    fact_id uuid PRIMARY KEY,
    organization_id uuid REFERENCES anar_core.organizations(organization_id),
    subject_type text NOT NULL CHECK (subject_type ~ '^[a-z][a-z0-9._:-]{0,127}$'),
    subject_ref text NOT NULL CHECK (subject_ref ~ '^[a-z][a-z0-9._:-]{0,127}$'),
    fact_type text NOT NULL CHECK (fact_type ~ '^[a-z][a-z0-9._:-]{0,127}$'),
    fact_value text NOT NULL CHECK (fact_value ~ '^[a-z][a-z0-9._:-]{0,127}$'),
    source_system text NOT NULL CHECK (source_system ~ '^[a-z][a-z0-9._:-]{0,127}$'),
    source_digest bytea NOT NULL CHECK (octet_length(source_digest) = 32),
    observed_at_epoch_ms bigint NOT NULL,
    valid_until_epoch_ms bigint,
    CHECK (valid_until_epoch_ms IS NULL OR observed_at_epoch_ms < valid_until_epoch_ms)
);

CREATE TABLE anar_core.external_revocation_facts (
    revocation_fact_id uuid PRIMARY KEY,
    organization_id uuid REFERENCES anar_core.organizations(organization_id),
    target_type text NOT NULL CHECK (target_type ~ '^[a-z][a-z0-9._:-]{0,127}$'),
    target_ref text NOT NULL CHECK (target_ref ~ '^[a-z][a-z0-9._:-]{0,127}$'),
    reason_code text NOT NULL CHECK (reason_code ~ '^[a-z][a-z0-9._:-]{0,127}$'),
    severity text NOT NULL CHECK (severity IN ('LOW', 'MODERATE', 'HIGH', 'CRITICAL')),
    source_system text NOT NULL CHECK (source_system ~ '^[a-z][a-z0-9._:-]{0,127}$'),
    source_digest bytea NOT NULL CHECK (octet_length(source_digest) = 32),
    effective_at_epoch_ms bigint NOT NULL
);

CREATE TABLE anar_core.elevation_grants (
    elevation_id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES anar_core.organizations(organization_id),
    principal_id uuid NOT NULL REFERENCES anar_core.principals(principal_id),
    capability_id text NOT NULL CHECK (capability_id ~ '^[a-z][a-z0-9._:-]{0,127}$'),
    effective_envelope_hash bytea NOT NULL CHECK (octet_length(effective_envelope_hash) = 32),
    purpose_code text NOT NULL CHECK (purpose_code ~ '^[a-z][a-z0-9._:-]{0,127}$'),
    reason_digest bytea NOT NULL CHECK (octet_length(reason_digest) = 32),
    max_uses integer NOT NULL DEFAULT 1 CHECK (max_uses > 0),
    uses_consumed integer NOT NULL DEFAULT 0 CHECK (uses_consumed BETWEEN 0 AND max_uses),
    issued_by_principal_id uuid NOT NULL REFERENCES anar_core.principals(principal_id),
    issued_at_epoch_ms bigint NOT NULL,
    expires_at_epoch_ms bigint NOT NULL,
    revoked_at_epoch_ms bigint,
    generation bigint NOT NULL DEFAULT 0 CHECK (generation BETWEEN 0 AND 9223372036854775806),
    CHECK (issued_at_epoch_ms < expires_at_epoch_ms)
);

CREATE TABLE anar_core.capability_requests (
    request_id uuid PRIMARY KEY,
    authority_context_id uuid NOT NULL REFERENCES anar_core.authority_contexts(authority_context_id),
    organization_id uuid NOT NULL REFERENCES anar_core.organizations(organization_id),
    purpose_code text NOT NULL CHECK (purpose_code ~ '^[a-z][a-z0-9._:-]{0,127}$'),
    capability_id text NOT NULL CHECK (capability_id ~ '^[a-z][a-z0-9._:-]{0,127}$'),
    capability_version integer NOT NULL CHECK (capability_version > 0),
    resource_scope_json jsonb NOT NULL CHECK (jsonb_typeof(resource_scope_json) = 'object'),
    effect_scope_json jsonb NOT NULL CHECK (jsonb_typeof(effect_scope_json) = 'object'),
    requested_constraints_json jsonb NOT NULL CHECK (jsonb_typeof(requested_constraints_json) = 'object'),
    cal_semantic_hash bytea NOT NULL CHECK (octet_length(cal_semantic_hash) = 32),
    request_semantic_hash bytea NOT NULL CHECK (octet_length(request_semantic_hash) = 32),
    package_ref text,
    manifest_hash bytea CHECK (manifest_hash IS NULL OR octet_length(manifest_hash) = 32),
    requested_at_epoch_ms bigint NOT NULL
);

ALTER TABLE anar_core.decisions
    ADD CONSTRAINT decision_request_fk
    FOREIGN KEY (request_id) REFERENCES anar_core.capability_requests(request_id) ON DELETE RESTRICT;

CREATE OR REPLACE FUNCTION anar_core.enforce_decision_request_binding()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, anar_core
AS $function$
DECLARE
    v_request anar_core.capability_requests%ROWTYPE;
    v_context anar_core.authority_contexts%ROWTYPE;
BEGIN
    SELECT * INTO v_request FROM anar_core.capability_requests WHERE request_id = NEW.request_id;
    SELECT * INTO v_context FROM anar_core.authority_contexts
     WHERE authority_context_id = v_request.authority_context_id;
    IF v_request.request_id IS NULL
       OR v_context.authority_context_id IS NULL
       OR v_request.organization_id IS DISTINCT FROM NEW.organization_id
       OR v_request.authority_context_id IS DISTINCT FROM NEW.authority_context_id
       OR v_request.purpose_code IS DISTINCT FROM NEW.purpose_code
       OR v_request.capability_id IS DISTINCT FROM NEW.capability_id
       OR v_request.capability_version IS DISTINCT FROM NEW.capability_version
       OR v_request.cal_semantic_hash IS DISTINCT FROM NEW.cal_semantic_hash
       OR v_request.request_semantic_hash IS DISTINCT FROM NEW.request_semantic_hash
       OR v_context.principal_id IS DISTINCT FROM NEW.principal_id
       OR v_context.organization_id IS DISTINCT FROM NEW.organization_id
       OR v_context.membership_id IS DISTINCT FROM NEW.membership_id
       OR v_context.authenticator_id IS DISTINCT FROM NEW.authenticator_id
    THEN
        RAISE EXCEPTION USING ERRCODE = 'AR003', MESSAGE = 'decision does not bind the immutable capability request and authority context';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE TRIGGER decisions_bind_immutable_request
BEFORE INSERT ON anar_core.decisions
FOR EACH ROW EXECUTE FUNCTION anar_core.enforce_decision_request_binding();

COMMIT;

