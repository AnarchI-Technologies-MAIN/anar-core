BEGIN;

REVOKE ALL ON ALL TABLES IN SCHEMA anar_core FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA anar_core FROM PUBLIC;
REVOKE ALL ON FUNCTION anar_core.enforce_decision_request_binding() FROM PUBLIC;

GRANT SELECT ON anar_core.organization_external_refs,
                anar_core.organization_relationships,
                anar_core.organization_units,
                anar_core.organization_unit_memberships,
                anar_core.role_definitions,
                anar_core.role_bindings,
                anar_core.entitlement_bindings,
                anar_core.policy_bindings,
                anar_core.capability_bindings,
                anar_core.delegations,
                anar_core.guardian_relationships,
                anar_core.external_state_assertions,
                anar_core.evidence_issuer_allowlists,
                anar_core.external_trust_facts,
                anar_core.external_revocation_facts,
                anar_core.elevation_grants,
                anar_core.capability_requests
TO anar_core_runtime;

ALTER TABLE anar_core.organization_external_refs ENABLE ROW LEVEL SECURITY;
ALTER TABLE anar_core.organization_external_refs FORCE ROW LEVEL SECURITY;
CREATE POLICY organization_external_ref_isolation ON anar_core.organization_external_refs
    USING (organization_id = nullif(current_setting('anar.organization_id', true), '')::uuid);

ALTER TABLE anar_core.organization_relationships ENABLE ROW LEVEL SECURITY;
ALTER TABLE anar_core.organization_relationships FORCE ROW LEVEL SECURITY;
CREATE POLICY organization_relationship_isolation ON anar_core.organization_relationships
    USING (
        source_organization_id = nullif(current_setting('anar.organization_id', true), '')::uuid
        OR target_organization_id = nullif(current_setting('anar.organization_id', true), '')::uuid
    );

ALTER TABLE anar_core.organization_units ENABLE ROW LEVEL SECURITY;
ALTER TABLE anar_core.organization_units FORCE ROW LEVEL SECURITY;
CREATE POLICY organization_unit_isolation ON anar_core.organization_units
    USING (organization_id = nullif(current_setting('anar.organization_id', true), '')::uuid);

ALTER TABLE anar_core.organization_unit_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE anar_core.organization_unit_memberships FORCE ROW LEVEL SECURITY;
CREATE POLICY organization_unit_membership_isolation ON anar_core.organization_unit_memberships
    USING (organization_id = nullif(current_setting('anar.organization_id', true), '')::uuid);

ALTER TABLE anar_core.role_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE anar_core.role_bindings FORCE ROW LEVEL SECURITY;
CREATE POLICY role_binding_isolation ON anar_core.role_bindings
    USING (organization_id = nullif(current_setting('anar.organization_id', true), '')::uuid);

ALTER TABLE anar_core.entitlement_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE anar_core.entitlement_bindings FORCE ROW LEVEL SECURITY;
CREATE POLICY entitlement_binding_isolation ON anar_core.entitlement_bindings
    USING (organization_id = nullif(current_setting('anar.organization_id', true), '')::uuid);

ALTER TABLE anar_core.policy_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE anar_core.policy_bindings FORCE ROW LEVEL SECURITY;
CREATE POLICY policy_binding_isolation ON anar_core.policy_bindings
    USING (organization_id = nullif(current_setting('anar.organization_id', true), '')::uuid);

ALTER TABLE anar_core.capability_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE anar_core.capability_bindings FORCE ROW LEVEL SECURITY;
CREATE POLICY capability_binding_isolation ON anar_core.capability_bindings
    USING (organization_id = nullif(current_setting('anar.organization_id', true), '')::uuid);

ALTER TABLE anar_core.delegations ENABLE ROW LEVEL SECURITY;
ALTER TABLE anar_core.delegations FORCE ROW LEVEL SECURITY;
CREATE POLICY delegation_isolation ON anar_core.delegations
    USING (organization_id = nullif(current_setting('anar.organization_id', true), '')::uuid);

ALTER TABLE anar_core.guardian_relationships ENABLE ROW LEVEL SECURITY;
ALTER TABLE anar_core.guardian_relationships FORCE ROW LEVEL SECURITY;
CREATE POLICY guardian_relationship_isolation ON anar_core.guardian_relationships
    USING (organization_id = nullif(current_setting('anar.organization_id', true), '')::uuid);

ALTER TABLE anar_core.external_state_assertions ENABLE ROW LEVEL SECURITY;
ALTER TABLE anar_core.external_state_assertions FORCE ROW LEVEL SECURITY;
CREATE POLICY external_state_assertion_isolation ON anar_core.external_state_assertions
    USING (organization_id = nullif(current_setting('anar.organization_id', true), '')::uuid);

ALTER TABLE anar_core.evidence_issuer_allowlists ENABLE ROW LEVEL SECURITY;
ALTER TABLE anar_core.evidence_issuer_allowlists FORCE ROW LEVEL SECURITY;
CREATE POLICY evidence_issuer_allowlist_isolation ON anar_core.evidence_issuer_allowlists
    USING (
        organization_id IS NULL
        OR organization_id = nullif(current_setting('anar.organization_id', true), '')::uuid
    );

ALTER TABLE anar_core.external_trust_facts ENABLE ROW LEVEL SECURITY;
ALTER TABLE anar_core.external_trust_facts FORCE ROW LEVEL SECURITY;
CREATE POLICY external_trust_fact_isolation ON anar_core.external_trust_facts
    USING (
        organization_id IS NULL
        OR organization_id = nullif(current_setting('anar.organization_id', true), '')::uuid
    );

ALTER TABLE anar_core.external_revocation_facts ENABLE ROW LEVEL SECURITY;
ALTER TABLE anar_core.external_revocation_facts FORCE ROW LEVEL SECURITY;
CREATE POLICY external_revocation_fact_isolation ON anar_core.external_revocation_facts
    USING (
        organization_id IS NULL
        OR organization_id = nullif(current_setting('anar.organization_id', true), '')::uuid
    );

ALTER TABLE anar_core.elevation_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE anar_core.elevation_grants FORCE ROW LEVEL SECURITY;
CREATE POLICY elevation_grant_isolation ON anar_core.elevation_grants
    USING (organization_id = nullif(current_setting('anar.organization_id', true), '')::uuid);

ALTER TABLE anar_core.capability_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE anar_core.capability_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY capability_request_isolation ON anar_core.capability_requests
    USING (organization_id = nullif(current_setting('anar.organization_id', true), '')::uuid);

COMMIT;

