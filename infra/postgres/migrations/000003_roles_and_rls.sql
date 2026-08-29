BEGIN;

DO $block$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anar_core_runtime') THEN
        CREATE ROLE anar_core_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anar_core_migrator') THEN
        CREATE ROLE anar_core_migrator NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
    END IF;
END;
$block$;

REVOKE ALL ON SCHEMA anar_core FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA anar_core FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA anar_core FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA anar_core FROM PUBLIC;

GRANT USAGE ON SCHEMA anar_core TO anar_core_runtime;
GRANT SELECT ON anar_core.organizations,
                anar_core.memberships,
                anar_core.authority_contexts,
                anar_core.organization_authority_sync,
                anar_core.authority_dependency_state,
                anar_core.decisions,
                anar_core.decision_receipts,
                anar_core.internal_mutation_grants,
                anar_core.authority_mutation_events
TO anar_core_runtime;
GRANT EXECUTE ON FUNCTION anar_core.finalize_decision_rehearsal(
    uuid, uuid, uuid, text, uuid, uuid, uuid, uuid, uuid, text, integer,
    text, bytea, text, text[], bytea, bytea, bytea, bytea, bytea, jsonb, bigint, bigint,
    bigint, bigint, bigint, bigint, bigint, bigint
) TO anar_core_runtime;
GRANT EXECUTE ON FUNCTION anar_core.execute_membership_revocation(
    uuid, uuid, uuid, uuid, uuid, bytea, text, bytea, bigint
) TO anar_core_runtime;

ALTER TABLE anar_core.organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE anar_core.organizations FORCE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON anar_core.organizations
    USING (organization_id = nullif(current_setting('anar.organization_id', true), '')::uuid);

ALTER TABLE anar_core.memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE anar_core.memberships FORCE ROW LEVEL SECURITY;
CREATE POLICY membership_isolation ON anar_core.memberships
    USING (organization_id = nullif(current_setting('anar.organization_id', true), '')::uuid);

ALTER TABLE anar_core.authority_contexts ENABLE ROW LEVEL SECURITY;
ALTER TABLE anar_core.authority_contexts FORCE ROW LEVEL SECURITY;
CREATE POLICY authority_context_isolation ON anar_core.authority_contexts
    USING (organization_id = nullif(current_setting('anar.organization_id', true), '')::uuid);

ALTER TABLE anar_core.organization_authority_sync ENABLE ROW LEVEL SECURITY;
ALTER TABLE anar_core.organization_authority_sync FORCE ROW LEVEL SECURITY;
CREATE POLICY organization_sync_isolation ON anar_core.organization_authority_sync
    USING (organization_id = nullif(current_setting('anar.organization_id', true), '')::uuid);

ALTER TABLE anar_core.authority_dependency_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE anar_core.authority_dependency_state FORCE ROW LEVEL SECURITY;
CREATE POLICY dependency_isolation ON anar_core.authority_dependency_state
    USING (
        organization_id IS NULL
        OR organization_id = nullif(current_setting('anar.organization_id', true), '')::uuid
    );

ALTER TABLE anar_core.decisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE anar_core.decisions FORCE ROW LEVEL SECURITY;
CREATE POLICY decision_isolation ON anar_core.decisions
    USING (organization_id = nullif(current_setting('anar.organization_id', true), '')::uuid);

ALTER TABLE anar_core.decision_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE anar_core.decision_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY receipt_isolation ON anar_core.decision_receipts
    USING (organization_id = nullif(current_setting('anar.organization_id', true), '')::uuid);

ALTER TABLE anar_core.internal_mutation_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE anar_core.internal_mutation_grants FORCE ROW LEVEL SECURITY;
CREATE POLICY mutation_grant_isolation ON anar_core.internal_mutation_grants
    USING (organization_id = nullif(current_setting('anar.organization_id', true), '')::uuid);

ALTER TABLE anar_core.authority_mutation_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE anar_core.authority_mutation_events FORCE ROW LEVEL SECURITY;
CREATE POLICY mutation_event_isolation ON anar_core.authority_mutation_events
    USING (organization_id = nullif(current_setting('anar.organization_id', true), '')::uuid);

COMMIT;
