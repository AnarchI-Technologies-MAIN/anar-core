\set ON_ERROR_STOP on
SET anar.organization_id = '20000000-0000-4000-8000-000000000001';

CREATE TEMP TABLE first_result AS
SELECT * FROM anar_core.finalize_decision_rehearsal(
    '70000000-0000-4000-8000-000000000001',
    '80000000-0000-4000-8000-000000000001',
    '90000000-0000-4000-8000-000000000001',
    'phase0.primary',
    '10000000-0000-4000-8000-000000000001',
    '20000000-0000-4000-8000-000000000001',
    '30000000-0000-4000-8000-000000000001',
    '40000000-0000-4000-8000-000000000001',
    '50000000-0000-4000-8000-000000000001',
    'authority.membership.revoke', 1, 'authority.membership.revoke',
    decode(repeat('11', 32), 'hex'), 'ALLOW', ARRAY['CURRENT_AUTHORITY_PROVEN'],
    decode(repeat('21', 32), 'hex'), decode(repeat('22', 32), 'hex'),
    decode(repeat('23', 32), 'hex'), decode(repeat('24', 32), 'hex'),
    decode(repeat('25', 32), 'hex'),
    '[{"dependency_type":1,"organization_id":"20000000-0000-4000-8000-000000000001","dependency_id":"60000000-0000-4000-8000-000000000001","expected_generation":3,"expected_digest":null,"expected_status":"ACTIVE"}]'::jsonb,
    2, 4, 5, 6, 7, 0, 0, 1800000000000
);

DO $proof$
DECLARE
    v_replay record;
BEGIN
    SELECT * INTO v_replay FROM anar_core.finalize_decision_rehearsal(
        '70000000-0000-4000-8000-000000000001',
        '80000000-0000-4000-8000-000000000001',
        '90000000-0000-4000-8000-000000000001',
        'phase0.primary',
        '10000000-0000-4000-8000-000000000001',
        '20000000-0000-4000-8000-000000000001',
        '30000000-0000-4000-8000-000000000001',
        '40000000-0000-4000-8000-000000000001',
        '50000000-0000-4000-8000-000000000001',
        'authority.membership.revoke', 1, 'authority.membership.revoke',
        decode(repeat('11', 32), 'hex'), 'ALLOW', ARRAY['CURRENT_AUTHORITY_PROVEN'],
        decode(repeat('21', 32), 'hex'), decode(repeat('22', 32), 'hex'),
        decode(repeat('23', 32), 'hex'), decode(repeat('24', 32), 'hex'),
        decode(repeat('25', 32), 'hex'),
        '[{"dependency_type":1,"organization_id":"20000000-0000-4000-8000-000000000001","dependency_id":"60000000-0000-4000-8000-000000000001","expected_generation":3,"expected_digest":null,"expected_status":"ACTIVE"}]'::jsonb,
        2, 4, 5, 6, 7, 0, 0, 1800000000000
    );
    IF NOT v_replay.replayed THEN
        RAISE EXCEPTION 'exact retry did not report replay';
    END IF;
    IF v_replay.witness_sha256_hex IS DISTINCT FROM (SELECT witness_sha256_hex FROM first_result) THEN
        RAISE EXCEPTION 'exact retry changed witness hash';
    END IF;

    BEGIN
        PERFORM * FROM anar_core.finalize_decision_rehearsal(
            '70000000-0000-4000-8000-000000000001',
            '80000000-0000-4000-8000-000000000001',
            '90000000-0000-4000-8000-000000000001',
            'phase0.primary',
            '10000000-0000-4000-8000-000000000001',
            '20000000-0000-4000-8000-000000000001',
            '30000000-0000-4000-8000-000000000001',
            '40000000-0000-4000-8000-000000000001',
            '50000000-0000-4000-8000-000000000001',
            'authority.membership.revoke', 1, 'authority.membership.revoke',
            decode(repeat('11', 32), 'hex'), 'ALLOW', ARRAY['CURRENT_AUTHORITY_PROVEN'],
            decode(repeat('31', 32), 'hex'), decode(repeat('22', 32), 'hex'),
            decode(repeat('23', 32), 'hex'), decode(repeat('24', 32), 'hex'),
            decode(repeat('25', 32), 'hex'), '[]'::jsonb,
            2, 4, 5, 6, 7, 0, 0, 1800000000000
        );
        RAISE EXCEPTION 'changed-input idempotency conflict was not denied';
    EXCEPTION WHEN SQLSTATE 'AR007' THEN
        NULL;
    END;
END;
$proof$;

DO $proof$
BEGIN
    BEGIN
        INSERT INTO anar_core.decisions
        SELECT
            '70000000-0000-4000-8000-000000000099'::uuid,
            '80000000-0000-4000-8000-000000000099'::uuid,
            request_id,
            'phase0.request-binding-smuggle',
            principal_id, organization_id, membership_id, authenticator_id,
            authority_context_id, purpose_code, capability_id, capability_version,
            cal_semantic_hash, outcome, reason_codes,
            decode(repeat('99', 32), 'hex'),
            evaluation_snapshot_hash, policy_bundle_hash, evidence_bundle_hash,
            dependency_bundle_hash, principal_generation, organization_generation,
            membership_generation, authenticator_generation,
            authority_context_generation, 99, 99,
            principal_global_revocation_epoch, organization_revocation_epoch,
            issued_at_epoch_ms
        FROM anar_core.decisions
        WHERE decision_id = '70000000-0000-4000-8000-000000000001';
        RAISE EXCEPTION 'immutable request mismatch was not denied';
    EXCEPTION WHEN SQLSTATE 'AR003' THEN
        NULL;
    END;
    IF EXISTS (SELECT 1 FROM anar_core.decisions WHERE idempotency_key = 'phase0.request-binding-smuggle') THEN
        RAISE EXCEPTION 'immutable request mismatch persisted a decision';
    END IF;
END;
$proof$;

DO $proof$
BEGIN
    UPDATE anar_core.authority_dependency_state SET generation = 4
     WHERE dependency_id = '60000000-0000-4000-8000-000000000001';
    BEGIN
        PERFORM * FROM anar_core.finalize_decision_rehearsal(
            '70000000-0000-4000-8000-000000000002',
            '80000000-0000-4000-8000-000000000002',
            '90000000-0000-4000-8000-000000000002',
            'phase0.stale-dependency',
            '10000000-0000-4000-8000-000000000001',
            '20000000-0000-4000-8000-000000000001',
            '30000000-0000-4000-8000-000000000001',
            '40000000-0000-4000-8000-000000000001',
            '50000000-0000-4000-8000-000000000001',
            'authority.membership.revoke', 1, 'authority.membership.revoke',
            decode(repeat('11', 32), 'hex'), 'ALLOW', ARRAY['CURRENT_AUTHORITY_PROVEN'],
            decode(repeat('41', 32), 'hex'), decode(repeat('42', 32), 'hex'),
            decode(repeat('43', 32), 'hex'), decode(repeat('44', 32), 'hex'),
            decode(repeat('45', 32), 'hex'),
            '[{"dependency_type":1,"organization_id":"20000000-0000-4000-8000-000000000001","dependency_id":"60000000-0000-4000-8000-000000000001","expected_generation":3,"expected_digest":null,"expected_status":"ACTIVE"}]'::jsonb,
            2, 4, 5, 6, 7, 0, 0, 1800000000000
        );
        RAISE EXCEPTION 'stale dependency was not denied';
    EXCEPTION WHEN SQLSTATE 'AR001' THEN
        NULL;
    END;
    UPDATE anar_core.authority_dependency_state SET generation = 3
     WHERE dependency_id = '60000000-0000-4000-8000-000000000001';
END;
$proof$;

DO $proof$
BEGIN
    PERFORM set_config('anar.organization_id', '20000000-0000-4000-8000-000000000002', false);
    BEGIN
        PERFORM * FROM anar_core.finalize_decision_rehearsal(
            '70000000-0000-4000-8000-000000000003',
            '80000000-0000-4000-8000-000000000003',
            '90000000-0000-4000-8000-000000000003',
            'phase0.wrong-tenant',
            '10000000-0000-4000-8000-000000000001',
            '20000000-0000-4000-8000-000000000001',
            '30000000-0000-4000-8000-000000000001',
            '40000000-0000-4000-8000-000000000001',
            '50000000-0000-4000-8000-000000000001',
            'authority.membership.revoke', 1, 'authority.membership.revoke',
            decode(repeat('11', 32), 'hex'), 'ALLOW', ARRAY['CURRENT_AUTHORITY_PROVEN'],
            decode(repeat('51', 32), 'hex'), decode(repeat('52', 32), 'hex'),
            decode(repeat('53', 32), 'hex'), decode(repeat('54', 32), 'hex'),
            decode(repeat('55', 32), 'hex'), '[]'::jsonb,
            2, 4, 5, 6, 7, 0, 0, 1800000000000
        );
        RAISE EXCEPTION 'wrong tenant was not denied';
    EXCEPTION WHEN SQLSTATE 'AR003' THEN
        NULL;
    END;
    PERFORM set_config('anar.organization_id', '20000000-0000-4000-8000-000000000001', false);
END;
$proof$;

DO $proof$
DECLARE
    v_decisions bigint;
    v_receipts bigint;
    v_principal_sequence bigint;
    v_organization_sequence bigint;
BEGIN
    SELECT count(*) INTO v_decisions FROM anar_core.decisions;
    SELECT count(*) INTO v_receipts FROM anar_core.decision_receipts;
    SELECT global_sequence INTO v_principal_sequence FROM anar_core.principal_authority_sync
     WHERE principal_id = '10000000-0000-4000-8000-000000000001';
    SELECT decision_sequence INTO v_organization_sequence FROM anar_core.organization_authority_sync
     WHERE organization_id = '20000000-0000-4000-8000-000000000001';
    IF v_decisions <> 1 OR v_receipts <> 1
       OR v_principal_sequence <> 1 OR v_organization_sequence <> 1 THEN
        RAISE EXCEPTION 'denial path changed durable finalization state';
    END IF;
    IF EXISTS (
        SELECT 1 FROM anar_core.decision_receipts
         WHERE canonical_receipt_sha256 IS DISTINCT FROM digest(convert_to(canonical_receipt::text, 'UTF8'), 'sha256')
    ) THEN
        RAISE EXCEPTION 'stored witness hash does not match stored witness bytes';
    END IF;
END;
$proof$;

DO $proof$
BEGIN
    UPDATE anar_core.principal_authority_sync
       SET global_sequence = 9223372036854775806
     WHERE principal_id = '10000000-0000-4000-8000-000000000001';
    BEGIN
        PERFORM * FROM anar_core.finalize_decision_rehearsal(
            '70000000-0000-4000-8000-000000000004',
            '80000000-0000-4000-8000-000000000004',
            '90000000-0000-4000-8000-000000000004',
            'phase0.sequence-exhaustion',
            '10000000-0000-4000-8000-000000000001',
            '20000000-0000-4000-8000-000000000001',
            '30000000-0000-4000-8000-000000000001',
            '40000000-0000-4000-8000-000000000001',
            '50000000-0000-4000-8000-000000000001',
            'authority.membership.revoke', 1, 'authority.membership.revoke',
            decode(repeat('11', 32), 'hex'), 'ALLOW', ARRAY['CURRENT_AUTHORITY_PROVEN'],
            decode(repeat('71', 32), 'hex'), decode(repeat('72', 32), 'hex'),
            decode(repeat('73', 32), 'hex'), decode(repeat('74', 32), 'hex'),
            decode(repeat('75', 32), 'hex'),
            '[{"dependency_type":1,"organization_id":"20000000-0000-4000-8000-000000000001","dependency_id":"60000000-0000-4000-8000-000000000001","expected_generation":3,"expected_digest":null,"expected_status":"ACTIVE"}]'::jsonb,
            2, 4, 5, 6, 7, 0, 0, 1800000000000
        );
        RAISE EXCEPTION 'sequence exhaustion was not denied';
    EXCEPTION WHEN SQLSTATE 'AR006' THEN
        NULL;
    END;
    UPDATE anar_core.principal_authority_sync
       SET global_sequence = 1
     WHERE principal_id = '10000000-0000-4000-8000-000000000001';
    IF EXISTS (SELECT 1 FROM anar_core.decisions WHERE idempotency_key = 'phase0.sequence-exhaustion') THEN
        RAISE EXCEPTION 'sequence exhaustion persisted a decision';
    END IF;
END;
$proof$;

INSERT INTO anar_core.internal_mutation_grants (
    mutation_grant_id, decision_receipt_id, actor_principal_id, organization_id,
    capability_id, target_type, target_ref, target_digest, purpose_code,
    effect_scope_hash, issued_at_epoch_ms, expires_at_epoch_ms
) VALUES (
    'a0000000-0000-4000-8000-000000000001',
    '80000000-0000-4000-8000-000000000001',
    '10000000-0000-4000-8000-000000000001',
    '20000000-0000-4000-8000-000000000001',
    'authority.membership.revoke', 'membership',
    '30000000-0000-4000-8000-000000000001',
    decode(repeat('61', 32), 'hex'), 'authority.membership.revoke',
    decode(repeat('62', 32), 'hex'), 1800000000000, 1800000060000
);

DO $proof$
BEGIN
    BEGIN
        PERFORM anar_core.execute_membership_revocation(
            'b0000000-0000-4000-8000-000000000000',
            'a0000000-0000-4000-8000-000000000001',
            '10000000-0000-4000-8000-000000000001',
            '20000000-0000-4000-8000-000000000001',
            '30000000-0000-4000-8000-000000000001',
            decode(repeat('ff', 32), 'hex'),
            'authority.membership.revoke', decode(repeat('62', 32), 'hex'),
            1800000001000
        );
        RAISE EXCEPTION 'mutated target digest was not denied';
    EXCEPTION WHEN SQLSTATE 'AR003' THEN
        NULL;
    END;
    IF (SELECT status FROM anar_core.memberships WHERE membership_id = '30000000-0000-4000-8000-000000000001') <> 'ACTIVE' THEN
        RAISE EXCEPTION 'denied mutation changed membership';
    END IF;
END;
$proof$;

SELECT witness_sha256_hex, replayed FROM first_result;
