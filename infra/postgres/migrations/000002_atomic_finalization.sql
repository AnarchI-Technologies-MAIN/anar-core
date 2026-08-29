BEGIN;

CREATE OR REPLACE FUNCTION anar_core.revalidate_dependency_vector(p_vector jsonb)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, anar_core
AS $function$
DECLARE
    v_dependency record;
    v_current record;
    v_count bigint;
    v_distinct_count bigint;
BEGIN
    IF jsonb_typeof(p_vector) IS DISTINCT FROM 'array' THEN
        RAISE EXCEPTION USING ERRCODE = 'AR004', MESSAGE = 'dependency vector must be an array';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM jsonb_array_elements(p_vector) AS element(value)
        WHERE jsonb_typeof(value) IS DISTINCT FROM 'object'
           OR EXISTS (
               SELECT 1
               FROM jsonb_object_keys(value) AS key(name)
               WHERE name NOT IN (
                   'dependency_type', 'organization_id', 'dependency_id',
                   'expected_generation', 'expected_digest', 'expected_status'
               )
           )
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'AR004', MESSAGE = 'dependency vector contains an unknown field or non-object entry';
    END IF;

    SELECT count(*),
           count(DISTINCT concat_ws(':', dependency_type::text, coalesce(organization_id, ''), dependency_id::text))
      INTO v_count, v_distinct_count
      FROM jsonb_to_recordset(p_vector) AS dependency(
          dependency_type smallint,
          organization_id text,
          dependency_id uuid,
          expected_generation bigint,
          expected_digest text,
          expected_status text
      );

    IF v_count IS DISTINCT FROM v_distinct_count THEN
        RAISE EXCEPTION USING ERRCODE = 'AR005', MESSAGE = 'dependency vector contains duplicate semantic keys';
    END IF;

    FOR v_dependency IN
        SELECT dependency_type,
               nullif(organization_id, '')::uuid AS organization_id,
               dependency_id,
               expected_generation,
               expected_digest,
               expected_status
          FROM jsonb_to_recordset(p_vector) AS dependency(
              dependency_type smallint,
              organization_id text,
              dependency_id uuid,
              expected_generation bigint,
              expected_digest text,
              expected_status text
          )
         ORDER BY dependency_type, nullif(organization_id, '')::uuid NULLS FIRST, dependency_id
    LOOP
        IF v_dependency.dependency_type IS NULL
           OR v_dependency.dependency_id IS NULL
           OR v_dependency.dependency_type NOT BETWEEN 1 AND 8
           OR (v_dependency.expected_generation IS NULL
               AND v_dependency.expected_digest IS NULL
               AND v_dependency.expected_status IS NULL)
        THEN
            RAISE EXCEPTION USING ERRCODE = 'AR004', MESSAGE = 'dependency entry is incomplete';
        END IF;
        IF v_dependency.expected_digest IS NOT NULL
           AND v_dependency.expected_digest !~ '^[0-9a-f]{64}$'
        THEN
            RAISE EXCEPTION USING ERRCODE = 'AR004', MESSAGE = 'dependency digest is not canonical lowercase SHA-256';
        END IF;

        SELECT generation, semantic_hash, status
          INTO v_current
          FROM anar_core.authority_dependency_state
         WHERE dependency_type = v_dependency.dependency_type
           AND organization_id IS NOT DISTINCT FROM v_dependency.organization_id
           AND dependency_id = v_dependency.dependency_id
         FOR UPDATE;

        IF NOT FOUND THEN
            RAISE EXCEPTION USING ERRCODE = 'AR002', MESSAGE = 'dependency unavailable';
        END IF;

        IF v_current.generation IS DISTINCT FROM v_dependency.expected_generation
           OR v_current.status IS DISTINCT FROM v_dependency.expected_status
           OR v_current.semantic_hash IS DISTINCT FROM (
                  CASE
                      WHEN v_dependency.expected_digest IS NULL THEN NULL::bytea
                      ELSE decode(v_dependency.expected_digest, 'hex')
                  END
              )
        THEN
            RAISE EXCEPTION USING ERRCODE = 'AR001', MESSAGE = 'dependency stale';
        END IF;
    END LOOP;
END;
$function$;

CREATE OR REPLACE FUNCTION anar_core.finalize_decision_rehearsal(
    p_decision_id uuid,
    p_receipt_id uuid,
    p_request_id uuid,
    p_idempotency_key text,
    p_principal_id uuid,
    p_organization_id uuid,
    p_membership_id uuid,
    p_authenticator_id uuid,
    p_authority_context_id uuid,
    p_capability_id text,
    p_capability_version integer,
    p_purpose_code text,
    p_cal_semantic_hash bytea,
    p_outcome text,
    p_reason_codes text[],
    p_request_semantic_hash bytea,
    p_evaluation_snapshot_hash bytea,
    p_policy_bundle_hash bytea,
    p_evidence_bundle_hash bytea,
    p_dependency_bundle_hash bytea,
    p_dependency_vector jsonb,
    p_expected_principal_generation bigint,
    p_expected_organization_generation bigint,
    p_expected_membership_generation bigint,
    p_expected_authenticator_generation bigint,
    p_expected_context_generation bigint,
    p_expected_principal_revocation_epoch bigint,
    p_expected_organization_revocation_epoch bigint,
    p_issued_at_epoch_ms bigint
)
RETURNS TABLE (
    decision_id uuid,
    receipt_id uuid,
    principal_global_sequence bigint,
    organization_decision_sequence bigint,
    witness_sha256_hex text,
    replayed boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, anar_core
AS $function$
DECLARE
    v_principal anar_core.principals%ROWTYPE;
    v_organization anar_core.organizations%ROWTYPE;
    v_membership anar_core.memberships%ROWTYPE;
    v_authenticator anar_core.authenticators%ROWTYPE;
    v_context anar_core.authority_contexts%ROWTYPE;
    v_existing anar_core.decisions%ROWTYPE;
    v_principal_sequence bigint;
    v_organization_sequence bigint;
    v_witness jsonb;
    v_witness_sha256 bytea;
BEGIN
    IF nullif(current_setting('anar.organization_id', true), '')::uuid
       IS DISTINCT FROM p_organization_id
    THEN
        RAISE EXCEPTION USING ERRCODE = 'AR003', MESSAGE = 'session organization does not match requested organization';
    END IF;

    IF p_idempotency_key !~ '^[a-zA-Z0-9._:-]{1,160}$'
       OR p_capability_id !~ '^[a-z][a-z0-9._:-]{0,127}$'
       OR p_capability_version <= 0
       OR p_purpose_code !~ '^[a-z][a-z0-9._:-]{0,127}$'
       OR octet_length(p_cal_semantic_hash) IS DISTINCT FROM 32
       OR p_outcome NOT IN ('ALLOW', 'DENY', 'REQUIRE_APPROVAL')
       OR coalesce(cardinality(p_reason_codes), 0) = 0
       OR octet_length(p_request_semantic_hash) IS DISTINCT FROM 32
       OR octet_length(p_evaluation_snapshot_hash) IS DISTINCT FROM 32
       OR octet_length(p_policy_bundle_hash) IS DISTINCT FROM 32
       OR octet_length(p_evidence_bundle_hash) IS DISTINCT FROM 32
       OR octet_length(p_dependency_bundle_hash) IS DISTINCT FROM 32
    THEN
        RAISE EXCEPTION USING ERRCODE = 'AR004', MESSAGE = 'invalid finalization input';
    END IF;

    SELECT global_sequence INTO v_principal_sequence
      FROM anar_core.principal_authority_sync
     WHERE principal_id = p_principal_id
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'AR002', MESSAGE = 'principal synchronization row unavailable';
    END IF;

    SELECT decision_sequence INTO v_organization_sequence
      FROM anar_core.organization_authority_sync
     WHERE organization_id = p_organization_id
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'AR002', MESSAGE = 'organization synchronization row unavailable';
    END IF;

    SELECT * INTO v_existing
      FROM anar_core.decisions
     WHERE organization_id = p_organization_id
       AND idempotency_key = p_idempotency_key;
    IF FOUND THEN
        IF v_existing.request_id IS DISTINCT FROM p_request_id
           OR v_existing.request_semantic_hash IS DISTINCT FROM p_request_semantic_hash
           OR v_existing.decision_id IS DISTINCT FROM p_decision_id
           OR v_existing.receipt_id IS DISTINCT FROM p_receipt_id
           OR v_existing.principal_id IS DISTINCT FROM p_principal_id
           OR v_existing.organization_id IS DISTINCT FROM p_organization_id
           OR v_existing.membership_id IS DISTINCT FROM p_membership_id
           OR v_existing.authenticator_id IS DISTINCT FROM p_authenticator_id
           OR v_existing.authority_context_id IS DISTINCT FROM p_authority_context_id
           OR v_existing.purpose_code IS DISTINCT FROM p_purpose_code
           OR v_existing.capability_id IS DISTINCT FROM p_capability_id
           OR v_existing.capability_version IS DISTINCT FROM p_capability_version
           OR v_existing.cal_semantic_hash IS DISTINCT FROM p_cal_semantic_hash
           OR v_existing.outcome IS DISTINCT FROM p_outcome
           OR v_existing.reason_codes IS DISTINCT FROM p_reason_codes
           OR v_existing.evaluation_snapshot_hash IS DISTINCT FROM p_evaluation_snapshot_hash
           OR v_existing.policy_bundle_hash IS DISTINCT FROM p_policy_bundle_hash
           OR v_existing.evidence_bundle_hash IS DISTINCT FROM p_evidence_bundle_hash
           OR v_existing.dependency_bundle_hash IS DISTINCT FROM p_dependency_bundle_hash
           OR v_existing.principal_generation IS DISTINCT FROM p_expected_principal_generation
           OR v_existing.organization_generation IS DISTINCT FROM p_expected_organization_generation
           OR v_existing.membership_generation IS DISTINCT FROM p_expected_membership_generation
           OR v_existing.authenticator_generation IS DISTINCT FROM p_expected_authenticator_generation
           OR v_existing.authority_context_generation IS DISTINCT FROM p_expected_context_generation
           OR v_existing.principal_global_revocation_epoch IS DISTINCT FROM p_expected_principal_revocation_epoch
           OR v_existing.organization_revocation_epoch IS DISTINCT FROM p_expected_organization_revocation_epoch
           OR v_existing.issued_at_epoch_ms IS DISTINCT FROM p_issued_at_epoch_ms
        THEN
            RAISE EXCEPTION USING ERRCODE = 'AR007', MESSAGE = 'idempotency key conflicts with changed semantic input';
        END IF;

        RETURN QUERY
        SELECT v_existing.decision_id,
               v_existing.receipt_id,
               v_existing.principal_global_sequence,
               v_existing.organization_decision_sequence,
               encode(r.canonical_receipt_sha256, 'hex'),
               true
          FROM anar_core.decision_receipts AS r
         WHERE r.receipt_id = v_existing.receipt_id;
        RETURN;
    END IF;

    SELECT * INTO v_principal
      FROM anar_core.principals
     WHERE principal_id = p_principal_id
     FOR UPDATE;
    SELECT * INTO v_organization
      FROM anar_core.organizations
     WHERE organization_id = p_organization_id
     FOR UPDATE;
    SELECT * INTO v_membership
      FROM anar_core.memberships
     WHERE membership_id = p_membership_id
     FOR UPDATE;
    SELECT * INTO v_authenticator
      FROM anar_core.authenticators
     WHERE authenticator_id = p_authenticator_id
     FOR UPDATE;
    SELECT * INTO v_context
      FROM anar_core.authority_contexts
     WHERE authority_context_id = p_authority_context_id
     FOR UPDATE;

    IF v_principal.principal_id IS NULL
       OR v_organization.organization_id IS NULL
       OR v_membership.membership_id IS NULL
       OR v_authenticator.authenticator_id IS NULL
       OR v_context.authority_context_id IS NULL
    THEN
        RAISE EXCEPTION USING ERRCODE = 'AR002', MESSAGE = 'core authority state unavailable';
    END IF;

    IF v_principal.status IS DISTINCT FROM 'ACTIVE'
       OR v_organization.status IS DISTINCT FROM 'ACTIVE'
       OR v_membership.status IS DISTINCT FROM 'ACTIVE'
       OR v_authenticator.status IS DISTINCT FROM 'ACTIVE'
       OR v_context.status IS DISTINCT FROM 'ACTIVE'
       OR v_membership.principal_id IS DISTINCT FROM p_principal_id
       OR v_membership.organization_id IS DISTINCT FROM p_organization_id
       OR v_authenticator.principal_id IS DISTINCT FROM p_principal_id
       OR v_context.principal_id IS DISTINCT FROM p_principal_id
       OR v_context.organization_id IS DISTINCT FROM p_organization_id
       OR v_context.membership_id IS DISTINCT FROM p_membership_id
       OR v_context.authenticator_id IS DISTINCT FROM p_authenticator_id
       OR v_context.capability_id IS DISTINCT FROM p_capability_id
       OR v_context.capability_version IS DISTINCT FROM p_capability_version
       OR v_context.purpose_code IS DISTINCT FROM p_purpose_code
       OR v_context.cal_semantic_hash IS DISTINCT FROM p_cal_semantic_hash
       OR v_context.expires_at_epoch_ms <= p_issued_at_epoch_ms
       OR v_authenticator.expires_at_epoch_ms IS NULL
       OR v_authenticator.expires_at_epoch_ms <= p_issued_at_epoch_ms
    THEN
        RAISE EXCEPTION USING ERRCODE = 'AR003', MESSAGE = 'core authority binding is inactive, expired, or mismatched';
    END IF;

    IF v_principal.generation IS DISTINCT FROM p_expected_principal_generation
       OR v_organization.generation IS DISTINCT FROM p_expected_organization_generation
       OR v_membership.generation IS DISTINCT FROM p_expected_membership_generation
       OR v_authenticator.generation IS DISTINCT FROM p_expected_authenticator_generation
       OR v_context.generation IS DISTINCT FROM p_expected_context_generation
       OR v_principal.global_revocation_epoch IS DISTINCT FROM p_expected_principal_revocation_epoch
       OR v_organization.revocation_epoch IS DISTINCT FROM p_expected_organization_revocation_epoch
    THEN
        RAISE EXCEPTION USING ERRCODE = 'AR001', MESSAGE = 'core authority generation is stale';
    END IF;

    PERFORM anar_core.revalidate_dependency_vector(p_dependency_vector);

    IF v_principal_sequence >= 9223372036854775806
       OR v_organization_sequence >= 9223372036854775806
    THEN
        RAISE EXCEPTION USING ERRCODE = 'AR006', MESSAGE = 'authority sequence exhausted';
    END IF;

    v_principal_sequence := v_principal_sequence + 1;
    v_organization_sequence := v_organization_sequence + 1;

    UPDATE anar_core.principal_authority_sync
       SET global_sequence = v_principal_sequence
     WHERE principal_id = p_principal_id;
    UPDATE anar_core.organization_authority_sync
       SET decision_sequence = v_organization_sequence
     WHERE organization_id = p_organization_id;

    INSERT INTO anar_core.decisions (
        decision_id, receipt_id, request_id, idempotency_key, principal_id,
        organization_id, membership_id, authenticator_id, authority_context_id,
        purpose_code, capability_id, capability_version, cal_semantic_hash,
        outcome, reason_codes,
        request_semantic_hash, evaluation_snapshot_hash, policy_bundle_hash,
        evidence_bundle_hash, dependency_bundle_hash, principal_generation,
        organization_generation, membership_generation, authenticator_generation,
        authority_context_generation, principal_global_sequence,
        organization_decision_sequence, principal_global_revocation_epoch,
        organization_revocation_epoch, issued_at_epoch_ms
    ) VALUES (
        p_decision_id, p_receipt_id, p_request_id, p_idempotency_key, p_principal_id,
        p_organization_id, p_membership_id, p_authenticator_id, p_authority_context_id,
        p_purpose_code, p_capability_id, p_capability_version, p_cal_semantic_hash,
        p_outcome, p_reason_codes,
        p_request_semantic_hash, p_evaluation_snapshot_hash, p_policy_bundle_hash,
        p_evidence_bundle_hash, p_dependency_bundle_hash, v_principal.generation,
        v_organization.generation, v_membership.generation, v_authenticator.generation,
        v_context.generation, v_principal_sequence,
        v_organization_sequence, v_principal.global_revocation_epoch,
        v_organization.revocation_epoch, p_issued_at_epoch_ms
    );

    v_witness := jsonb_build_object(
        'format', 'ANAR-POSTGRES-FINALIZATION-WITNESS-V1',
        'decision_id', p_decision_id,
        'receipt_id', p_receipt_id,
        'request_id', p_request_id,
        'principal_id', p_principal_id,
        'organization_id', p_organization_id,
        'membership_id', p_membership_id,
        'authenticator_id', p_authenticator_id,
        'authority_context_id', p_authority_context_id,
        'purpose_code', p_purpose_code,
        'capability_id', p_capability_id,
        'capability_version', p_capability_version,
        'cal_semantic_hash', encode(p_cal_semantic_hash, 'hex'),
        'outcome', p_outcome,
        'reason_codes', to_jsonb(p_reason_codes),
        'request_semantic_hash', encode(p_request_semantic_hash, 'hex'),
        'evaluation_snapshot_hash', encode(p_evaluation_snapshot_hash, 'hex'),
        'policy_bundle_hash', encode(p_policy_bundle_hash, 'hex'),
        'evidence_bundle_hash', encode(p_evidence_bundle_hash, 'hex'),
        'dependency_bundle_hash', encode(p_dependency_bundle_hash, 'hex'),
        'principal_generation', v_principal.generation,
        'organization_generation', v_organization.generation,
        'membership_generation', v_membership.generation,
        'authenticator_generation', v_authenticator.generation,
        'authority_context_generation', v_context.generation,
        'principal_global_sequence', v_principal_sequence,
        'organization_decision_sequence', v_organization_sequence,
        'principal_global_revocation_epoch', v_principal.global_revocation_epoch,
        'organization_revocation_epoch', v_organization.revocation_epoch,
        'issued_at_epoch_ms', p_issued_at_epoch_ms,
        'production_mutated', false
    );
    v_witness_sha256 := public.digest(convert_to(v_witness::text, 'UTF8'), 'sha256');

    INSERT INTO anar_core.decision_receipts (
        receipt_id, decision_id, organization_id, canonical_receipt,
        canonical_receipt_sha256, created_at_epoch_ms
    ) VALUES (
        p_receipt_id, p_decision_id, p_organization_id, v_witness,
        v_witness_sha256, p_issued_at_epoch_ms
    );

    RETURN QUERY SELECT p_decision_id, p_receipt_id, v_principal_sequence,
                        v_organization_sequence, encode(v_witness_sha256, 'hex'), false;
END;
$function$;

CREATE OR REPLACE FUNCTION anar_core.execute_membership_revocation(
    p_event_id uuid,
    p_mutation_grant_id uuid,
    p_actor_principal_id uuid,
    p_organization_id uuid,
    p_target_membership_id uuid,
    p_target_digest bytea,
    p_purpose_code text,
    p_effect_scope_hash bytea,
    p_now_epoch_ms bigint
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, anar_core
AS $function$
DECLARE
    v_grant anar_core.internal_mutation_grants%ROWTYPE;
    v_principal anar_core.principals%ROWTYPE;
    v_membership anar_core.memberships%ROWTYPE;
    v_organization anar_core.organizations%ROWTYPE;
    v_authenticator anar_core.authenticators%ROWTYPE;
    v_context anar_core.authority_contexts%ROWTYPE;
    v_decision anar_core.decisions%ROWTYPE;
    v_pre_epoch bigint;
BEGIN
    IF nullif(current_setting('anar.organization_id', true), '')::uuid
       IS DISTINCT FROM p_organization_id
    THEN
        RAISE EXCEPTION USING ERRCODE = 'AR003', MESSAGE = 'session organization does not match requested organization';
    END IF;

    SELECT * INTO v_grant FROM anar_core.internal_mutation_grants
     WHERE mutation_grant_id = p_mutation_grant_id;
    SELECT d.* INTO v_decision
      FROM anar_core.decision_receipts AS r
      JOIN anar_core.decisions AS d ON d.decision_id = r.decision_id
     WHERE r.receipt_id = v_grant.decision_receipt_id;

    IF v_grant.mutation_grant_id IS NULL
       OR v_decision.decision_id IS NULL
       OR v_grant.actor_principal_id IS DISTINCT FROM p_actor_principal_id
       OR v_grant.organization_id IS DISTINCT FROM p_organization_id
    THEN
        RAISE EXCEPTION USING ERRCODE = 'AR003', MESSAGE = 'mutation discovery binding denied';
    END IF;

    PERFORM 1 FROM anar_core.principal_authority_sync
     WHERE principal_id = p_actor_principal_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'AR002', MESSAGE = 'principal synchronization row unavailable';
    END IF;
    PERFORM 1 FROM anar_core.organization_authority_sync
     WHERE organization_id = p_organization_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'AR002', MESSAGE = 'organization synchronization row unavailable';
    END IF;

    SELECT * INTO v_principal FROM anar_core.principals
     WHERE principal_id = p_actor_principal_id FOR UPDATE;
    SELECT * INTO v_organization FROM anar_core.organizations
     WHERE organization_id = p_organization_id FOR UPDATE;
    SELECT * INTO v_membership FROM anar_core.memberships
     WHERE membership_id = p_target_membership_id FOR UPDATE;
    SELECT * INTO v_authenticator FROM anar_core.authenticators
     WHERE authenticator_id = v_decision.authenticator_id FOR UPDATE;
    SELECT * INTO v_context FROM anar_core.authority_contexts
     WHERE authority_context_id = v_decision.authority_context_id FOR UPDATE;
    SELECT * INTO v_grant FROM anar_core.internal_mutation_grants
     WHERE mutation_grant_id = p_mutation_grant_id FOR UPDATE;

    IF v_principal.principal_id IS NULL
       OR v_membership.membership_id IS NULL
       OR v_organization.organization_id IS NULL
       OR v_authenticator.authenticator_id IS NULL
       OR v_context.authority_context_id IS NULL
       OR v_grant.mutation_grant_id IS NULL
    THEN
        RAISE EXCEPTION USING ERRCODE = 'AR002', MESSAGE = 'mutation state unavailable';
    END IF;

    IF v_decision.outcome IS DISTINCT FROM 'ALLOW'
       OR v_decision.principal_id IS DISTINCT FROM p_actor_principal_id
       OR v_decision.organization_id IS DISTINCT FROM p_organization_id
       OR v_decision.capability_id IS DISTINCT FROM v_grant.capability_id
       OR v_membership.organization_id IS DISTINCT FROM p_organization_id
       OR v_principal.status IS DISTINCT FROM 'ACTIVE'
       OR v_membership.status IS DISTINCT FROM 'ACTIVE'
       OR v_organization.status IS DISTINCT FROM 'ACTIVE'
       OR v_authenticator.status IS DISTINCT FROM 'ACTIVE'
       OR v_context.status IS DISTINCT FROM 'ACTIVE'
       OR v_authenticator.expires_at_epoch_ms IS NULL
       OR v_authenticator.expires_at_epoch_ms <= p_now_epoch_ms
       OR v_context.expires_at_epoch_ms <= p_now_epoch_ms
       OR v_principal.generation IS DISTINCT FROM v_decision.principal_generation
       OR v_organization.generation IS DISTINCT FROM v_decision.organization_generation
       OR v_membership.generation IS DISTINCT FROM v_decision.membership_generation
       OR v_authenticator.generation IS DISTINCT FROM v_decision.authenticator_generation
       OR v_context.generation IS DISTINCT FROM v_decision.authority_context_generation
       OR v_principal.global_revocation_epoch IS DISTINCT FROM v_decision.principal_global_revocation_epoch
       OR v_organization.revocation_epoch IS DISTINCT FROM v_decision.organization_revocation_epoch
       OR v_grant.actor_principal_id IS DISTINCT FROM p_actor_principal_id
       OR v_grant.organization_id IS DISTINCT FROM p_organization_id
       OR v_grant.target_type IS DISTINCT FROM 'membership'
       OR v_grant.target_ref IS DISTINCT FROM p_target_membership_id
       OR v_grant.target_digest IS DISTINCT FROM p_target_digest
       OR v_grant.purpose_code IS DISTINCT FROM p_purpose_code
       OR v_grant.effect_scope_hash IS DISTINCT FROM p_effect_scope_hash
       OR v_grant.consumed_at_epoch_ms IS NOT NULL
       OR v_grant.revoked_at_epoch_ms IS NOT NULL
       OR v_grant.expires_at_epoch_ms <= p_now_epoch_ms
    THEN
        RAISE EXCEPTION USING ERRCODE = 'AR003', MESSAGE = 'mutation grant unavailable, stale, consumed, or mismatched';
    END IF;

    IF v_organization.revocation_epoch >= 9223372036854775806
       OR v_membership.generation >= 9223372036854775806
    THEN
        RAISE EXCEPTION USING ERRCODE = 'AR006', MESSAGE = 'authority sequence exhausted';
    END IF;

    v_pre_epoch := v_organization.revocation_epoch;
    UPDATE anar_core.memberships
       SET status = 'REVOKED', generation = generation + 1
     WHERE membership_id = p_target_membership_id;
    UPDATE anar_core.organizations
       SET revocation_epoch = revocation_epoch + 1
     WHERE organization_id = p_organization_id;
    UPDATE anar_core.internal_mutation_grants
       SET consumed_at_epoch_ms = p_now_epoch_ms
     WHERE mutation_grant_id = p_mutation_grant_id;

    INSERT INTO anar_core.authority_mutation_events (
        event_id, mutation_grant_id, decision_receipt_id, actor_principal_id,
        organization_id, target_type, target_ref, capability_id, purpose_code,
        pre_generation, post_generation, pre_revocation_epoch,
        post_revocation_epoch, recorded_at_epoch_ms
    ) VALUES (
        p_event_id, p_mutation_grant_id, v_grant.decision_receipt_id,
        p_actor_principal_id, p_organization_id, 'membership', p_target_membership_id,
        v_grant.capability_id, p_purpose_code, v_membership.generation,
        v_membership.generation + 1, v_pre_epoch, v_pre_epoch + 1, p_now_epoch_ms
    );

    RETURN p_event_id;
END;
$function$;

COMMIT;
