\set ON_ERROR_STOP on
DO $proof$
DECLARE
    v_event_count bigint;
    v_status text;
    v_generation bigint;
    v_epoch bigint;
    v_consumed bigint;
BEGIN
    SELECT count(*) INTO v_event_count FROM anar_core.authority_mutation_events
     WHERE mutation_grant_id = 'a0000000-0000-4000-8000-000000000001';
    SELECT status, generation INTO v_status, v_generation
      FROM anar_core.memberships
     WHERE membership_id = '30000000-0000-4000-8000-000000000001';
    SELECT revocation_epoch INTO v_epoch FROM anar_core.organizations
     WHERE organization_id = '20000000-0000-4000-8000-000000000001';
    SELECT consumed_at_epoch_ms INTO v_consumed FROM anar_core.internal_mutation_grants
     WHERE mutation_grant_id = 'a0000000-0000-4000-8000-000000000001';
    IF v_event_count <> 1 OR v_status <> 'REVOKED' OR v_generation <> 6
       OR v_epoch <> 1 OR v_consumed <> 1800000002000 THEN
        RAISE EXCEPTION 'one-shot mutation invariant failed: events %, status %, generation %, epoch %, consumed %',
            v_event_count, v_status, v_generation, v_epoch, v_consumed;
    END IF;
END;
$proof$;

SELECT jsonb_build_object(
    'decisions', (SELECT count(*) FROM anar_core.decisions),
    'receipts', (SELECT count(*) FROM anar_core.decision_receipts),
    'mutation_events', (SELECT count(*) FROM anar_core.authority_mutation_events),
    'membership_status', (SELECT status FROM anar_core.memberships WHERE membership_id = '30000000-0000-4000-8000-000000000001'),
    'membership_generation', (SELECT generation FROM anar_core.memberships WHERE membership_id = '30000000-0000-4000-8000-000000000001'),
    'organization_revocation_epoch', (SELECT revocation_epoch FROM anar_core.organizations WHERE organization_id = '20000000-0000-4000-8000-000000000001')
)::text;

