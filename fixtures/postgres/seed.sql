BEGIN;

INSERT INTO anar_core.principals (
    principal_id, principal_kind, status, generation, global_revocation_epoch
) VALUES (
    '10000000-0000-4000-8000-000000000001', 'AGENT', 'ACTIVE', 2, 0
);

INSERT INTO anar_core.organizations (
    organization_id, status, generation, revocation_epoch
) VALUES
    ('20000000-0000-4000-8000-000000000001', 'ACTIVE', 4, 0),
    ('20000000-0000-4000-8000-000000000002', 'ACTIVE', 1, 0);

INSERT INTO anar_core.memberships (
    membership_id, principal_id, organization_id, status, generation
) VALUES (
    '30000000-0000-4000-8000-000000000001',
    '10000000-0000-4000-8000-000000000001',
    '20000000-0000-4000-8000-000000000001',
    'ACTIVE', 5
);

INSERT INTO anar_core.authenticators (
    authenticator_id, principal_id, status, generation, expires_at_epoch_ms
) VALUES (
    '40000000-0000-4000-8000-000000000001',
    '10000000-0000-4000-8000-000000000001',
    'ACTIVE', 6, 1900000000000
);

INSERT INTO anar_core.authority_contexts (
    authority_context_id, principal_id, organization_id, membership_id,
    authenticator_id, purpose_code, capability_id, capability_version,
    cal_semantic_hash, status, generation, expires_at_epoch_ms
) VALUES (
    '50000000-0000-4000-8000-000000000001',
    '10000000-0000-4000-8000-000000000001',
    '20000000-0000-4000-8000-000000000001',
    '30000000-0000-4000-8000-000000000001',
    '40000000-0000-4000-8000-000000000001',
    'authority.membership.revoke', 'authority.membership.revoke', 1,
    decode(repeat('11', 32), 'hex'), 'ACTIVE', 7, 1900000000000
);

INSERT INTO anar_core.principal_authority_sync (principal_id, global_sequence)
VALUES ('10000000-0000-4000-8000-000000000001', 0);

INSERT INTO anar_core.organization_authority_sync (organization_id, decision_sequence)
VALUES
    ('20000000-0000-4000-8000-000000000001', 0),
    ('20000000-0000-4000-8000-000000000002', 0);

INSERT INTO anar_core.authority_dependency_state (
    dependency_type, organization_id, dependency_id, generation, semantic_hash, status
) VALUES (
    1,
    '20000000-0000-4000-8000-000000000001',
    '60000000-0000-4000-8000-000000000001',
    3, NULL, 'ACTIVE'
);

COMMIT;

