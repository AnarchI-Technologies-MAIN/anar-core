BEGIN;

INSERT INTO anar_core.principals (
    principal_id, principal_kind, status, generation, global_revocation_epoch,
    canonical_name
) VALUES (
    '10000000-0000-4000-8000-000000000001', 'AGENT', 'ACTIVE', 2, 0,
    'rehearsal-action-runner'
);

INSERT INTO anar_core.organizations (
    organization_id, status, generation, revocation_epoch, canonical_name
) VALUES
    ('20000000-0000-4000-8000-000000000001', 'ACTIVE', 4, 0, 'falcon-electrical'),
    ('20000000-0000-4000-8000-000000000002', 'ACTIVE', 1, 0, 'isolation-control');

INSERT INTO anar_core.memberships (
    membership_id, principal_id, organization_id, status, generation,
    membership_class, valid_from_epoch_ms
) VALUES (
    '30000000-0000-4000-8000-000000000001',
    '10000000-0000-4000-8000-000000000001',
    '20000000-0000-4000-8000-000000000001',
    'ACTIVE', 5, 'SERVICE', 1700000000000
);

INSERT INTO anar_core.authenticators (
    authenticator_id, principal_id, status, generation, expires_at_epoch_ms,
    authenticator_type, valid_from_epoch_ms
) VALUES (
    '40000000-0000-4000-8000-000000000001',
    '10000000-0000-4000-8000-000000000001',
    'ACTIVE', 6, 1900000000000, 'workload.mtls', 1700000000000
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

INSERT INTO anar_core.capability_requests (
    request_id, authority_context_id, organization_id, purpose_code,
    capability_id, capability_version, resource_scope_json, effect_scope_json,
    requested_constraints_json, cal_semantic_hash, request_semantic_hash,
    requested_at_epoch_ms
) VALUES (
    '90000000-0000-4000-8000-000000000001',
    '50000000-0000-4000-8000-000000000001',
    '20000000-0000-4000-8000-000000000001',
    'authority.membership.revoke', 'authority.membership.revoke', 1,
    '{"kind":"EXPLICIT_SET","resources":["membership:30000000-0000-4000-8000-000000000001"]}'::jsonb,
    '{"classes":["authority.membership.revoke"]}'::jsonb,
    '{"max_uses":1}'::jsonb,
    decode(repeat('11', 32), 'hex'), decode(repeat('21', 32), 'hex'),
    1800000000000
);

INSERT INTO anar_core.entitlement_bindings (
    entitlement_binding_id, organization_id, membership_id, principal_id,
    package_ref, entitlement_ref, source_system, source_digest, status,
    valid_from_epoch_ms, valid_until_epoch_ms, generation
) VALUES
    (
        'c0000000-0000-4000-8000-000000000001',
        '20000000-0000-4000-8000-000000000001',
        '30000000-0000-4000-8000-000000000001',
        '10000000-0000-4000-8000-000000000001',
        'package.recoveries', 'recoveries.active', 'marketplace',
        decode(repeat('81', 32), 'hex'), 'ACTIVE', 1700000000000, 1900000000000, 1
    ),
    (
        'c0000000-0000-4000-8000-000000000002',
        '20000000-0000-4000-8000-000000000002',
        NULL, NULL,
        'package.recoveries', 'recoveries.active', 'marketplace',
        decode(repeat('82', 32), 'hex'), 'ACTIVE', 1700000000000, 1900000000000, 1
    );

COMMIT;
