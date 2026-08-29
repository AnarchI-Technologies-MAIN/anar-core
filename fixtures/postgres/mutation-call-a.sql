\set ON_ERROR_STOP on
\set VERBOSITY verbose
SET anar.organization_id = '20000000-0000-4000-8000-000000000001';
SELECT anar_core.execute_membership_revocation(
    'b0000000-0000-4000-8000-000000000001',
    'a0000000-0000-4000-8000-000000000001',
    '10000000-0000-4000-8000-000000000001',
    '20000000-0000-4000-8000-000000000001',
    '30000000-0000-4000-8000-000000000001',
    decode(repeat('61', 32), 'hex'),
    'authority.membership.revoke', decode(repeat('62', 32), 'hex'),
    1800000002000
);
