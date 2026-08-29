# Anar-Core Contracts

Canonical implementation-neutral contracts for Anar-Core identity, organization,
membership, entitlement, enrollment, authorization projection, hydration, and
shared Anar-Core/Broker authority boundaries.

## v0.1 boundaries

Anar-Core owns current identity and authority truth.

The Broker owns bounded executable capability mediation.

Neither component may broaden the normalized shared boundary contract.

A boundary mismatch is not negotiated. It fails closed.

Secrets are not part of these contracts.