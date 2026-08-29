# ADR-002: Preserve predecessor behavior without extending the legacy authority path

## Context

The supplied Python v0.1 predecessor contains useful current-state, generation, revocation, single-use, and historical-preservation behavior. It also owns adapter and operation definitions, Cloud-Spine bootstrap constants, and an AdForge-specific consumer handoff, and it assumes privileged callers have already been authorized.

## Decision

Preserve the predecessor archives and extracted sources as migration evidence. Build vNext as a separate typed runtime path. No vNext service imports the legacy Python package.

The following predecessor behaviors must receive golden migration fixtures:

- exact identity/account/membership/organization relationships;
- current credential and generation revalidation;
- scoped membership suspension, departure, and revocation;
- one-use challenge and handoff consumption;
- historical membership preservation and rejoin with a new membership ID;
- fail-closed normalized-boundary mismatch;
- cross-connection single-winner behavior.

The following concepts are not carried into the vNext authority path:

- adapter and operation definition ownership;
- product bootstrap grants;
- AdForge-only handoff semantics;
- direct privileged mutation without a bounded current administrative decision;
- SQLite as the authoritative production store.

## Consequence

Legacy evidence remains queryable, but it cannot mint vNext capability decisions or receipts.

