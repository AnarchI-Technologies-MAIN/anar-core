# Phase -1 Institutional Reconciliation

## Result

`SAFE_TO_BUILD_ISOLATED_VNEXT`; `NOT_AUTHORIZED_FOR_PRODUCTION`.

## Inputs

- supplied pre-freeze SPEC-3.12 artifact;
- supplied `anar-core-master.zip` predecessor kernel;
- supplied `anar-core-contracts-master.zip` boundary contracts;
- admitted AnarchI current-canon responsibility map;
- admitted Identity, Authority, and Broker Doctrine;
- current Recoveries repository and its frozen SPEC-1.6 enforcement boundary.

## Live-state findings

- No Anar-Core repository, service, database, container, or live endpoint was present in WSL2 at reconnaissance time.
- The Recoveries and governance repositories were clean.
- Recoveries remains a product-domain consumer and must fail closed when Anar-Core authority is unavailable.
- Governance reserves Anar-Core's architectural responsibility but explicitly says doctrine is not implementation proof.
- No production endpoint, customer record, Stripe account, Vault instance, or provider credential was contacted.

## Predecessor results

- Standalone contract suite: 10 tests passed.
- Kernel distribution contract tests: 11 tests passed.
- Three kernel test modules could not load because the current WSL Python 3.14 environment does not contain `argon2`; this is recorded as `ENVIRONMENT_DEPENDENCY_MISSING`, not an authority-test failure.
- Predecessor source is preserved under `legacy/predecessor/` and is not part of the vNext runtime build.

## Reconciled ownership

| Concern | Owner | Anar-Core treatment |
|---|---|---|
| principal, organization, membership, delegation, revocation | Anar-Core | authoritative current-state resolution |
| policy and entitlement bindings | Anar-Core state, external definitions | typed references and current binding state |
| CAL capability semantics | CAL / Registry | validated references only |
| product facts and workflow | Recoveries or other product | digest-bound policy evidence only |
| secrets and dynamic credentials | Vault / broker boundary | secret references and operational availability only |
| external execution | CERBERUS / broker / adapter | bounded envelope consumer; never broaden |
| legal authority | attributable legal/governance instrument | never inferred from technical authority |

## Safe-pause boundary

If implementation stops after this phase, the repository contains only source preservation, mapping, and receipts. It does not expose an authorization API, migrate predecessor data, or change a running service.

