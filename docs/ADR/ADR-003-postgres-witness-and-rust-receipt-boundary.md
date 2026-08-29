# ADR-003: PostgreSQL Finalization Witness Is Not the Cross-Language Decision Receipt

## Status

Accepted for the pre-freeze local rehearsal. This ADR does not freeze SPEC-3.12 and grants no production authority.

## Context

SPEC-3.12 requires a consequential decision to assign both synchronization sequences, insert the decision, and insert its receipt in one database transaction. It also requires receipt bytes to be deterministic and complete.

The current Rust proof model can issue and verify the typed decision receipt. The current PostgreSQL procedure can lock and revalidate authority state, assign both sequences, insert the decision, and insert a hash-bound record in one transaction. There is not yet a production Rust persistence adapter that constructs the final Rust receipt after reading the assigned sequences and inserts those exact bytes before committing the same SQL transaction.

Calling the database-produced JSON projection the final cross-language receipt would therefore say more than the implementation proves.

## Decision

The database record is explicitly identified as `ANAR-POSTGRES-FINALIZATION-WITNESS-V1`.

It includes the selected authority identities, capability, outcome, reasons, all semantic proof hashes, exact generations, both synchronization sequences, both revocation epochs, issue time, and `production_mutated: false`. PostgreSQL hashes the stored JSON bytes in the same transaction and the rehearsal independently recomputes that digest.

The Rust `DecisionReceipt` remains the receipt contract. M10 remains not ready until the production Rust persistence path proves that the final typed receipt bytes are inserted in the same SQLx transaction that assigns the database sequences.

## Consequences

- The local rehearsal can prove database serialization, rollback, idempotency, tenant isolation, sequence exhaustion, dependency revalidation, and one-shot mutations without making a false cross-language claim.
- Evidence packets name the database artifact a witness and mark `cross_language_decision_receipt` as `NOT_YET_PROVEN`.
- No compatibility promise exists between witness JSON bytes and Rust receipt bytes.
- Historical witnesses will not be rewritten when the cross-language adapter is implemented.

