# ADR-004: Corpus manifest coverage and undisclosed adjudication

## Status

Accepted as a pre-freeze correction; production authority remains `NONE`.

## Context

The first durable packet after the authority-domain increment completed the
PostgreSQL rehearsal and verified its receipt chain, but its input manifest
enumerated only the SQL fixtures used directly by that database run. The
repository also contained conformance and adversarial specimens intended to be
part of the evidence corpus. A reviewer receiving the packet could therefore
not prove that the complete committed corpus had been digest-bound.

The independent reviewer must receive the output packet without the expected
answers. Expected outcomes stay in the committed fixture corpus and are
available to the adjudication process only after the reviewer records an
independent conclusion.

## Decision

The rehearsal corpus root is `fixtures/`, and every file beneath it is included
in the packet artifact hash map. The packet carries a versioned structured
manifest with source digests and undisclosed case identifiers, but does not copy
fixture expected outcomes into the packet. The verifier resolves each digest
from the packet's repository commit and fails closed on any missing or changed
artifact.

This is an evidence-boundary correction, not a release decision. It does not
change the frozen specification or authorize production access.

## Consequences

- Conformance, adversarial, and database fixtures are covered by one digest map.
- A reviewer can reconstruct the exact corpus bytes from the committed packet
  manifest without being primed by expected labels.
- The packet's case identifiers are visible for adjudication bookkeeping, while
  expected outcomes remain outside the packet.
- Historical packets are not rewritten; the earlier packet remains evidence of
  the narrower manifest and is superseded only for future runs.
