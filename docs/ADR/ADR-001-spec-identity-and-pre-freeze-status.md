# ADR-001: Preserve supplied spec identity and pre-freeze status

## Observation

The supplied filename identifies `SPEC-3.12`, while line 1 identifies `SPEC-3.0`. The document status says `pre-hard-freeze`, and Addendum 12 ends with M10 `NOT READY`.

## Decision

The original bytes and SHA-256 remain unchanged. Implementation provenance identifies the source as `SPEC-3.12 supplied artifact / internal title SPEC-3.0` and binds the exact digest. This repository does not rename the internal title, declare a hard freeze, or infer M10 completion.

## Invariant

Implementation progress, passing tests, and repository commits cannot promote the specification. Hard-freeze authority requires a separately attributable adjudication and a new immutable artifact hash.

## Consequence

All receipts carry the supplied artifact digest and the explicit state `PRE_FREEZE_M10_NOT_READY`.

