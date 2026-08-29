# ADR-005: Canonical order for the four-service manifest

## Status

Accepted as a pre-freeze correction; production authority remains `NONE`.

## Context

The first four-service development rehearsal proved startup, readiness, and
teardown, but packet verification rejected the packet because the runner listed
services in its startup sequence while the verifier compared a canonical
representation. The packet was not accepted and no production state was
changed.

## Decision

The service manifest order is the lexical sequence `minio`, `nats`, `postgres`,
`zitadel`. The runner uses that order for probing, results, packet metadata, and
the verifier's exact comparison. The order is representational only; dependency
readiness remains expressed by Compose's `depends_on` graph.

## Consequences

- Independent reviewers do not need to infer process startup order.
- Equivalent runs produce the same manifest ordering.
- The rejected pre-correction verifier result remains recorded in
  `CORRECTION-013` and is not rewritten as a pass.
