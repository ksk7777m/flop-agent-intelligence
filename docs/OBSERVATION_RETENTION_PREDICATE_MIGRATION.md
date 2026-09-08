# Observation Evidence Retention / Predicate Migration & Reobservation Ceremony

Status: offline, descriptive-only, review-ready. This package performs no live
GET, write, MCP invocation, signing, nonce request, wallet operation, scheduler,
polling, retry, or persistence action.

## Existing coverage reconciliation

| Concern | Initial classification | Result |
|---|---|---|
| evidence identity / policy binding | `PARTIALLY_COVERED` | Sealed canonical identity binds the fixed source set, observation time, v1 predicate, observation policy, transport and semantic result |
| immutable observation record / generation | `PARTIALLY_COVERED` | Existing retention semantics reused; process-local immutable record generations added |
| supersession / incomplete retention | `PARTIALLY_COVERED` | Old evidence remains retained and is classified separately as superseded and incomplete |
| expiry / currentness | `BLOCKED_BY_POLICY` | No TTL is invented; `RETENTION_POLICY_REQUIRED` and `CURRENTNESS_UNKNOWN` remain |
| freshness | `ALREADY_COVERED` | `FRESHNESS_NOT_CONFIRMED` remains independent |
| predicate migration | `MISSING` | Fixed v1-to-v2 migration record; same, unknown, duplicate, downgrade and cycle paths fail closed |
| reobservation ceremony | `MISSING` | Fixed GET-only, retry-zero descriptive plan and human-review record |
| attempt journal / duplicate prevention | `PARTIALLY_COVERED` | Replay semantics reused; immutable attempt generations prevent duplicate plans and per-source attempts |
| crash recovery | `BLOCKED_BY_POLICY` | No persistent executor exists; process loss cannot auto-resume or execute |
| public projection | `MISSING` | Closed schema and field-by-field reconstruction added |
| action isolation | `ALREADY_COVERED` | No capability issuer or sink is introduced |
| new live observation | `NOT_APPLICABLE` | Explicitly outside this package |

## Historical LLMS evidence and migration

The retained one-shot evidence is bound to source set
`technocore-runtime-fixed-source-set-v1`, observation policy
`technocore-runtime-readonly-observation-v1`, and predicate revision
`technocore-runtime-predicates-v1`. Its LLMS result remains
`LLMS_SEMANTIC_GAP`; its raw response was not retained.

Its SHA-256 identity uses the domain `FLOP_OBSERVATION_RETENTION_RECORD_ID_V1`
and the repository-defined `STRICT_TYPED_UTF8_JSON_V1` encoding: sorted JSON
object keys, preserved array order, explicit UTF-8, escaped Unicode code points,
no Unicode normalization, and no floats or non-JSON types. The identity binds
the schema, generation, previous identity, fixed source IDs and ordinals,
observation time and policy, predicate revision and domain-separated identity
hash, transport/semantic outcomes,
completeness, one-shot version evidence, minimized freshness/cache state,
retention/currentness/supersession, and compatibility. The historical body
hashes and exact lengths were not retained; each source therefore binds explicit
null values plus `body_evidence=NOT_RETAINED`, the accepted bounded-size result,
and the fixed byte cap. No digest or length is reconstructed or guessed.

The descriptive migration binds v1 to `technocore-runtime-predicates-v2`, the
fixed reason `LLMS_PREDICATE_ALIGNED_TO_PINNED_REVISION`, the LLMS source ID,
the previous evidence identity and a fixed local event time. It cannot change
the old result, re-evaluate absent raw bytes, alter predicates or sources,
observe the network, prove compatibility, or authorize action. Reobservation
therefore remains required.

Superseded is not deleted: old records remain immutable and addressable.
Retained is not current, recent is not fresh, fresh is not compatible, and
compatible would still not mean ready or authorized. This repository has no
approved local retention window for these observations. `RETENTION_POLICY_REQUIRED`
is a repository operational state, not an official Technocore rule.

## Reobservation ceremony and attempt journal

The plan fixes the repository-owned observation policy, predicate v2, exact
four-source set, GET-only operation, redirect rejection, existing fixed timeout
and body caps, retry count zero, and no alternate URL, fallback, remote MCP,
signing, write or scheduler. It contains no URL or executable transport.

A human-review record is descriptive and non-serializable; it is not reusable
network authority. Beginning an attempt records state only and performs no GET.
Each source can transition once in an immutable attempt generation. Duplicate
plan execution, stale generations, duplicate source attempts, and continuation
after failure/interruption are rejected. A completed four-source attempt still
cannot commit a result without a sealed current-policy evidence identity. This
package intentionally has no issuer for such live evidence.

The ledger is fixture-only and process-local. There is no persistence API, so a
crash cannot trigger automatic recovery or retry. A failed/interrupted attempt
requires a future separately reviewed plan; it never deletes earlier evidence.
Connecting any live observer or runner remains blocked until a durable journal
and explicit restart reconciliation policy are implemented and reviewed.

## Public and production boundary

The public projection contains only fixed enums, timestamps, hashes, source-set
identity and descriptive booleans. Its schema and semantic validator reject
unknown fields and authority promotion. There are no raw bodies, headers, error
bodies, URLs, arbitrary metadata, credentials or secrets.

Production callers cannot supply a store, path, clock, predicate, resolver,
opener, writer, callback or sink. Import, migration, planning, validation and
projection do not access the network or filesystem. Runtime nonce remains
`BLOCKED_BY_LIVE_SIGNED_WRITE`; public KV cache observation and continuous
compatibility remain blocked. Every record is `COMPATIBILITY_REVIEW_REQUIRED`,
`ready_to_act=false`, `authorized_to_act=false`, and `live_action_enabled=false`.
