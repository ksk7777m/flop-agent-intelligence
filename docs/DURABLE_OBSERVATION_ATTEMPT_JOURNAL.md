# Durable Observation Attempt Journal / Crash Reconciliation Boundary

Status: local-journal-only, fixture crash-tested, review-ready. No Technocore
GET/write, MCP, signing, nonce, wallet, scheduler, polling, or retry is
connected in production. A private fixture-only runner exercises the journal.

## Existing coverage reconciliation

| Concern | Initial classification | Result |
|---|---|---|
| fixed journal root | `PARTIALLY_COVERED` | Existing ignored repository runtime convention reused; production closure captures one fixed subdirectory |
| secure creation / locking / fsync | `PARTIALLY_COVERED` | Existing atomic-history patterns adapted with stricter regular-file, owner, link and mode checks |
| append-only sequence / hash chain | `MISSING` | Immutable logical JSONL chain, rewritten only as a fully fsynced atomic snapshot |
| pre-attempt/source intent | `MISSING` | Durable records precede any future request boundary |
| source state / duplicate prevention | `PARTIALLY_COVERED` | Replay semantics reused; fixed four-source state and one intent/result per source added |
| crash/torn-tail/middle corruption detection | `MISSING` | Offline inspection fails closed without truncation or repair |
| restart recovery / reconciliation | `BLOCKED_BY_LIVE_RUNNER` | Descriptive inspection only; no resume/retry/token recovery |
| result commit/finalization | `MISSING` | Four durable results plus fixture-only sealed v2 evidence required |
| retention/rotation/repair | `BLOCKED_BY_POLICY` | No TTL, deletion, rotation, truncation or repair policy |
| privacy/public projection | `PARTIALLY_COVERED` | Closed minimized schema and semantic validator added |
| action isolation | `ALREADY_COVERED` | No network/effect capability introduced |

## Durable model and identity

Attempt states include `PREPARED`, `INTENT_DURABLE`, `IN_PROGRESS`,
`OUTCOME_UNKNOWN`, `RESULTS_COMPLETE`, `EVIDENCE_COMMITTED`, `FINALIZED`,
`ABANDONED`, and `RECONCILIATION_REQUIRED`. Source states include
`NOT_ATTEMPTED`, `INTENT_DURABLE`, `REQUEST_MAY_HAVE_STARTED`,
`RESULT_DURABLE`, `OUTCOME_UNKNOWN`, and `FAILED_CONFIRMED`.

Records use `STRICT_TYPED_UTF8_JSON_V1`, SHA-256, a journal domain separator,
repository journal identity, sealed plan/attempt identities, predicate v2,
fixed source-set/order, generation zero, monotonic sequence, previous hash,
record/state type, minimized result/evidence identity, fixed descriptive time,
and reconciliation flag. Sequence, not wall time, orders records. The chain
detects local damage and accidental substitution; it is not protection against
a compromised host or malicious same-UID process.

## Persistence and crash meaning

The journal and lock live only below the fixed Git-ignored runtime directory.
The directory is `0700`; journal, lock and candidate are `0600`, owner-only,
regular, single-link objects. The verified parent is opened first; the runtime
root is then opened relative to that directory descriptor. Journal, lock and
candidate opens, stat checks, candidate unlink, atomic replace, and directory
fsync are anchored to the verified runtime directory descriptor. Descriptor
metadata is compared with non-following directory-entry metadata. No-follow
opens, `O_EXCL` candidates, a captured process `RLock`, nonblocking OS file
locking, complete-write loops, file fsync, atomic replace and directory fsync
provide single-writer snapshot durability. Tokens also bind their issuer PID,
so a fork cannot reuse a parent token. Failure before replace keeps
the old good journal. Failure after replace but before directory fsync is
reported as `DURABILITY_UNKNOWN`, blocks subsequent writes in that service, and
requires inspection/manual investigation. The call does not claim durable
success and does not predict whether the old or new directory entry would have
survived an actual crash.

Crash before journal creation leaves only an absence of durable evidence, not
proof that no request ran. A durable attempt/source intent without a durable
result becomes `OUTCOME_UNKNOWN`. A possible request start or response received
before result commit has the same meaning. Durable results are never scheduled
again. All four durable results still require sealed v2 semantic evidence.
Evidence commit without finalize remains inspectable and requires deliberate
finalization; finalized attempts block duplicates.

Trailing partial bytes are not records and are not removed. Any middle damage,
hash mismatch, sequence gap/duplicate/fork, unsafe file, or torn tail blocks
execution; corruption requires manual investigation. Inspection never repairs,
truncates, rotates, deletes, resumes, retries, creates a review/plan, or invokes
a network operation. A process restart cannot reconstruct the sealed writer
token.

The physical file is an atomically replaced complete snapshot, not a physically
append-only file. Every candidate includes the validated old sequence unchanged,
adds one record whose previous hash equals the old head, stays below 2 MiB, and
is parsed and hash-chain validated again before replace. At the limit, writes
stop without deletion. With no external anchor, a valid older snapshot can be
substituted without detection; the chain detects malformed tails, middle
corruption, reordering, gaps and forks, but not disk rollback or host compromise.

## Privacy and remaining boundary

The public projection contains only fixed IDs/hashes, enums, counts, booleans,
and four ordered minimized source states. It excludes paths, filenames, UID,
PID, hostname, raw response/header/error/URL, metadata, credentials and journal
record bodies. It cannot be deserialized into writer or execution authority.
Fixture result/evidence issuers are returned only by the private test factory;
the production factory returns no issuer, and a fixture token belongs to a
different sealed registry and cannot commit into a production-shaped service.

Only local journal persistence is added to production. Manual reobservation is
implemented-disabled and connected only by a private fixture seam.
Retention/rotation/repair policy is absent. Runtime nonce remains
blocked by live signed write; public KV cache observation remains blocked;
continuous compatibility is unproved; Testnet activation remains blocked.
