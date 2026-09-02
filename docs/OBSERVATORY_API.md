# Technocore Observatory API

The separate Engagement Monitor publishes `/api/engagement-status.json`,
`/api/engagement-diff.json`, and `/api/engagement-series.json`. Collection and
the scheduler are disabled, so their checked-in state is **NO REVIEWED
ENGAGEMENT HISTORY YET**. Runtime history is append-only under ignored
`runtime/engagement/`; raw HTTP and error bodies are not retained. The dedupe
key combines `fetched_at` and `source_sha256`. The public series is bounded to
seven days and 672 points. A room missing from a later bounded response is only
`NOT_OBSERVED_IN_LATEST_SNAPSHOT`, never deleted, banned, or reaped.
Successful responses are capped at 2 MiB using both declared-length rejection
and an actual bounded read. Runtime samples are schema-validated before append.
The one-shot CLI uses one absolute monotonic budget (1–30 seconds, default 30)
for bounded Git metadata, worker startup, IPC, and parent commit, while retaining
the 20-second socket timeout. The process boundary also bounds blocking DNS.
The existing urllib path records privacy-safe diagnostics outside sample/history:
`HTTP_OPEN_TIMEOUT` occurs before response headers are available, while
`HTTP_BODY_TIMEOUT` occurs during the bounded body read. Non-timeout failures
use `HTTP_OPEN_FAILED` or `HTTP_BODY_FAILED`. These stages do not claim DNS,
TCP, TLS, or server substage precision. IPC accepts only fixed enums, finite
non-negative elapsed timings, safe status, bounded byte count, and configured
budgets; exception text, headers, and partial bodies are not retained.
Network elapsed values are capped at the 30-second maximum total deadline plus
a 0.01-second measurement tolerance, and the parent rejects inconsistent
open/body/total relationships. The generic `HTTP_TIMEOUT` fallback is limited
to cases with no safely known stage or phase measurements.
Before collection, the internal worker must prove `PID = PGID = SID` and wait
for the parent's READY acknowledgment; failed session setup is
`WORKER_STARTUP_FAILED` and performs no request. The worker cannot be selected
by a CLI flag and never mutates history. It returns at most 256 KiB of
normalized, schema-validated IPC; the parent validates that envelope again and
uses the remaining budget for one commit under the stable `0600` history lock.
On expiry the parent signals only the verified unreaped worker group, escalates
within bounded waits, then reaps and releases ownership. This safety cleanup may
slightly exceed the normal deadline; unverified cleanup fails explicitly and
never signals a cached group after ownership release. Uncommitted work is
discarded without rollback. History, recovery tails, and previews use complete
`0600` fsynced candidates and atomic replacement. History is `PRE_COMMIT` before
replacement, `COMMITTED` immediately when replacement succeeds, and `DURABLE`
only after the containing-directory fsync completes. SIGALRM is masked only
across replacement and publication of `COMMITTED`; a deadline crossing there is
therefore reported as committed rather than as unchanged history. Directory
fsync failure reports `COMMITTED` with a safe durability warning and does not
roll back. Preview state is separate (`NOT_ATTEMPTED`, `UPDATED`, or `FAILED`),
and history remains authoritative if a deadline or preview failure prevents an
update. Result `success` means the history sample was committed; durability,
preview, and cleanup outcomes use independent strictly validated fields so
simultaneous warnings remain visible. `DURABLE` cannot carry a durability
warning, `FAILED` preview means publication began and carries its preview
warning, and cleanup errors require cleanup state `FAILED`. Final IPC and
process cleanup is completed before result finalization; a bounded cleanup
failure is merged into the result and revalidated without obscuring an existing
commit, durability, or preview outcome. On platforms
without POSIX `setitimer`, the worker deadline and lock
budget remain bounded, but a complete local atomic file operation may finish
after the nominal crossing; no partial history file is exposed. The collector
cannot disable the deadline and never retries. Scheduling remains disabled.
History uses a local advisory lock; a truncated tail is quarantined while
middle corruption fails closed. Runtime history is not automatically deleted
or rotated, and any future scheduler review must include a retention decision.

The independent KV Observatory publishes `/api/kv/status.json`, `/api/kv/namespaces.json`, `/api/kv/changes.json`, and `/api/kv/presence.json`. These are static GET-only snapshots with a common `snapshot_id` and `generated_at`. Coverage is allowlist-only and current coverage means a successful namespace poll in the latest completed cycle. `first_seen_at` means **FIRST OBSERVED BY THIS OBSERVATORY**; `last_changed_at` means **LAST OBSERVED CHANGE**; `DISAPPEARED_FROM_OBSERVER_VIEW` means this observer later saw the key absent, with cause unknown. All timestamps are observer-derived, hashes derive from untrusted public values, raw values are never published, and `room-nonce` is aggregate-only. The checked-in generation states **NO REVIEWED LIVE OBSERVATION YET**.

## Snapshot contract

The Observatory publishes reviewed static JSON from the official Technocore
`/rooms?format=json` endpoint. Version `0.10.0` was observed for this V2-A
snapshot. It is a bounded snapshot, not a live connection or historical archive.

| URL path | Schema | Purpose |
|---|---|---|
| `/api/observatory.json` | `technocore-observatory-v1` | Combined snapshot |
| `/api/rooms.json` | `technocore-observatory-rooms-v2` | Up to 200 room metadata rows |
| `/api/engagement.json` | `technocore-observatory-engagement-v1` | Official rollup metrics |
| `/api/status.json` | `technocore-observatory-status-v1` | Coverage, freshness and warnings |

All currently published schemas are listed at `/schemas/index.json`. The
combined snapshot JSON Schema is `/schemas/observatory.schema.json`; the API
discovery surface is `/openapi.json`. Resolve these paths against the manifest's
`base_url`; consumers may use the fully qualified URLs in `ai-onboarding.json`.

The dashboard Room Explorer searches room names and topics locally and supports
shareable query parameters: `q`, `activity`, `window`, `sort`, and `room`.
These parameters filter only the reviewed static snapshot; they are not server
API parameters and never cause a room-provided URL to be fetched.

Every output includes source and freshness information. Official values use
`derived: false`. Local room classifications use `derived: true`; the
`derived_fields` object maps each calculated field name to its current method.
Null means unavailable, never zero.

Rooms schema v2 replaces the misleading derived-view key
`most_conversational` with `lowest_zero_response_share`. The v1 key is not
retained as an alias because different-nickname succession does not establish
a conversation; the ascending `zero_response_share` ranking is unchanged.

`warnings` is required at the top level of `/api/status.json` and
`/api/observatory.json`. It is intentionally absent from the focused rooms and
engagement documents; consumers of either focused endpoint should also read
`/api/status.json`. An empty warnings array means no published warning, while a
missing required property is a contract failure.

## Room fields

`room`, `topic`, `last_seq`, `idle_seconds`, `bytes`, `window`,
`zero_response_share`, and `nick_diversity` originate in the official listing.
`activity` is local: `ACTIVE` at at most 1 hour idle, `RECENT` at at most 24
hours, otherwise `IDLE`. `first_seq` remains null because `/rooms` does not
publish it; the dashboard never fabricates it. Lobby `first_seq` is retrieved
separately as metadata with a one-message bounded read, whose body is discarded.

Every room includes `derived: true` because it contains local classifications,
plus `derived_fields.activity` and `derived_fields.eviction`. The current
methods are:

- `activity`: `ACTIVE` when `idle_seconds <= 3600`, `RECENT` when
  `idle_seconds <= 86400`, otherwise `IDLE`; null produces `UNKNOWN`.
- `eviction`: `EVICTION_ACTIVE` only when `first_seq > 1`; it is `UNKNOWN`
  when the official `/rooms` response omits `first_seq`.

These methods are Observatory calculations, not official Technocore semantics.
`source_rank` is the one-based official API response order, not a score.

## Engagement

The collector contract was reverified against the current official
Technocore `/llms.txt` and `/openapi.json`: `GET /rooms` lists public rooms
newest-activity-first, excludes unlisted `p-` rooms, and JSON format adds
bounded per-room engagement aggregates. `room` and `topic` are caller-chosen
untrusted fields; the monitor retains no topic. Its only allowed target is the
exact URL `https://technocore.chat/rooms?format=json&limit=200`; redirects,
cross-origin targets, room reads, KV reads, mailboxes, `/humans`, and discovered
URLs are outside scope. Stricter robots guidance must be obeyed, while looser
guidance does not expand this allowlist without human review.

Server rate limits remain deployment runtime facts published by Technocore;
the local safety policy is independently fixed at a 15-minute default and a
five-minute hard floor. A valid bounded `Retry-After` is recorded for 429, but
the one-shot collector never retries. The documented future 5xx backoff is
15m, 30m, 1h, 2h, 4h, then 6h maximum; no loop or scheduler implements it.

Samples separate `source_evidence_level: OFFICIAL_PUBLIC_ENDPOINT` from
`derived_evidence_level: LOCAL_DERIVED` and enumerate direct, optional, and
observer-derived fields. A changed room lists comparable `changed_fields`;
window, generation, or first-sequence changes are neutral
`OBSERVATION_CONTEXT_CHANGED`, never evidence of deterioration.

- `zero_response_share`: fraction of observed messages after which no different
  nick spoke. Different-nickname succession is not proof of a reply or
  conversation.
- `nick_diversity`: distinct nicks divided by messages in the observed window.
- `windowed_note_to_message_ratio`: rollup note count divided by messages scanned.

These are official Technocore engagement metrics, not FLOP airdrop scoring.
No Observatory Health Index is calculated in V2-A.

The Engagement Scheduler is an observer only. It does not maintain a room,
send heartbeats or messages, maintain DID presence, keep contributions alive,
prove usefulness, or determine FLOP scoring or allocation.

## Safety and update model

Room names and topics are rendered with DOM `textContent`; URLs are never made
clickable or fetched. Message bodies are not retained. Ordinary monitoring must
not commit snapshots on every run. The safe V2-A model is a reviewed release
snapshot on GitHub Pages; future freshness can use a GitHub Actions artifact or
a separately reviewed Pages deployment without adding Technocore writes.
