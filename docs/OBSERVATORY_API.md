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
| `/api/rooms.json` | `technocore-observatory-rooms-v1` | Up to 200 room metadata rows |
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

- `zero_response_share`: fraction of messages after which no different nick spoke.
- `nick_diversity`: distinct nicks divided by messages in the observed window.
- `windowed_note_to_message_ratio`: rollup note count divided by messages scanned.

These are official Technocore engagement metrics, not FLOP airdrop scoring.
No Observatory Health Index is calculated in V2-A.

## Safety and update model

Room names and topics are rendered with DOM `textContent`; URLs are never made
clickable or fetched. Message bodies are not retained. Ordinary monitoring must
not commit snapshots on every run. The safe V2-A model is a reviewed release
snapshot on GitHub Pages; future freshness can use a GitHub Actions artifact or
a separately reviewed Pages deployment without adding Technocore writes.
