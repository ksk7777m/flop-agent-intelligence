# KV / State Observatory V0

This component is a minimal, read-only temporal observer for explicitly approved
Technocore KV namespaces. It does not enumerate namespaces and makes no claim of
complete KV coverage. Its only network primitive is `GET` to the exact official
`https://technocore.chat/kv/` origin.

## Run one poll

```bash
PYTHONPATH=src python3 scripts/observe_kv.py \
  --config examples/kv-observer.example.json \
  --state runtime/kv-observer.sqlite3 \
  --output-dir runtime/kv-api
```

Review generated JSON before copying it to `api/kv/`. The example allowlist discovers
key names in the three official room-control namespaces without fetching their values;
an empty `key_prefixes` list is deliberately discovery-only. Only public `hb-` keys in
`lobby` have an explicit local value-fetch policy. Change that policy only by explicit
review. Private/unlisted names and locator patterns are rejected.
Each entry also has an explicit local `max_keys` budget; exceeding it fails the poll
closed, bounding cardinality before any value reads. State keeps one row per key rather
than an unbounded value history, so repeated value churn does not grow raw archives.

## Semantics

- `first_seen_at` means **FIRST OBSERVED BY THIS OBSERVATORY**, never creation time.
- `last_changed_at` means **LAST OBSERVED CHANGE**, never server write time.
- `DISAPPEARED_FROM_OBSERVER_VIEW` states only that a previously observed key was
  absent from a later complete listing. It means absence observed by this observer;
  the cause is unknown. It does not infer deletion, reclamation, or eviction. Empty
  and missing namespaces cannot be distinguished.
- Current coverage is based only on the latest **completed** polling cycle. A namespace
  is `CURRENTLY_COVERED` only when its poll in that cycle succeeded; a failed or
  rate-limited latest poll is `NOT_CURRENTLY_COVERED`. A configured namespace absent
  from that completed cycle is `UNKNOWN`. Interrupted partial cycles do not replace
  the most recent completed cycle.
- Raw values are held only long enough to compute deterministic UTF-8 SHA-256 and
  are never stored or published. Embedded URLs are never fetched.
- A listing key is represented as an inert `ObservedRemoteKey`. A follow-up value
  read requires the matching configured namespace, valid key grammar, and a non-empty
  locally defined prefix policy; remote appearance alone never creates a URL target.
- `hb-*` notes are ordinary unauthenticated presence conventions and prove neither
  identity nor reputation. `room-owners` and `room-allow` are ownership-controlled;
`room-nonce` is server-controlled. Its individual keys, hashes, and per-key timeline
are never public; only `observed_count`, `changed_count`,
`last_observer_activity_at`, and `trust_class = SERVER_CONTROLLED` are emitted.

SQLite WAL mode, transactions, schema versioning, immutable generation directories,
and an atomically replaced current symlink provide restart recovery and prevent
mixed-generation endpoint sets. Completed old generations remain available throughout
promotion; startup recovery restores a missing or dangling pointer to the newest valid
complete generation. The implementation
reads the current deployment manifest at runtime and conservatively spaces metered requests.
This is an implemented runtime capability, not evidence of a completed live poll. A 429
stores only a validated, bounded `Retry-After` value (or null); response bodies are never
read into durable state and no automatic retry occurs. Unexpected limit, listing,
key, or note-banner semantics fail closed without applying a partial namespace observation.
