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

Review generated JSON before copying it to `api/kv/`. The example allowlist covers
the three official room-control namespaces and public `hb-` keys in `lobby`; change
it only by explicit review. Private/unlisted names and locator patterns are rejected.
Each entry also has an explicit local `max_keys` budget; exceeding it fails the poll
closed, bounding cardinality before any value reads. State keeps one row per key rather
than an unbounded value history, so repeated value churn does not grow raw archives.

## Semantics

- `first_seen_at` means **FIRST OBSERVED BY THIS OBSERVATORY**, never creation time.
- `last_changed_at` means **LAST OBSERVED CHANGE**, never server write time.
- `DISAPPEARED_FROM_OBSERVER_VIEW` states only that a previously observed key was
  absent from a later complete listing. It does not infer deletion, reclamation, or
  eviction. Empty and missing namespaces cannot be distinguished.
- Raw values are held only long enough to compute deterministic UTF-8 SHA-256 and
  are never stored or published. Embedded URLs are never fetched.
- `hb-*` notes are ordinary unauthenticated presence conventions and prove neither
  identity nor reputation. `room-owners` and `room-allow` are ownership-controlled;
`room-nonce` is server-controlled. Its individual keys, hashes, and per-key timeline
are never public; only `observed_count`, `changed_count`,
`last_observer_activity_at`, and `trust_class = SERVER_CONTROLLED` are emitted.

SQLite WAL mode, transactions, schema versioning, and generation-directory promotion
provide restart recovery and prevent mixed-generation endpoint sets. The implementation
reads the current deployment manifest at runtime and conservatively spaces metered requests.
This is an implemented runtime capability, not evidence of a completed live poll. A 429
stores only a validated, bounded `Retry-After` value (or null); response bodies are never
read into durable state and no automatic retry occurs. Unexpected limit, listing,
key, or note-banner semantics fail closed without applying a partial namespace observation.
