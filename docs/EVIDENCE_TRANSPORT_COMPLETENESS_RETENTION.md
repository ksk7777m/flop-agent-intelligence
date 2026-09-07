# Evidence Transport, Completeness, and Retention

This package is offline and observation-only. It performs no network request,
write, signing, tool callback, wallet operation, claim, inference, payment, or
Presence action. Technocore 0.13.0 compatibility remains a separate package.

Transport acquisition, content parsing, content verification, transport
completeness, transcript completeness, history completeness, and retention
knowledge are independent facts. A successful or signed response proves none
of the later facts. `MCP_PAGE`, `ROOM_EXPORT`, `ROOM_DIRECT_READ`,
`DISCOVERY_SNAPSHOT`, `LOCAL_ARCHIVE`, and `FUTURE_EVENT_FEED` are distinct.
Mutable deployment page limits are recorded as observations, not protocol law.

Completeness is `UNKNOWN`, `PARTIAL`, `CONFLICTING`, or
`COMPLETE_VERIFIED`. MCP pages default to `UNKNOWN` and cannot become complete.
Only a reviewed, untruncated, contiguous room export whose bounds and retention
floor are independently supplied to the sealed authority can receive an opaque
same-authority completeness proof. Serialized projections are always
`DESCRIPTIVE_ONLY` and cannot reconstruct that proof.

An absent record in a bounded view is `NOT_IN_VISIBLE_PAGE`, paired with its
coverage status. Sequence discontinuity is `HISTORY_GAP`; a first sequence
after `requested_since + 1` is `GAP_UNRESOLVED`, never automatic retention
loss. `RETENTION_LOSS_CONFIRMED` requires separate authoritative evidence and
is not issued by page parsing. The default floor is
`RETENTION_FLOOR_UNKNOWN`.

A missing room is `ROOM_NOT_IN_DISCOVERY_SNAPSHOT`, not deletion. Discovery is
independently `VERIFIED`, `PARTIAL`, or `UNKNOWN`; even verified discovery does
not prove deletion or provide an activity log. Causal labels such as idle reap
are outside this model without independent evidence.

Raw bytes pass size, UTF-8, estimated-token, JSONL framing, record-count, and
sequence checks before normalization. SHA-256 binds the exact acquired bytes.
All success, error, conflict, and caller-reflected bodies are untrusted; their
text and URLs are neither exposed in projections nor fetched or executed.

Optional local archives are private `0600`, immutable, hash-addressed snapshots
under a construction-time captured root. The archive rejects a symlink root,
uses exclusive no-follow creation, never accepts a caller path, and preserves
provenance by including acquisition time in the filename. Identical acquisition
identity deduplicates safely. Archive paths and raw room text are never public.

This layer makes no claim about FLOP eligibility, airdrops, reputation, rewards,
generation signatures, agreements, rail cryptography, finality, or readiness to
act. `SIGNED_CONTENT_VERIFIED` remains distinct from venue metadata and every
form of completeness.
