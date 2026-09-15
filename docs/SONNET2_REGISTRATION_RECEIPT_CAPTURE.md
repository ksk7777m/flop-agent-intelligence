# Sonnet-2 Registration Receipt Capture

This package is a read-only companion to the human-approved Sonnet-2 writer
registration boundary. It must be prepared before the one-shot registration is
attempted. It owns no POST method, signing key, identity loader, nonce allocator,
request-ID generator, approval issuer, or automatic resend path.

## Fixed boundary

Production construction seals the official `https://technocore.chat` origin,
the `mb-sonnet-2-registration` room, contest and writer role, the existing
registration request and participant identity, the pinned referee DID, and the
pinned manifest commit and SHA-256. Only the expected observed deployment
generation, initial high-water cursor, and UTC observation start are supplied by
the local runner. The evidence root is a sealed `receipt-evidence` child of the
existing private registration runtime root; callers cannot select a filesystem
destination, and its absolute path is never projected.

`observer_ready` is true only after all sealed configuration and bounded-read
limits validate, the private store is descriptor-anchored to an owner-controlled
`0700` directory, and a GET-only read confirms the expected room generation and
a non-regressing cursor without an unresolved gap. Readiness is status for the
external human-controlled runner. It grants no registration or write authority.

## Polling and recovery

The observer uses the official JSON read view with `since=<last_seq>`, a limit of
200, and a bounded long poll. The server-assigned sequence must be contiguous and
strictly newer than the cursor. `first_seq > since + 1` is a gap. The cursor only
advances after a structurally valid response in the expected generation.

The raw JSONL export is used only after a gap. It is accepted only from the same
fixed origin and room, without redirects, within fixed byte/record bounds, and
with `X-Room-Generation` equal to the expected generation. An export that does
not contain the target receipt does not prove absence. A generation change,
unresolved gap, timeout, HTTP 408, malformed or oversized response, network
failure, or bounded observation ending remains `UNCONFIRMED`; none authorizes a
resend.

## Verification and state

A terminal state requires a strict `sonnet.receipt.v1` object whose contest,
request, participant DID, role, and writer X account match the sealed values.
Unexpected fields and duplicate JSON keys are rejected. The signed outer record
must be in the fixed room and verify over the exact
`<room>|<nonce>|<text>` bytes using the pinned referee DID.

Only a formally signed `accepted` disposition yields `ACCEPTED`, and only a
formally signed `rejected` disposition yields `REJECTED`. Every other outcome is
`UNCONFIRMED`. Distinct valid receipts with contradictory dispositions are kept
separately as private evidence and produce review-required `UNCONFIRMED`.

## Private durability and restart

The store follows the repository's private evidence pattern: an existing
absolute root, descriptor-relative access, symlink/path-traversal rejection,
owner and mode checks, `0600` files, an exclusive lock, temporary-file write,
file `fsync`, atomic rename, and directory `fsync`. The canonical signed record
and minimized verification metadata are separate files keyed by a content
digest. Metadata never contains the signature, receipt body, request payload,
or private path. A metadata file is the completion marker, so orphan temporary
or receipt files are not formal evidence. Existing evidence is re-read and its
digest and signature are verified before reuse.

Restart reconciliation uses the same sealed request ID and never signs, posts,
allocates a nonce, or creates a replacement request. Saved verified evidence can
still be checked after the contest deadline. Missing or damaged evidence remains
`UNCONFIRMED` and is never deleted automatically.
