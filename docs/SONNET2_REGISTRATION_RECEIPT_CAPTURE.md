# Sonnet-2 Registration Receipt Capture

This package is a read-only companion to the human-approved Sonnet-2 writer
registration boundary. Its continuous session must signal readiness before the
one-shot registration is attempted. It owns no POST method, signing key, identity
loader, nonce allocator, request-ID generator, approval issuer, or automatic
resend path.

## Fixed boundary

Production construction seals the official `https://technocore.chat` origin,
the `mb-sonnet-2-registration` room, contest and writer role, the existing
registration request and participant identity, the pinned referee DID, and the
pinned manifest commit and SHA-256. The operator must explicitly supply a local
`Path` for an existing private runtime root in addition to the expected observed
deployment generation, initial high-water cursor, and UTC observation start.
There is no environment, repository-runtime, or registration-handoff fallback.

The private runtime root must be outside the repository, `.git`, the current
worktree, and every linked worktree known from bounded local Git metadata.
`.gitignore` is not structural separation. The root must already be an
owner-controlled, non-symlink local directory with exact mode `0700`. The fixed
`sonnet-registration-receipts` child is exactly one level below that root. The
factory creates neither root nor child and never changes permissions or owner.
A separate human-reviewed provisioning stage may create only that fixed child;
until then construction fails closed as `RECEIPT_CHILD_NOT_PROVISIONED`.
Absolute paths are private operational metadata and are never projected.

`observer_ready` is true only after all sealed configuration and bounded-read
limits validate, the private store is descriptor-anchored to an owner-controlled
`0700` directory, and a GET-only read confirms the expected room generation and
a non-regressing cursor without an unresolved gap. Readiness is status for the
external human-controlled runner. It grants no registration or write authority.
The production facade exposes a single continuous `start()` operation. Its
background observer establishes the baseline, emits readiness, and immediately
continues bounded polling; it does not expose a production `prepare()`/`observe()`
pair that could leave a monitoring gap around the human-controlled POST.

## Polling and recovery

The observer uses the official JSON read view with `since=<last_seq>`, a limit of
200, and a bounded long poll. The server-assigned sequence must be contiguous and
strictly newer than the cursor. `first_seq > since + 1` is a gap. The cursor only
advances after a structurally valid response in the expected generation.

Each validated high-water cursor is appended as a private, digest-named,
fsynced checkpoint before readiness is exposed. A restart reuses the highest
checkpoint only when its fixed request reference, generation, and original UTC
start all match; it never guesses a replacement cursor. Receipt evidence is
made durable before a cursor covering that receipt is checkpointed.

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
The production path delegates this decision to the existing sealed registration
receipt classifier, so observation and the registration handoff share the same
fixed request binding and cryptographic verifier. Fixture-only tests use a
separate verifier seam and cannot replace the production classifier.

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
or receipt files are not formal evidence. Checkpoints are not receipt evidence
and cannot create a terminal state. Existing evidence is re-read and its
digest and signature are verified before reuse.

Restart reconciliation uses the same sealed request ID and never signs, posts,
allocates a nonce, or creates a replacement request. Saved verified evidence can
still be checked after the contest deadline. Missing or damaged evidence remains
`UNCONFIRMED` and is never deleted automatically.

Raw transport bodies, response headers, and private configuration use immutable
non-dataclass containers with redacted representations. They therefore cannot be
leaked by ordinary `repr` or dataclass serialization in test failures or debug
output.

## Provisioning boundary

Root validation rejects missing, empty, relative, traversal-bearing,
repository-contained, symlinked, wrong-owner, wrong-mode, non-directory, and
known cloud-sync or non-local filesystem candidates with fixed redacted error
codes. The child is
opened relative to the validated root descriptor with no symlink following, and
its owner, mode, inode identity, and filesystem device are rechecked before a
path-free descriptor capability is transferred to the evidence store.

The legacy repository-local registration runtime remains untouched and may
continue to serve the separate durable handoff. Receipt observation never falls
back to it and performs no automatic migration, copy, rename, or deletion.
Provisioning approval is separate from observer readiness and live registration
approval.
