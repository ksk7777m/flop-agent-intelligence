# Sonnet-2 Full-Lineage Binding

P0.5 binds every new receipt-observation checkpoint to the complete fixed
production observation condition.  It does not authorize registration,
network access, observer startup, or migration of an existing checkpoint.

## Canonical lineage

The lineage input is the exact JSON object with schema
`sonnet-registration-observation-lineage.v1` and these fields:

- `contest_id`
- `origin`
- `room`
- `request_id`
- `participant_did`
- `role`
- `x_account_url`
- `referee_did`
- `manifest_commit`
- `manifest_sha256`

Every value must be a non-empty string.  Keys are sorted, separators are the
compact JSON separators, JSON string escaping is ASCII-safe, and the UTF-8
bytes are hashed with SHA-256.  Values are not case-folded, URL-normalized,
trimmed, or otherwise rewritten.  The schema value provides domain and version
separation.  Extra fields cannot enter through the explicit function
signature, and the production value is derived only from the sealed reviewed
constants.

The digest proves equality with those exact local inputs.  It is not a
signature, issuer authentication, or protection from an attacker already able
to replace evidence consistently as the same operating-system user.  The
descriptor-anchored private filesystem boundary and the signed referee receipt
remain separate controls.

Receipt classification also depends on the receipt type and accepted/rejected
status.  Those are properties of the signed receipt rather than fixed
observation inputs, so they are not part of the lineage digest.  Timing,
retry, pacing, read limits, and the process deadline likewise do not change
which registration receipt is being observed.

## Checkpoint and progress version

New immutable checkpoints use
`sonnet-registration-receipt-checkpoint.v2`.  They retain the existing request
reference and add `lineage_binding_sha256`.  The request reference continues to
mean SHA-256 of the request identifier; P0.5 does not silently change its
meaning.

The mutable cursor file uses
`sonnet-registration-receipt-progress.v2` and carries the same lineage digest,
request reference, contest, room, generation, and persistent observation
identity as its checkpoint.  Only the verified cursor may advance.  Progress
replacement remains temporary-write, file-fsync, atomic-rename, verification,
and directory-fsync based.  Receipt evidence and conflict evidence remain
durable before cursor advancement.

Before network access, recovery requires one unambiguous v2 checkpoint whose
lineage digest equals the current sealed production condition.  Progress must
match that checkpoint and cannot move the cursor backwards.  A mismatch never
falls back to a fresh observation or generates another request identifier.

## Legacy checkpoint boundary

A v1 checkpoint lacks the full-lineage digest and stops with
`LEGACY_CHECKPOINT_LINEAGE_UNVERIFIED`.  It is distinguished from malformed
JSON, content digest failure, an ambiguous checkpoint set, and an ordinary v2
binding mismatch.  P0.5 does not edit, delete, reset, or migrate it.

A future separately approved migration decision requires evidence that:

- identifies the exact code and configuration used for the production run;
- establishes every saved observation condition listed above;
- proves those conditions equal the intended current conditions;
- ties the checkpoint and any progress file to that execution;
- supports preserving generation, cursor, and observation identity unchanged.

Repository history containing matching constants is not proof that those
constants were used for the production run.  Human approval is not a substitute
for technical evidence.  If any required evidence is missing or contradictory,
the checkpoint remains non-migratable and restart remains blocked.

## Partial artifact validation

Every recognized receipt, metadata, and conflict entry is checked before a
partial-pair recovery return.  Validation is descriptor-relative and checks a
no-follow, nonblocking open against the name's prior and current inode.  The
entry must be a regular file owned by the current user, mode `0600`, with one
link and a bounded size.  Directories, symlinks, FIFOs, sockets, devices,
oversized files, unsafe modes, unsafe owners, and link-count changes fail
closed.

A safe regular receipt or metadata half left by a crash remains non-terminal
and replays from the unchanged durable cursor.  File-attribute validation does
not claim that a partial receipt has a valid signature.  No partial artifact is
deleted or promoted automatically.
