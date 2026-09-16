# Sonnet-2 Legacy Checkpoint Migration

This package implements a separately invoked, one-shot migration from the
legacy v1 observation checkpoint to the P0.5 v2 full-lineage format.  Import,
normal observer startup, and the default command do not migrate anything.
Production execution remains separately authorized.  The read-only prepare,
private review sealing, and apply operations are three distinct modes.

## Evidence boundary

Migration relies on the reviewed operational correlation for the single P0.2
run under the owner-managed, local-only threat model.  Adding the current
lineage digest does not independently prove which historical configuration
created the legacy bytes.  The tool therefore also requires an exact legacy
schema, fixed request reference, fixed contest and room, a single checkpoint,
an optional matching progress file, and an unchanged prepare/apply inventory.

## Archive and transaction

The external private runtime root must contain a separately provisioned fixed
archive child named by `ARCHIVE_BASENAME`.  It must be an existing local
directory owned by the current user with mode `0700`; migration never creates
it.  Exact legacy checkpoint and optional progress bytes are written without
modification as mode `0600` files.  Exclusive creation, file fsync, reread and
digest verification, and archive-directory fsync complete before active state
changes.  The archive digest is an integrity check, not a signature.

After archive durability, a fixed transaction marker is made durable in the
active child.  P0.5 treats the marker and staging names as unknown artifacts,
so normal observation fails closed throughout the multi-file transition.  The
v2 checkpoint and optional v2 progress are staged and fsynced, the exact
prepared v1 checkpoint is removed, and staged files are switched under the
same non-blocking session lock.  The marker remains until exact-byte checks and
active-directory fsync complete.  It is then removed and the existing P0.5
checkpoint and receipt validators run directly under the already-held lock.
No second lock acquisition or unlocked validation window exists.

The conversion changes only `schema` and adds `lineage_binding_sha256`.
Request reference, contest, room, generation, checkpoint cursor, latest
durable progress cursor, and persistent observation identity remain exact.
No value is guessed, normalized, reset, or regenerated.

## Prepare and target fixation

The default entry point is read-only.  It validates the current legacy target
and reports only a fixed status; its in-memory plan intentionally expires with
the process.  A later apply must not treat a newly selected valid target as the
one a human reviewed.  Therefore a separately authorized `--seal-review` mode
revalidates the target under the session lock and exclusively writes one fixed
private review record in the active child.  The record contains only internal
digests and the sealed lineage digest, is mode `0600`, and is never printed or
accepted through argv or environment values.

The review record is an unknown artifact to the normal observer, so observation
remains fail-closed between review sealing and apply.  `--apply` loads that
record, requires the exact checkpoint bytes, progress presence and bytes,
lineage, empty archive, and inventory to match, and then revalidates once more
immediately before switching.  Apply cannot consume an ordinary read-only
prepare plan.  The review record is an owner-managed local correlation record,
not a signature or cryptographic execution attestation.

Generated v2 checkpoint and progress payloads pass the same P0.5 semantic
validation core before either commit guard is removed.  The transaction marker
is removed first; the review record continues to block normal observation.
Only after semantic validation and durable switching is the review record
removed and its directory fsynced.  A crash between guard removals therefore
remains fail-closed, while a crash after the final guard removal leaves the
already validated v2 state.

## Crash behavior

There is no automatic rollback or recovery.  A failure before the transaction
marker leaves active v1 evidence unchanged, possibly with a partial private
archive.  A failure after the marker leaves a marker, a staging file, or a
mixed v1/v2 inventory that P0.5 rejects.  Manual review must use the archive,
marker, and active inventory to decide the next action; timestamps and largest
cursors never select a winner.  Re-running a partially completed migration is
rejected because the archive is no longer empty or the active inventory is not
exactly one v1 checkpoint plus optional v1 progress.

The fixed archive child must be provisioned in a future, separately authorized
operation before production preparation.  Later authorizations must separately
cover read-only preparation, `--seal-review`, and only then `--apply`.
Successful migration does not start an observer, contact Technocore, sign,
register, or create a new request identifier.
