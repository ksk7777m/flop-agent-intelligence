# Sonnet-2 Checkpoint Restart Binding

P0.4 separates the durable identity of one receipt observation lineage from
the runtime budget of any process that observes it. This closes the confirmed
restart mismatch without migrating, deleting, renaming, or rewriting an
existing production checkpoint.

## Two independent time boundaries

The existing checkpoint field `observation_started_at` is the persistent
observation identity. It is generated once for `NEW_OBSERVATION`, durably
stored before readiness, and recovered unchanged for
`RESUMING_OBSERVATION`. A restart does not compare it with a fresh wall-clock
timestamp. It continues to bind the fixed registration request, contest,
room, generation, cursor, and the production closure's participant, role,
account, referee, and manifest constants.

Each supervisor invocation separately starts a fresh monotonic deadline of at
most 1,800 seconds. Storage validation, lock acquisition, checkpoint recovery,
bootstrap, polling, bounded retry and backoff, export fallback, persistence,
and cleanup all consume that same process budget. Wall-clock rollback or jump
does not extend it, and the monotonic value is never serialized.

## Restart states and durability

- `NEW_OBSERVATION` means no durable lineage exists. The fixed factory creates
  one persistent identity. Its first verified read saves the single checkpoint
  before readiness.
- `RESUMING_OBSERVATION` means exactly one strictly verified checkpoint exists.
  Its saved identity, generation, and cursor are recovered only inside an
  opaque single-use capability. The first GET starts at the saved cursor and
  must confirm generation and cursor continuity.
- Invalid bindings fail as `CHECKPOINT_RESTART_BINDING_INVALID`; ambiguous
  checkpoint sets fail as `CHECKPOINT_RESTART_AMBIGUOUS`. Neither falls back
  to a fresh scan or a new request identifier.

The existing content-addressed checkpoint bytes and schema remain unchanged
and form an immutable lineage anchor. Verified progress after that anchor is
stored separately in one fixed, private cursor-progress file bound to the
same request reference, contest, room, generation, and observation identity.
The cursor may only advance. An unchanged cursor causes no rewrite, and a
regression or binding change fails closed.

Progress replacement writes a private temporary file, fsyncs it, atomically
renames it over the fixed progress file, verifies the replacement, and fsyncs
the containing directory. A crash before rename leaves the previous durable
cursor authoritative; a temporary artifact is never selected as a
checkpoint. A crash after rename can expose only the old or new monotonic
cursor. No timestamp or filename ordering is used to select among multiple
lineage checkpoints.

Verified terminal receipt evidence is archived before cursor progress is
advanced. For a conflict, the fail-closed marker and both verified receipts
are durable before the cursor update is attempted. Re-reading after a crash
is idempotent, cannot create a request identifier, and cannot skip a receipt;
a retention gap still requires the existing bounded export proof and
otherwise fails closed.

Deleting the checkpoint would erase continuity and could incorrectly turn a
resume into a new observation. Operators must not delete, edit, rename, or
migrate it. No automatic restart is provided; every process start remains a
separate human-approved operation.

## Capability and lock boundary

Root and child validation retain the P0.1 descriptor anchoring, no-follow,
owner, mode, inode, device, local-filesystem, repository, linked-worktree, and
cloud-sync checks. The fixed session lock is acquired non-blocking before the
checkpoint mode is selected and is held through bootstrap, observation, and
cleanup. Contention stops before network access.

The restart capability is path-free, immutable, non-copyable,
non-serializable, redacted in `repr`, and single-use. It owns both the child
descriptor and session lock until ownership is consumed by the observer.
Constructor, signal, terminal, and exception paths close the store and release
the lock.

`validate_production_restart` performs a read-only, network-free check. It
opens the existing fixed root and child, validates the checkpoint and lock
non-blocking, releases every descriptor immediately, and returns only a fixed
sanitized status such as `RESTART_VALIDATION_PASS`,
`NEW_OBSERVATION_AVAILABLE`, `CHECKPOINT_RESTART_BINDING_INVALID`,
`CHECKPOINT_RESTART_AMBIGUOUS`, or `LOCK_HELD`.

P0.4 fixes only `RESTART_BINDING_DESIGN_MISMATCH_CONFIRMED`. The earlier
`OBSERVER_UNCONFIRMED` terminal cause remains
`ROOT_CAUSE_NOT_RECOVERABLE_FROM_PRIOR_RUN`; no new cause is inferred.
