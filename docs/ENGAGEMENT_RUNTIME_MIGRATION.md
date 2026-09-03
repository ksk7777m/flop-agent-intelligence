# Engagement production runtime migration

Status: runtime fix implemented; production migration not performed. The scheduler is
already ARMED, while the loaded LaunchAgent continues to use the old system-interpreter
topology until a separately approved Approval C.

The private runtime uses immutable `generations/<approved-revision>` directories. There
is no mutable `current` link. Each generation contains its own venv, verified wheelhouse,
and private manifest; the plist names the immutable interpreter path. Existing generations
are retained as rollback evidence. The scheduler state, history, locks, receipts, and
other evidence remain outside generations and are never replaced by provisioning.
Generation publication is serialized by a stable private publication lock and uses
no-replace semantics; an existing same-revision generation is never overwritten.

The interpreter policy permits only the venv-created `python3` link whose literal target
is the approved Apple Command Line Tools Python. Every subsequent OS link must be
root-owned and the resolved object must be a root-owned regular file. Runtime root,
generation root, project paths, wheelhouse entries, manifests, and plist candidates must
not be uncontrolled links. Wheel files are user-owned `0600` regular files in a user-owned
`0700` directory. Project code resolves under the exact clean approved repository.

Project imports use one shared isolated bootstrap contract. It derives the canonical
`src` directory only from the trusted repository containing the runtime tooling, rejects
aliases, symlinks, writable directories, and arbitrary source roots, then installs that
path ahead of other import sources inside `-I`. Provisioning probes, renderer readiness,
the LaunchAgent launcher, scheduler status/run-once, and the collector subprocess all use
this contract. `PYTHONPATH`, user site, the initial working directory, and sibling checkouts
cannot select project code; the loaded `flop_agent` origin is revalidated beneath the exact
trusted `src` directory.

## Approval A — code only

Merge the reviewed feature, run the complete offline validation, and push only if that is
separately approved. Local `main` may be ahead of `origin/main` during this gate. The
dedicated validator uses `VALIDATION_ONLY_LOCAL_MAIN`: it requires a clean matching local
`main`, trusted account and production-root configuration, and the complete runtime contract,
but builds only below a private disposable root. It neither claims production eligibility nor
requires origin evidence, and it cannot publish a production generation or installable plist.
Approval A does not authorize runtime provisioning or launchd changes.

## Approval B — runtime generation only

1. Confirm local `main` HEAD equals freshly verified `origin/main`; record that SHA as the
   explicit approved-main and verified-origin evidence. Provisioning never fetches.
2. Confirm the main worktree is clean and the scheduler remains ARMED but idle.
3. Hash the authoritative state, history, and locks.
4. Build a new sibling generation from the verified private wheelhouse. Installation is
   offline and hash-locked.
5. Run `scripts/validate_engagement_production_runtime.py` and require PASS. Missing
   prerequisites are `TEST_ENVIRONMENT_MISSING`, never a skipped success.
   Its `source-runtime` is the existing trusted production root used read-only for
   state and wheelhouse inputs; the integration generation itself is built only in
   a disposable temporary directory. Account identity and production-root policy
   must pass before disposable validation can report success.
6. Before generation publication, validate the complete interpreter chain, package and
   project origins, manifest/main/project coherence, and the real isolated scheduler
   `status` path. Hash state, history, and both locks before and after; do not run collector.
7. Generate a `PRODUCTION_ELIGIBLE` plist candidate bound to the same immutable generation.
8. Recheck state, history, and lock hashes, retain prior generations, and STOP.

Approval B does not authorize plist installation, launchd reload, scheduler state changes,
or collection. A failed candidate build is removed before publication and leaves prior
generations and all scheduler data untouched.
Production readiness is mandatory inside both renderer and launcher helpers and cannot be
disabled by replacing their command runner. Feature revisions emit non-installable JSON only.

## Approval C — single-label LaunchAgent migration

1. Revalidate main, manifest, generation, and candidate plist SHA coherence.
2. Capture the active plist bytes and loaded-job metadata; confirm no scheduler run is active.
3. Boot out the existing single label.
4. Atomically publish the approved plist and bootstrap that same label only.
5. Verify the loaded configuration. Do not kickstart, manually run the scheduler, manually
   collect, reset state, or re-arm.
6. Preserve the existing ARM authorization and wait for a natural `StartInterval=3600` run.

No alternate label is permitted. Sleep does not create a replay backlog; scheduling remains
`StartInterval`, not `StartCalendarInterval`.

## Failure and rollback

If Approval C fails, stop and verify that no duplicate job exists. Preserve state, history,
locks, current generation, prior generation, captured plist, and loaded-job evidence.
Rollback requires a new explicit approval: restore only the captured prior plist, bootstrap
the same label once, do not re-arm, and do not manually trigger collection.

After a successful migration, validation is natural only: observe one scheduled run-count
increase, preflight success, at most one GET, a valid sample or bounded recorded failure,
no retry/overlap, and no Technocore write, Presence action, or wallet action.
