# Engagement Scheduler Approval C — Pre-Activation Controls

Approval C adds offline controls; it does not activate collection. The real scheduler
remains `READY_DISABLED`, and no LaunchAgent is installed or loaded.

Scheduler state v0.2 adds the retained UTC field `not_before_at`. A legacy v0.1 state
is accepted only when disabled and is migrated in memory to v0.2 with a null boundary;
reading status does not rewrite it. The narrow `enable-scheduled` transition accepts
only a valid, non-running `READY_DISABLED` state with no unresolved failure count. Under
the scheduler lock it writes `READY`, enables policy, and sets `not_before_at` to the
activation time plus the authoritative 60-minute normal interval. It performs no
collection or network request. Before that boundary, dry-run and run-once return
`SCHEDULER_NOT_BEFORE` without recording an attempt. Normal spacing, rolling budget,
overlap, and circuit gates remain additive and authoritative.

`disable-scheduled` is a separate offline rollback control. It preserves attempts,
timestamps, error evidence, history, and the activation boundary. Circuit reset remains
separate, returns to disabled, and never re-enables automatically. A later eligible
re-enable creates a fresh future boundary.

The private plist renderer performs offline code-revision and tracked-tree checks,
requires an explicit 40-character revision, substitutes all template placeholders,
and creates a new `0600` plist exclusively in a private staged directory. It refuses
the active `~/Library/LaunchAgents` directory, never overwrites, and has no load or
bootstrap capability. The Approval B SHA is suitable only for fixtures: after Approval C
is merged, production rendering must pin the new exact main SHA.

Future activation requires separate authorization and this order:

1. Merge Approval C and obtain the exact new main SHA.
2. Run the full offline suite and confirm the real state is still `READY_DISABLED`.
3. Render and inspect a private staged plist pinned to that SHA.
4. Bootstrap the `RunAtLoad=false` LaunchAgent while the scheduler is still disabled.
5. Explicitly approve the offline enable transition, creating `not_before_at` at least
   60 minutes ahead of the first eligible collection.
6. Verify state and loaded status; do not kickstart. Wait for a scheduled opportunity.

Bootstrapping while disabled closes the gap in which an enabled scheduler exists without
its control plane. The policy boundary, rather than launchd timing, prevents an immediate
request. Rollback is: disable offline, boot out the agent, verify no process remains, and
preserve state, history, and logs.
