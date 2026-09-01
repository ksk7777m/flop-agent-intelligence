# Engagement LaunchAgent V0.1 — Approval B

Approval B supplies an unloaded user LaunchAgent template and a pinned preflight
launcher. It does not install or load a job, enable the scheduler, or authorize
collection. The scheduler remains `READY_DISABLED` and is still authoritative
for state validation, spacing, budget, overlap, and circuit policy.

The template uses `StartInterval=3600`, `RunAtLoad=false`, no `KeepAlive`, and
direct isolated execution through `/usr/bin/python3 -I`. There is no replay backlog
or N-times catch-up burst; depending on macOS/launchd behavior, missed intervals may
produce at most one coalesced wake-time opportunity. Internal scheduler gates remain
authoritative, and there is no connectivity probe. Placeholders must be replaced
with a separately reviewed absolute repository root, private runtime root, and
the final approved 40-character Git revision during Approval C. Public files do
not contain private local paths.

The launcher rejects revision drift, tracked-tree changes, missing or symlinked
reviewed code, and missing/invalid scheduler state before `run-once`. Ignored
runtime files do not dirty the tracked tree. It never updates Git and the runtime
root cannot select executable code. A disabled invocation returns `OK_DISABLED`
with zero collector and network requests.

Private JSONL logging is required before a network-capable scheduler invocation.
Logs and their lock are `0600` inside a private `launcher-logs` directory, rotate
at 1 MiB, and retain three files total. Records contain only UTC time, bounded
outcomes, circuit state, request count, and collector invocation count. Raw
responses, room content, exception text, environment data, paths, URLs, and
secrets are forbidden. Preflight logging failure blocks invocation. A logging
failure after scheduler return preserves the bounded scheduler outcome and invocation
facts while reporting `log_persisted=false` and `log_error_class=LOG_UNAVAILABLE`.

If a future launcher receives `READY_DISABLED`, it may call the scheduler but
the scheduler refuses collection. Approval C must separately implement and
review an atomic enable transition with a policy-layer `not_before_at` so first
eligibility is approximately activation time plus 60 minutes.

Future installation destination (not created here):
`~/Library/LaunchAgents/com.flop-agent-intelligence.engagement-scheduler.plist`.
Future macOS commands, shown only as a preview, are:

```text
launchctl bootstrap gui/<uid> <APPROVED_LAUNCHAGENT_PATH>
launchctl bootout gui/<uid>/com.flop-agent-intelligence.engagement-scheduler
```

Rollback order is: disable scheduler state, boot out the LaunchAgent, verify no
launcher/scheduler/collector remains, and preserve state, history, and logs.
