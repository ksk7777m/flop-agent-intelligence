# Engagement Scheduler V0.1

Scheduler V0.1 is an offline-reviewed, disabled-by-default policy wrapper around
the existing Engagement collector. Its existence does not activate collection:
the repository and public capability state remain **Scheduler: DISABLED**.
There is no activation command, installed cron or launchd job, or scheduled
GitHub Actions workflow.

## Policy

- Normal cadence: 60 minutes. A low-frequency cadence fits an aggregate trend
  use case, a capped 200-room snapshot, unavailable rate metadata, and the
  observed history of one no-response timeout followed by bounded 3.073- and
  2.070-second successes. Real-time polling is unnecessary.
- Hard minimum: 30 minutes, even if future approved configuration is lowered.
- Daily ceiling: 24 attempts in a rolling 24 hours. This is a ceiling, not a
  target.
- Retry count: zero. One allowed run invokes the reviewed collector at most
  once, which can issue at most one GET. Failures wait for a later decision.
- Server metadata may lengthen a future approved wait, but can never shorten
  the configured cadence or the hard minimum. Missing metadata grants nothing.
- Circuit breaker: the first consecutive failure is `DEGRADED`; the second is
  `CIRCUIT_OPEN`. Time never resets an open circuit. `approve-reset` moves it to
  `READY_DISABLED` without collecting; activation or execution is a separate
  approval. Reset clears the consecutive count but preserves attempt timestamps,
  last attempt, last success, and the most recent bounded forensic error class.
- Scheduled success is deliberately stricter than collector history commitment:
  only a durable history commit with an updated preview and completed cleanup is
  clean success. Other committed outcomes remain authoritative in history but
  count as a bounded scheduler failure requiring later review.
- Collection and publication are separate. The wrapper can only create ignored
  private runtime history/previews through the collector. It cannot update API
  JSON, commit, push, deploy, post messages, or access Presence/KV writers.

Collection failures are the fixed enum implemented in
`flop_agent.engagement_scheduler.FAILURE_CLASSES`. None are retried. A stable
private lock prevents overlap without terminating the legitimate active run.
Spacing and rolling-budget refusal do not count as network failures because no
collector is invoked.

## State and recovery

State is local at `runtime/engagement/scheduler-state.json` with mode `0600`.
It contains only the enabled flag, circuit state, bounded interval, last attempt
and success UTC timestamps, consecutive failure count, bounded last error,
rolling attempt timestamps, and an in-progress marker. It contains no response,
exception text, headers, room/topic content, or URL. A private fsynced candidate,
atomic replacement, and directory fsync make updates crash-safe.

Missing, corrupt, future-dated, internally inconsistent, or permission-unsafe
state fails closed. An attempt is durably recorded before collector invocation.
If an in-progress marker survives a crash, the next locked decision records a
bounded `WORKER_CRASHED` failure and makes no request.

## CLI surface

`status`, `dry-run`, `run-once`, and `approve-reset` are the only commands.
`dry-run` reports allowance, spacing, rolling budget, circuit state, overlap,
and next eligibility without invoking the collector. `run-once` applies every
safety gate and has no bypass flag. `approve-reset` never invokes the collector.
No command initializes or enables scheduling; those remain future reviewed
operations.

## Execution environment review

| Environment | Assessment |
|---|---|
| Local cron | Can preserve private history/state, but environment and overlap handling are less explicit; do not install in V0.1. |
| launchd | Best future macOS fit for a local wrapper: stable local storage, explicit process ownership, and auditable configuration. Installation and enablement require separate approval. |
| GitHub Actions schedule | Not recommended: ephemeral runners do not preserve local private history or circuit state, and repository/deployment credentials enlarge the boundary. |
| External/manual automation | Acceptable only when it invokes this wrapper locally and cannot bypass its state, lock, spacing, budget, or circuit gates. |

The recommended future architecture is a separately reviewed, disabled launchd
definition invoking this local wrapper. No OS schedule is included here.
