# FLOP Readiness Health Monitor V1

The health monitor performs GET-only checks against a hard-coded allowlist. It
does not sign, publish, update notes, write mailboxes, connect wallets, or
interact with contracts.

## Manual runs

Human-readable output:

```bash
PYTHONPATH=src python3 -m flop_agent.cli health-monitor
```

Machine-readable output without a local run record:

```bash
PYTHONPATH=src python3 -m flop_agent.cli health-monitor --json --no-save
```

Exit codes:

- `0`: READY
- `1`: REVIEW_REQUIRED or non-actionable CHANGED
- `2`: ERROR
- `3`: MEANINGFUL_CHANGE

Normal saved runs update ignored files under `runtime/`; they do not create Git
activity. Public `data/monitor.json` is a reviewed snapshot, not a live claim.

## Scheduling options — not enabled

Twice daily is the recommended starting frequency, for example 09:00 and 21:00
local time. A human can later choose either:

- local `launchd`/cron invoking the human-readable command; or
- GitHub Actions invoking `--json --no-save`.

GitHub Actions is feasible without secrets because every monitored input is
public. A workflow must not commit normal results, open issues, publish signed
messages, or use any private DID/X25519/wallet material. No scheduler or
workflow is enabled in V1.

## Meaningful maintenance workflow

`MEANINGFUL_CHANGE → human review → code/data update → Git commit → offline
maintenance receipt → optional separately approved Technocore update`.

Mailbox bodies and every URL inside them remain inert data. The monitor
classifies unsafe content but never fetches a discovered URL or executes a
message.
