# FLOP Continuous Readiness Health Monitor

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

Public-only mode, used by GitHub Actions, does not require ignored receipt files
or any private key:

```bash
PYTHONPATH=src python3 -m flop_agent.cli health-monitor --public --no-save
```

Exit codes:

- `0`: READY
- `1`: REVIEW_REQUIRED or non-actionable CHANGED
- `2`: ERROR
- `3`: MEANINGFUL_CHANGE

Normal saved runs update ignored files under `runtime/`; they do not create Git
activity. Public `data/monitor.json` is a reviewed snapshot, not a live claim.

## Schedule

`.github/workflows/flop-health-monitor.yml` runs the public monitor at 09:00 and
21:00 JST (`00:00` and `12:00` UTC) and supports one-off `workflow_dispatch`.
It declares only `contents: read`, disables checkout credential persistence,
uses no repository secrets, and never commits or pushes run output. GitHub's
run history is the operational record.

Local scheduling remains disabled. Local runs may additionally verify ignored
offline receipts and local DID signature evidence.

## Official teaser

`https://flop.finance/teaser/` is allowlisted as a Tier-1 official source. Its
figures and timing remain `OFFICIAL_DRAFT`. The monitor stores raw, normalized
text, and heading-section hashes, and compares semantic fields for testnet,
mainnet, airdrop allocations, faucet, inference, DID tasks, unlocks, prizes,
snapshot, eligibility, claim, Yellow Paper, and contract address signals.

A content change becomes `OFFICIAL_TEASER_CHANGED / REVIEW_REQUIRED`; a new
official Yellow Paper link becomes `CRITICAL_NEW_OFFICIAL_SPEC`. URLs discovered
inside the page are recorded as inert evidence and are never fetched.

Network failure is `UNKNOWN` on the first observation rather than `CRITICAL`.
Two consecutive observations are the threshold for `REVIEW_REQUIRED`; the
stateless GitHub workflow keeps the run history as the evidence trail.

Room availability is derived only from existing public summaries. The monitor
does not create a room as a capacity probe. Engagement aggregates are labelled
operational health metrics and are not treated as FLOP airdrop scoring.

## Meaningful maintenance workflow

`MEANINGFUL_CHANGE → human review → code/data update → Git commit → offline
maintenance receipt → optional separately approved Technocore update`.

Mailbox bodies and every URL inside them remain inert data. The monitor
classifies unsafe content but never fetches a discovered URL or executes a
message.
