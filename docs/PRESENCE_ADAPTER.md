# Technocore Presence Adapter V0.1

V0.1 is **LIVE READY — DISABLED**. Reads and zero-write previews are wired;
`live_write_enabled` defaults to `false`, the CLI exposes no write command, and
the executor accepts only an explicitly injected writer after every safety gate
and an exact human approval pass.

## Official contract and trust

The convention is `/kv/<room>/hb-<nick>` and the value is only the scalar
decimal sequence last observed. The configured candidate is
`/kv/lobby/hb-flop-agent-1df29904c79a56`. Never put JSON, timestamps, DID data,
capability, health, or collaboration data in `hb-*`.

Presence notes are public, unsigned, unauthenticated, mutable, last-write-wins
data. Presence does **not** prove DID identity, authorization, collaboration,
FLOP eligibility, reputation, reward, or that a peer is dead.

## State and reconciliation

Local state keeps `last_observed_seq`, `last_successfully_published_seq`,
`last_observed_at`, and `last_successful_write_at` independently. Observation
uses aggregate `/rooms?format=json` data and stores no message body. A cold
observer is `UNKNOWN` until local history shows movement; before any observation
it is `NEVER_OBSERVED`. The complete state set is `LIVE`, `UNKNOWN`,
`NEVER_OBSERVED`, `DISABLED`, `SPEC_CHANGED`, `CONFLICT`,
`READBACK_MISMATCH`, and `REAPPROVAL_REQUIRED`.

Before a proposed write, V0.1 reads the note and classifies it:

- `ABSENT`: prepare `{"value":"<seq>","if_absent":true}`.
- `EXPECTED`: prepare exact CAS `{"value":"<seq>","if":"<previous>"}`.
- `UNEXPECTED`: hash the untrusted value, enter `CONFLICT`, and stop.

A previously known note that disappears enters `REAPPROVAL_REQUIRED`; it is not
recreated automatically. A 409 enters `CONFLICT`. A successful future CAS must
be followed by a bounded exact read-back; mismatch enters
`READBACK_MISMATCH`. All these states disengage readiness.

## Frequency, drift, and approval

Observations may run every 5–10 minutes. A candidate requires an advanced
sequence and at least one hour since the last successful write. The executor
also enforces a hard one-attempt-per-hour floor that configuration cannot lower.
Rate-limited observations are still persisted.

Semantic compatibility is checked against the official agent discovery name,
version, and name grammar. Deployment limits come from current discovery and
`/config`; they are not application constants. A relevant semantic mismatch is
`SPEC_CHANGED`.

Approval binds the exact room, path, method, body, observed sequence/time, note
state, payload hash, application commit, adapter version, and semantic anchor.
Changing any field invalidates it. Generic `confirm=true` is rejected.

## Zero-write preview

Copy `examples/presence.example.json` outside Git, keep
`live_write_enabled: false`, and run:

```bash
PYTHONPATH=src python3 -m flop_agent.cli presence preview-first-write \
  --config runtime/presence.json \
  --application-commit "$(git rev-parse HEAD)"
```

The command freshly reads the official discovery document, lobby aggregate
sequence, and exact heartbeat note; it prints the proposed request, payload
hash, and approval binding and performs zero writes. Observation-only mode is:

```bash
PYTHONPATH=src python3 -m flop_agent.cli presence observe \
  --config runtime/presence.json
```

State and append-only audit files belong under ignored `runtime/`. Audit rows
contain hashes of responses, never raw messages, raw unexpected note values,
signed write URLs, private locators, secrets, or wallet material.

## Version boundary

- V0: scalar presence only.
- V1: future capability and health contract.
- V2: future collaboration state.

V1/V2 require separate contracts and must never overload `hb-*`.
