# Testnet Readiness and Runtime Capability

This Safety Layer package keeps five independent claims separate:

`IMPLEMENTED != DOCUMENTED != RUNTIME_OBSERVED != READY_TO_ACT != AUTHORIZED_TO_ACT`

The canonical assessment covers Identity, Technocore, Export Evidence, Faucet,
Testnet Network, Inference, Settlement Rail, and Evidence Durability. Missing or
old evidence produces explicit blockers. The overall state is the least
justified critical-domain state, never an average.

## Evidence and authority

Documentation, reviewed repository sources, signed official sources, direct
runtime observations, third-party reports, and local fixtures have distinct
provenance. Third-party reports are `UNTRUSTED_CONTEXT` and cannot promote
runtime readiness. Runtime evidence is an opaque process-local token issued by
the sealed verifier for a fixed `ReviewedRuntimeFixtureId` or, in a future
separately reviewed package, sealed acquisition evidence. Arbitrary mappings,
paths, URLs, timestamps, hashes, and response labels cannot issue production
authority. Its public projection is `DESCRIPTIVE_ONLY`; it cannot be copied,
serialized, reconstructed, or used across verifier authorities.

The checked-in package performs no live probe. Future read-only probes are
inert specifications binding an exact reviewed source ID, method, endpoint ID,
redirect policy, retry policy, timeout, response cap, and safe response
classes. A separate human approval is required before any future probe is run.
Observations are evidence only and can never initiate a claim, signature,
wallet operation, inference spend, payment, or Technocore write.

## Freshness and conflicts

The local Safety Layer default TTL is six hours. It is conservative policy, not
a protocol truth. The production TTL and clock are captured by the sealed
service and are not public parameters. A future or expired observation is
`STALE_RUNTIME_OBSERVATION`. Documentation claiming availability while the
reviewed runtime reports unavailability is
`CONFLICTING_CAPABILITY_EVIDENCE`; neither record rewrites the other.

## Action boundary

`ready_to_act` and `authorized_to_act` are separate fields. This package has no
configured action-authorization store, so it cannot mint authorization. Faucet
claims and inference execution remain disabled. PaperRail protocol validity is
not economic value: `economic_value_verified` remains false until independent
economic and finality evidence exists.

## Canonical gates and dependencies

Critical domains are explicit and cannot be omitted. An empty definition set or
a missing critical domain is `INVALID_CONFIGURATION`, never vacuously ready.
Action dependency graphs are fixed: Faucet, inference, settlement, and general
testnet review consume only their declared domain dependencies. The canonical
dependency matrix labels every domain `REQUIRED` or `NOT_APPLICABLE`:

| Action | Required domains |
|---|---|
| `GENERAL_TESTNET` | Identity, Technocore, Export, Faucet, Testnet Network, Inference, Settlement Rail, Evidence Durability, Replay Safety |
| `FAUCET_CLAIM` | Identity, Technocore, Faucet, Testnet Network, Evidence Durability, Replay Safety |
| `INFERENCE_REQUEST` | Identity, Testnet Network, Inference, Evidence Durability |
| `SETTLEMENT` | Identity, Settlement Rail, Evidence Durability, Replay Safety |

Settlement does not require Testnet Network in this generic rail model; a future
network-specific rail must add that dependency through reviewed policy. Identity backup
and recovery, inference schema/auth/spend review, rail finality/economic value,
and evidence durability are canonical blockers rather than dashboard-only text.

Network observations bind documented and observed chain, RPC, and
network/genesis identities independently. Any mismatch is
`CONFLICTING_CAPABILITY_EVIDENCE`, keeps `testnet_live` false, and blocks action.

## Offline capability taxonomy

- Native Export separates verifier implementation, documentation, runtime
  observation, trusted acquisition, and completeness.
- Delegation Verification is offline-only, preserves lossless delegation nonce
  handling, and keeps root keys local.
- Tool Output Budget is local Safety Layer policy: 200 records, 2 MiB, and an
  estimated 131,072-token ceiling. Remote/tool output is `UNTRUSTED_CONTENT`;
  discovered URLs and actions remain inert.
- The replay ledger and side-effect journal are implemented offline as a sealed,
  local SQLite safety gate. This clears only the implementation blockers; it
  supplies neither runtime observation nor action authorization. Faucet claims
  and settlement retain all independent runtime, approval, network, read-back,
  economic-value, and finality blockers.
- Agreement, TransferAttempt, and RailObservation are
  `GENERIC_MODEL_READY`; this does not claim tclk/2 is finalized.
- PTLC remains `EXPERIMENTAL_UNEXERCISED`; owned-room metadata is
  `INSUFFICIENT_AS_SOLE_AUTH_EVIDENCE`.
- Remote/hosted MCPs have no root DID, signer, wallet, or payment-key custody.

`/config` is modeled only as a future reviewed runtime source. Release, main,
live documentation, and runtime observations remain independent. Mutable
capacity, timing, quota, and rate-limit values are documented/observed/stale/
conflicting values, never permanent protocol constants.

The canonical manifest contains separate records for `stillborn_seconds`,
`idle_seconds`, `room_capacity`, `note_capacity`, `rate_limit`, and `quota`.
Each retains documented and observed values, source, observation hash, freshness,
and status independently. Checked-in values are `NOT_OBSERVED`; no current
deployment number is encoded as protocol truth. Runtime-value status,
independently derived age, and freshness labels must agree: observed values are
fresh, stale values are labeled stale, and documented-only or unobserved values
carry no runtime observation evidence.

## Canonical validation

The JSON Schema validates structure and local invariants. The sealed semantic
validator enforces cross-domain rules that JSON Schema cannot reliably express:
all required dependencies must exist and match the action graph; required child
capabilities must be ready and blocker-free before `ACTION_READY` or `AUTHORIZED`;
Replay Safety must be implemented for side-effecting actions; and mutable-value
conflicts cannot be labeled ready. `AUTHORIZED` additionally requires independent
authorization, while a consistent `ACTION_READY` manifest remains unauthorized.
For every required child, the validator independently requires sufficient
implementation and documentation state. Runtime-required children must be
`RUNTIME_OBSERVED` with complete trusted observation evidence; children whose
reviewed policy requires no runtime observation use the explicit `NOT_REQUIRED`
runtime state. Every other or future runtime state is denied by default. The
semantic validator recomputes freshness with its sealed evaluation clock and
captured six-hour local-safety TTL: age zero and exactly six hours are accepted,
while future timestamps and ages greater than six hours fail closed. Callers
cannot supply the evaluation clock or TTL.

PaperRail fields are canonical: protocol validity is independent from crypto
verification, economic value, and finality. `PAPER_RAIL` may be protocol-valid,
but `economic_value_verified` and `finality_verified` must both remain false.

## Captured dependency inventory

| Callable | Captured dependencies | Method |
|---|---|---|
| Runtime issuer | Fixture enum, fixed records, reviewed probes, registry | Closure |
| Observation validator | Exact token type and same weak registry | Closure |
| Staleness evaluator | Clock, six-hour TTL, UTC, duration type | Closure |
| Conflict evaluator | Response/state/domain enums and identity comparison | Closure |
| Aggregator | Definitions, critical domains, action dependencies | Closure |
| Faucet transition evaluator | Nested immutable transition graph | Closure |
| Action validator | Exact opaque type; no configured issuer | Closure |
| Schema projection | Assessor and fixed output keys | Closure |
