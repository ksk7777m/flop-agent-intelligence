# Testnet Activation Adapters and Inference Evidence

This package prepares interfaces for a future FLOP Testnet activation without
performing one. It has no HTTP or RPC client, endpoint injection, wallet
connection, signer, private-key input, approval issuer, effect callback, or live
implementation. The state remains `NO_OFFICIAL_RUNTIME`; implementation does
not mean configured, runtime-observed, ready, or authorized.

## Activation and unresolved runtime values

The modeled progression is `NO_OFFICIAL_RUNTIME`, documented and reviewed
runtime, runtime observation, identity and wallet readiness, verified Faucet
and inference requirements, evidence-path readiness, human approval, and only
then authorization. This package cannot advance that state. Chain ID, genesis
and network identity, RPC and Faucet endpoints and schemas, wallet onboarding,
identity staking, inference endpoint/auth/pricing/session semantics, escrow and
settlement, receipt formats and verification, claim paths, allocation
conversion, snapshots, and Airdrop scoring remain explicitly unresolved.

Mutable claims retain their source class: ratified protocol parameter, release,
main, live documentation, runtime observation, workbook draft, or community
claim. Conflicting official values are preserved as
`CONFLICTING_OFFICIAL_MATERIAL`; the code selects no favorable value. Draft
allocation figures and provisional spend-to-unlock relationships are never
ratified parameters or executable scoring rules.

## Disabled adapter responsibilities

`FaucetAdapter`, `AgentWalletAdapter`, `InferenceSessionAdapter`, and
`UsageReceiptAdapter` describe future discovery, validation, preparation, and
inspection responsibilities. Their sealed instances always report
`IMPLEMENTED_DISABLED`, unresolved endpoints, no runtime observation, no
approval issuer, and no live action. Wallet interfaces expose no sign, send,
broadcast, connect, private-key, mnemonic, or generic callback path. A future
Faucet or spend effect must separately obtain canonical Replay reservation and
journaling plus exact human approval. A submitted claim with no response is
`EFFECT_OUTCOME_UNKNOWN`, never implicitly safe to retry.

Root DID secret material must never be used as an Agent session or wallet key,
or exposed to browsers, hosted tools, remote services, prompts, or Git. Session
lifetime, transaction and daily caps, circuit breakers, ownership, and
revocation remain documented possibilities rather than runtime observations.

## Inference evidence ledger

`TestnetInferenceEvidenceLedger` is separate from Technocore contribution
evidence, the Replay store, and the general Evidence archive. It may retain
bounded references to descriptive Evidence Transport projections. It stores
exact hashes of bounded raw request, response, and receipt bytes—not prompt or
response bodies—and distinguishes raw response hashes from any separately
claimed normalized-result hash. Amounts and compute units are lossless canonical
decimal strings; floats and exponent notation are rejected.

All current ledger records are `EVIDENCE_INCOMPLETE`. Provider identity, model
name/hash/measured root, receipt signature, settlement identity, verified
compute, and evidence completeness remain independent. PaperRail, mock rails,
and local receipts do not prove FLOP value settlement. Signature verification
would not establish complete evidence, settlement would not establish Airdrop
eligibility, and serialized projections are always `DESCRIPTIVE_ONLY`.

The activation goal is useful verified inference followed by a usage receipt
and complete evidence—not merely obtaining Faucet tokens. Activity may be
described as useful, unknown utility, or self-referential, but receives no
reward weight. Farming loops, wash/self-spend behavior, receipt generation, and
optimization of sessions or spending for a presumed Airdrop are explicit
non-goals. Technocore activity is not Testnet allocation evidence.

## Future gates

Official activation should add separately reviewed configuration and runtime
observation rather than weaken these interfaces. It additionally requires
network, provider, receipt-signature, settlement, Replay, Evidence Completeness,
and human-approval verifiers that genuinely exist. None is configured here.
`AIRDROP_SCORING_UNRESOLVED` is the only current scoring statement, and neither
`READY_TO_ACT` nor `AUTHORIZED_TO_ACT` can be derived from a public projection.
