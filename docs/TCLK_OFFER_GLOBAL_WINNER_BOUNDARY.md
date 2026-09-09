# TCLK Offer-global Winner / Accept Race Boundary

This package is a pure offline, descriptive-only boundary. Its production API
accepts exact offer bytes and exact signed-transcript bytes. It reuses the
pinned official TCLK schema evidence, Offline Accept Preflight validator,
transcript parser, exact `room|nonce|text` Ed25519 verifier, canonical encoder,
and their minimized evidence identities. It has no URL, reader, clock, trust
flag, winner flag, callback, path, network, signer, nonce allocator, writer,
wallet, lock, settlement, scheduler, retry, or resync input.

## Epistemic boundary

A schema-conformant, correctly signed accept whose reference and derived
contract match is only `LOCAL_ACCEPT_ELIGIBLE` in a `VALID` contract-local
view. Multiple such candidates become `RACE_LOSS_CANDIDATE`; none becomes an
`ACCEPT_RACE_LOST` result. The caller cannot provide authenticated venue order,
complete lower/upper boundaries, complete offer-wide source coverage, or a
durable Replay decision. Consequently the production API cannot emit
`OFFER_GLOBAL_WINNER_VERIFIED` or definitive race loss.

Unsigned `seq`, `ts`, and `generation`, record position, minimum sequence, and
earliest timestamp are descriptive local observations only. Reordering,
deletion, duplication, gaps, regression, equal timestamps, and mixed generation
labels change the input/artifact identity or prevent evidence escalation, but
never authenticate chronology or select a winner. Missing/invalid contracts,
derivation failures, invalid signatures, and policy rejection are not race loss,
maliciousness, payer abandonment, spam, or reputation evidence.

Winner, lock, and settlement are independent. Even a future verified winner
would not verify a lock or settlement. This package always publishes
`GLOBAL_WINNER_UNRESOLVED`, `LOCK_NOT_VERIFIED`, `SETTLEMENT_UNVERIFIED`,
`ready_to_act=false`, `authorized_to_act=false`, and
`live_action_enabled=false`.

## Field-report correction boundary

The existing Issue 142 aggregate remains an immutable, source-bound-by-artifact
point-in-time report and is not silently rewritten. This package binds only its
artifact identity and marks it `POINT_IN_TIME_REPORTED_NOT_CURRENTLY_ATTESTED`.
The user-reported replacement figures are not stored as current facts because
no exact source revision was acquired in this offline package. The states are
`CORRECTION_REPORTED`, `SOURCE_EVIDENCE_REQUIRED`,
`CURRENTNESS_NOT_CONFIRMED`, `QUANTITATIVE_IMPACT_UNRESOLVED`, and
`SUPERSESSION_REVIEW_REQUIRED`. A conflict between mutable title and body is
not emitted as confirmed fact. Neither set of figures establishes missing
contract impact, payer abandonment, winner, lock, settlement, maliciousness, or
reputation. The pinned schema, required-contract policy, and Offline Accept
Preflight remain current immutable inputs and are not obsolete.

## Public and resource safety

The public result is reconstructed field-by-field. It contains hashes and fixed
states, never raw offer/accept/transcript/frame data, DID, signature, nonce,
contract, statement, payment key, rail, room, timestamp, URL, remote error,
path, or arbitrary metadata. Errors are fixed codes without input values or
exception details. Candidate count is capped at 64; inherited parsers enforce
the transcript, record, JSON-depth/member/array/string/node, UTF-8, numeric, and
duplicate-key limits. Hashes are linkable content fingerprints, not authority.

Next package candidate: **KOL Referral Attribution / KOL Program Readiness**.
