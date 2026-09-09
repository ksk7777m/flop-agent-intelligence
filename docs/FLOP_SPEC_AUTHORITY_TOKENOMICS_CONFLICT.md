# FLOP Specification Authority / Tokenomics Conflict

This package is a closed, descriptive-only registry for specification claims.
It separates a document's role from the ratification status of each parameter.
No source precedence, recency, arithmetic, or human acknowledgement selects a
current value.

## Repository evidence reconciliation

The retained teaser baseline identifies `flop.finance/teaser/` as a Tier-1
official draft, binds its normalized text hash, and records an agent allocation
of up to 1,200,000,000 FLOP. It also records Genesis Airdrop and unlock mechanics
only as draft signals. The retained repository evidence does **not** establish
the formal identity, v0.5.0 revision, document hash, or ratification role of a
Yellow Paper; nor does it retain source-bound extraction evidence for the
596,030,000, 3,500,000,000, or 2,483,460,000 candidates reported by monitoring.

Accordingly, the public artifact preserves all four candidate claims but labels
only the retained teaser allocation extraction `VERIFIED_LOCAL_EVIDENCE`. The
other candidates are `SOURCE_EVIDENCE_REQUIRED`; the Yellow Paper candidate is
also an `UNVERIFIED_SOURCE` with `REVISION_UNVERIFIED` and `HASH_UNVERIFIED`.
These labels verify neither the values nor their ratification.
Registering `YELLOW_PAPER` means only that the source type is recognized. The
reported v0.5.0 identity remains unverified and its content is `NOT_ATTESTED`;
it is not an official-document registration.

## Authority, parameter, and conflict axes

Source types are `YELLOW_PAPER`, `TEASER`, `WORKBOOK`, and `RATIFIED_PARAMS`.
Their distinct authority labels are `AUTHORITATIVE_REFERENCE`,
`OFFICIAL_CONTEXT`, `SUPPORTING_WORKBOOK`, `RATIFICATION_RECORD`, and
`UNVERIFIED_SOURCE`. Parameter states are `RATIFIED`, `PROVISIONAL`,
`CONFLICTING`, `TBD`, `SUPERSEDED`, and `UNRESOLVED`.

`AUTHORITATIVE_REFERENCE` never implies `RATIFIED`. Even a source whose type is
`RATIFIED_PARAMS` must have locally validated identity, revision, hash, and
sealed ratification evidence before it can create `RATIFIED` or
`RESOLVED_BY_RATIFIED_PARAMS`. Human review can acknowledge a conflict but
cannot resolve it.

Each exact decimal-string claim remains source-bound in a conflict set. Claim
and artifact identities use canonical JSON with fixed domains, never delimiter
concatenation. Mutation of a value, source, evidence state, conflict state,
scoring state, compatibility state, readiness, or authorization invalidates
the relevant identity. A caller-provided digest is not evidence authority.
The encoding revision is explicitly bound as `SORTED_ASCII_JSON_V1`.

## Scoring and action isolation

Airdrop scoring, Testnet-to-Mainnet conversion, caps, curves, minimum activity,
Agent vesting, spend-to-unlock, and final Agent allocation are all
`UNRESOLVED`. In particular, the teaser's 3:1 language is not an executable or
guaranteed rule, and inference spend is never converted into allocation.

The public schema and semantic validator use closed field sets at every level,
fixed enums, exact decimal strings, and safe errors that omit rejected values.
Raw documents, remote bodies, headers, credentials, filesystem paths, arbitrary
metadata, and exception causes are not public fields. The package has no fetch,
MCP, scheduler, network, signer, wallet, claim, pricing, or action interface.
It remains `COMPATIBILITY_REVIEW_REQUIRED`, `NO_LIVE_ACTION`,
`ready_to_act=false`, and `authorized_to_act=false`.

## Existing behavior migration

The existing Testnet activation projection already exposes only
`AIRDROP_SCORING_UNRESOLVED`, and the dashboard describes the Teaser as a draft.
Those contracts remain unchanged. Consumers needing tokenomics values must use
`data/spec_authority.json`; they must not reinterpret the older monitoring
signal as a current parameter.

## Classification and backlog

- `ALREADY_COVERED`: Testnet scoring unresolved; teaser monitoring provenance;
  remote-content isolation; readiness/authorization false; unsafe API count zero.
- `PARTIALLY_COVERED`: earlier activation evidence preserved conflicting values
  but did not expose the full source-authority axis or a closed conflict artifact.
- `MISSING` (implemented here): specification registry, exact claim identities,
  conflict sets, scoring uncertainty projection, public schema and migration text.
- `OBSOLETE`: treating any single draft tokenomics value or 3:1 relationship as
  final or executable.
- `BLOCKED_BY_SOURCE_EVIDENCE`: Yellow Paper v0.5.0 identity/revision/hash and
  three source-bound claim extractions.
- `BLOCKED_BY_RATIFICATION`: every current parameter resolution.
- `NOT_APPLICABLE`: live Technocore, wallet, claim, inference-spend, or chain work.

Next packages, not implemented here:

1. S: TCLK Transcript Completeness / Unsigned Venue Metadata Boundary
2. S: Offer-global Winner Verification / Accept Race Classification
3. A: Delegation Signature-first Resolution
4. A: TCLK vs FLOP Settlement Conformance
5. A: Rail Maturity Model
6. A: Canonical Signing / All-rails Validation
7. A: Cursor Integrity / Generation Checkpoint
8. A: Local Signer Nonce Durability
9. A: Operator Probe Traffic Classification

Latest untrusted monitoring material adds, without implementation:

- S: **TCLK Accept Schema Conformance / Observatory Historical
  Reclassification Boundary**. Exact official schema revision and whether
  `contract` is required remain unverified. Issue #142 is only a
  `HIGH_SIGNAL_FIELD_REPORT`; maintainer ratification is unconfirmed and mixed
  pull/issue references require reconciliation. Reported counts and percentages
  (1,022 / 922 / 90.2% / 711 / 666 / 93.7% / 56 / 55) are not source-bound or
  evergreen runtime facts. Local defensive classification separates structural
  facts from protocol judgments and uses `REPORTED_POLICY_MISSING_CONTRACT`,
  `REPORTED_POLICY_CONTRACT_TYPE_REJECTED`, and
  `LOCAL_ACCEPT_SAFETY_PROFILE_PASS/FAIL`; official conformance remains
  `OFFICIAL_SCHEMA_CONFORMANCE_UNKNOWN`. `ACCEPT_SCHEMA_VALID` requires pinned
  official evidence; historical accepted-but-unlocked records remain
  `HISTORICAL_CLASSIFICATION_UNRESOLVED` without complete raw evidence.
- S: **TCLK Official Schema Evidence Pinning / Offline Source Import Boundary**.
  This must precede any preflight validator and bind an exact official commit,
  schema hash/version, constraints, derivation reference, immutable snapshot,
  and supersession policy without network or action authority.
- Blocked: **Offline TCLK Accept Preflight Validator**. A future pure validator would
  require an exact pinned schema, required-field and semantic validation,
  contract ID re-derivation, canonical encoding, and all-rails validation, with
  no posting, signing, network, or action authority.

Current classification: `CURRENT_PACKAGE=NOT_APPLICABLE`,
`NEXT_S_PACKAGE=RECORDED`, `FIELD_REPORT=UNRATIFIED`, and
`OFFICIAL_SCHEMA=EXACT_REVISION_VERIFICATION_REQUIRED`. No TCLK schema,
validator, or runtime model is introduced here.
