# TCLK Accept Schema Conformance / Historical Reclassification Boundary

This package is an offline, descriptive Observatory classification boundary. It
does not post accepts, verify signatures, execute rails, read Technocore, or
select an offer winner.

## Source evidence

The repository does not retain the official TCLK frame schema, its exact
revision or hash, the `contract` derivation specification, or a canonical
identity proving whether reference 142 is an issue or pull request. The fixed
policy therefore records `OFFICIAL_SCHEMA_REVISION_REQUIRED`,
`REVISION_UNVERIFIED`, `HASH_UNVERIFIED`, and `SOURCE_EVIDENCE_REQUIRED`.
The reported requirement for `contract` is not content-attested. No current
official-schema-valid claim can be generated.

The reported reference 142 measurements are a separate
`HIGH_SIGNAL_FIELD_REPORT`: `UNRATIFIED`, `POINT_IN_TIME_REPORTED`,
`METHODOLOGY_NOT_INDEPENDENTLY_REPRODUCED`, not evergreen, not protocol
specification, and not current-runtime proof. Counts are bounded integers.
Exact fractions `461/511`, `74/79`, and `55/56` are derived from count pairs
without floats; the reported
percentage strings remain non-authoritative display values. No DID list,
frame, signature, room, URL, or author data is retained.

## Structural facts, local profile, and ordered stages

The projection separates directly observed structural facts (parse result,
type presence/equality, contract presence/type/emptiness, and unknown-field
presence) from every protocol judgment. Contract values themselves are never
published. A fixed local defensive profile may pass or fail, but has
`official_schema_authority=false`; official conformance is always
`OFFICIAL_SCHEMA_CONFORMANCE_UNKNOWN` in this package.

The model keeps these dimensions independent: frame observed, accept type,
official schema validity, signature validity, replay validity, contract
presence, contract derivation, evidence completeness, offer-global coverage,
offer-global winner, lock observation, and settlement verification.

The 12 stages are an ordered grammar with fixed ordinal, ID, and epistemic
state (`VERIFIED`, `REJECTED`, `NOT_EVALUATED`, `EVIDENCE_REQUIRED`, or
`UNKNOWN`). Missing, duplicate, reordered, unknown, and truthy/bool ordinal
forms are rejected. No later stage can prove an earlier one.

Obvious local shape failures use fixed priority: malformed input, non-accept
frame, unknown field, missing `contract`, then rejected local contract shape.
Independent failures are preserved. A contract-shaped candidate is only
`LOCAL_ACCEPT_SAFETY_PROFILE_PASS`; it is not promoted to official schema
validity, signature validity, accepted-contract count, winner, lock, or
settlement. Missing contract is `REPORTED_POLICY_MISSING_CONTRACT`—never an
official invalidity, race loss, payer abandonment, replay, spam, maliciousness,
or negative reputation.

No caller boolean can inject verified evidence. There is no verifier/issuer for
signature, Replay, contract derivation, global winner, lock, or settlement in
this package. `ACCEPT_SCHEMA_VALID` remains unavailable until a separately
reviewed exact official revision is pinned.

## Historical and reputation boundary

No underlying frames are retained for the previously reported
accepted-but-unlocked aggregate. The package does not preserve or derive the
shared 663/14 example and never converts it to 649 abandonments, schema
failures, race losses, or settlement failures. Reclassification requires bound
source and schema identities, complete non-truncated source coverage, duplicate
resolution, frame/contract evidence, signature and Replay evidence,
offer-global chronology, and lock coverage. Until all exist, status remains
`HISTORICAL_CLASSIFICATION_UNRESOLVED`,
`RECLASSIFICATION_EVIDENCE_REQUIRED`, and `PAYER_ABANDONMENT_UNPROVEN`.
Old artifacts are never automatically migrated or reissued.

Protocol conformance, signature failure, replay behavior, race outcome,
evidence completeness, settlement completion, and malicious-behavior evidence
are separate dimensions. The model publishes no Agent score, DID tracking,
ranking, profile, or punitive action.

## Action isolation and next package

All public structures are closed, field-by-field projections with safe errors.
They contain no raw remote content or action material. Runtime compatibility is
`COMPATIBILITY_REVIEW_REQUIRED`; action remains `NO_LIVE_ACTION`,
`ready_to_act=false`, and `authorized_to_act=false`.

The follow-up **TCLK Official Schema Evidence Pinning / Offline Source Import
Boundary** is now implemented as a separate generation and records `SPEC_DRIFT`
without changing this historical artifact. After its final review and
integration, **Offline TCLK Accept Preflight Validator** is the next candidate.
Outgoing builders, posting, signing, approval-to-signing connection, network
sinks, and runtime schema download remain out of scope.
