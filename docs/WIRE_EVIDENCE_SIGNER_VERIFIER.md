# Wire Evidence, Signer, and Verifier Hardening V1

Status: offline defensive implementation. It does not activate a protocol,
perform a Technocore request, access a production secret, connect a wallet, or
assert live compatibility.

## Evidence is layered

The implementation keeps five independent evidence layers: cryptographic,
venue, transcript, agreement, and settlement. Finality is an explicit outcome
of settlement verification. A valid Ed25519 content signature establishes only
the signed bytes and key. It does not sign venue sequence, timestamp, or
generation metadata; prove that an export is complete; establish bilateral
agreement; or prove economic settlement.

Venue timestamps and terminal transcript states therefore remain
`FINALITY_UNVERIFIED` without independent, rail-specific cryptographic
verification. PaperRail can be protocol-valid coordination evidence, but never
proof of economic value.

## Lossless wire inputs

Nonce values are accepted only as canonical, positive decimal strings in the
reviewed 1–19 digit range. They are never accepted as Python numbers or
converted through JavaScript `Number`. This preserves exact values across the
2^53 boundary and through the reviewed maximum.

The tclk-alpha adapter gates raw bytes before structured decoding: 4096-byte
and character limits, strict UTF-8, exactly one line, and printable ASCII.
Unix millisecond fields must be explicit integers from zero through the
reviewed maximum; booleans, floats, NaN, infinity, negatives, and overflow
fail closed as `TIME_INVALID`.

## Local signing context

Signing validation is ordered: reviewed public room, nonce lexeme, swept text
frame, locally reconstructed canonical bytes, optional exact challenge
comparison, then existing capability validation and signing. A remote peer's
canonical string is never authoritative.

The consumed signing capability binds the exact room, nonce lexeme,
text hash, canonical-byte hash, action class, target, Git revision, and config
version. Those fields are recomputed before identity loading. A wrong room,
nonce, text, canonical challenge, revision, or policy version is rejected before
key access or signing.

## Exports and provenance

Raw export bytes remain inside a sealed verifier service. Public
`ExportObservation` values contain only source identity, acquisition time,
length, snapshot SHA-256, verifier revision, generation, and a minimized
structural assessment. Third-party exports always remain descriptive inputs.
A structurally clean sequence is not complete. A repository-controlled,
closure-sealed acquisition policy binds source, generation, snapshot hash and
length, record count, first and last sequence values, acquisition time bounds,
truncation state, verifier revision, and policy version into an opaque
`TrustedAcquisitionEvidence` capability. Only that capability—not an equal or
reconstructed `ExportObservation`—can be consumed to issue an opaque
`VerifiedTranscriptCompleteness` object. Completeness has no caller-supplied
bounds or truncation override.

The verifier detects malformed records, invalid time, duplicate or reversed
sequence values, gaps, inconsistent generations, truncation indicators, and
acquisition-bound mismatches.

## Agreements, rails, and read-back

tclk-alpha is classified as coordination only. The adapter verifies both
Ed25519 signatures, recomputes offer and agreement identifiers, and separately
checks the exact offer reference, counterparties, protocol, and reviewed lock
semantics. The authority advances agreement state only through the enforced
`PROPOSED → OFFER_VERIFIED → ACCEPTANCE_VERIFIED → AGREEMENT_VERIFIED`
sequence. Signatures cannot override a failure in any other condition.

Rail observations preserve both the raw alias and locally canonicalized rail.
Transcript claims, rail observation, rail cryptographic verification, and
independent finality remain distinct. Evidence read-back advances only through:

```text
WRITE_ACCEPTED → READ_BACK_OBSERVED → DECODE_VALID → SIGNATURE_VALID
→ STATE_REPLAY_VALID → EVIDENCE_CONFIRMED
```

Skipping a stage fails closed. `ReadBackStage.EVIDENCE_CONFIRMED` remains a
descriptive enum value; only the configured sequential verifier can issue
`VerifiedReadBackEvidence`.

## Verified authority

Completeness, agreement, rail finality, read-back, and combined bundle claims
are process-local opaque objects. Their public constructors reject, and they
cannot be copied or serialized. Production uses one service constructed at
module initialization from repository-controlled, fail-closed policy; no
caller-configurable production factory remains. Mutable issuance registries
live only in captured closures, never service attributes. Each token is
meaningful only by object identity in the closure of the service that issued
it. Exact cryptographic inputs, IDs, provenance, verifier revision, policy
version, and verification time are bound in private records. Reconstructing
visible fields, booleans, enum values, JSON, or a token from another authority
does not grant authority. This boundary does not claim protection from a
debugger, unrestricted process-memory access, or deliberate closure-cell
introspection or mutation.

The production authority revision is a descriptive digest of the authority
schema and sealed fail-closed root policy. It is not caller-settable and is not
a trust primitive. It deliberately is not presented as a self-referential Git
commit hash.

Public `EvidenceBundle` values are descriptive and cannot accept verified
completeness, agreement, rail, or finality statuses. Only the same sealed
service that issued a bundle can project its verified statuses. Production
projection rejects test/caller-authority bundles, and `FINALITY_VERIFIED`
requires that service's own `VerifiedRailFinality` bound to the bundle's
verified agreement. PaperRail can never produce that token.

## Secret-safe failures and compatibility

Secret-bearing fields such as secrets, preimages, witnesses, `presig.s`,
payment keys, private keys, seeds, and mnemonics are rejected. Errors retain
only field class, type, length, and a fixed reason. Decoder exceptions are
replaced outside the upstream handler without cause/context chaining, so raw
JSON text and invalid UTF-8 bytes are not retained in exception objects,
tracebacks, or normal `exc_info` logging.

The compatibility manifest distinguishes `DOCUMENTED_CAPABILITY` from
`RUNTIME_OBSERVED_CAPABILITY`. Runtime capabilities remain
`NOT_OBSERVED_OFFLINE`, and overall compatibility remains review-required.
Typed readiness reports defensive implementation state and
`DO_NOT_ACTIVATE`; it does not claim live verification.
