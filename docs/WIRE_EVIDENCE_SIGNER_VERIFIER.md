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

The descriptive capability binding includes the exact room, nonce lexeme,
text hash, canonical-byte hash, action class, target, Git revision, and config
version. It does not issue capability or broaden the P1 production authority
boundary.

## Exports and provenance

Captured export fixtures retain a source kind, configured source identifier,
acquisition time, snapshot SHA-256, verifier revision, generation, and bounded
raw bytes. Public evidence excludes raw bytes. Third-party exports always
remain untrusted inputs. A structurally clean sequence is not complete: only
an independently verified, exact claim for a configured reviewed export may
produce `TRANSCRIPT_COMPLETENESS_VERIFIED`.

The verifier detects malformed records, invalid time, duplicate or reversed
sequence values, gaps, inconsistent generations, truncation indicators, and
acquisition-bound mismatches.

## Agreements, rails, and read-back

tclk-alpha is classified as coordination only. The adapter verifies both
Ed25519 signatures, recomputes offer and agreement identifiers, and separately
checks the exact offer reference, counterparties, protocol, and reviewed lock
semantics. Signatures cannot override a failure in any other condition.

Rail observations preserve both the raw alias and locally canonicalized rail.
Transcript claims, rail observation, rail cryptographic verification, and
independent finality remain distinct. Evidence read-back advances only through:

```text
WRITE_ACCEPTED → READ_BACK_OBSERVED → DECODE_VALID → SIGNATURE_VALID
→ STATE_REPLAY_VALID → EVIDENCE_CONFIRMED
```

Skipping a stage fails closed.

## Secret-safe failures and compatibility

Secret-bearing fields such as secrets, preimages, witnesses, `presig.s`,
payment keys, private keys, seeds, and mnemonics are rejected. Errors retain
only field class, type, length, and a fixed reason; rejected values are not
included in errors or public evidence.

The compatibility manifest distinguishes `DOCUMENTED_CAPABILITY` from
`RUNTIME_OBSERVED_CAPABILITY`. Runtime capabilities remain
`NOT_OBSERVED_OFFLINE`, and overall compatibility remains review-required.
Typed readiness reports defensive implementation state and
`DO_NOT_ACTIVATE`; it does not claim live verification.
