# TCLK Transcript Completeness / Unsigned Venue Metadata Boundary

`assess_tclk_transcript(transcript_bytes: bytes)` is a deterministic, offline
pure validator for bounded LF-terminated JSON Lines. It accepts no URL, room,
cursor, reader, clock, trust flag, expected count, completeness claim, final
state, winner, callback, or sink. It reads only the fixed vendored TCLK schema
and specification evidence and has no network, persistence, resync, signing,
posting, wallet, settlement, or scheduler capability.

## Existing-package classification

- Wire Evidence signature/completeness separation: `ALREADY_COVERED`
- Evidence Transport opaque completeness proof and retention/gap model: `ALREADY_COVERED`
- Replay Journal durable side-effect state: `ALREADY_COVERED`, but transcript replay conclusion is `BLOCKED_BY_ACQUISITION_EVIDENCE`
- Technocore Transport truncation/HTTP/freshness separation: `ALREADY_COVERED`
- TCLK preflight and official schema validation: `ALREADY_COVERED`
- Transcript-wide signed/unsigned projection and boundary model: previously `MISSING`, implemented here
- Venue metadata authenticity: `BLOCKED_BY_VENUE_ATTESTATION`
- Authenticated cursor/checkpoint and resync: `BLOCKED_BY_ACQUISITION_EVIDENCE`
- Winner and settlement verification: `NOT_APPLICABLE` to this descriptive package

The pinned TCLK specification binds the Ed25519 transport signature to exactly
`<room>|<nonce>|<text>`. `seq` and `ts` are explicitly venue metadata and are
not sender-signed. This package also treats optional export `generation` as
unsigned local venue/export metadata. Changing any unsigned metadata can leave
signature verification unchanged, but changes the exact transcript hash,
per-record metadata hash, and artifact identity.

## Dimensions and completeness

The closed result independently represents transport completion, parsing,
bounds, official frame schema, signature, signed-payload binding, duplicates,
Replay, metadata presence/type/order/authenticity, lower and upper boundaries,
truncation, source set, completeness, final state, winner, settlement, and
currentness. Each dimension uses epistemic states rather than booleans.

The production API cannot issue `COMPLETE`. A future sealed acquisition
authority would need source identity, acquisition policy, completed request,
bounded response, explicit truncation and pagination evidence, expected source
set, lower/upper boundaries, duplicate resolution, generation, authenticated
cursor/checkpoint, transport evidence, and observation/currentness evidence.
HTTP success, counts, contiguous internal seq values, a final-page claim, or all
valid signatures cannot substitute for those proofs.

Internal `100,101,102` continuity says only that no internal gap was observed.
The lower boundary remains `LOWER_BOUNDARY_UNKNOWN`, the upper boundary remains
`UPPER_BOUNDARY_UNKNOWN`, and prefix/suffix truncation remain possible. A
detected middle gap, duplicate, regression, timestamp regression, or mixed
generation makes completeness `INCOMPLETE`; otherwise it remains `UNKNOWN`.

## Format, seq, ts, and privacy

The local resource policy caps the transcript at 262144 bytes, records at 256,
and each record at 8192 bytes. UTF-8 is strict; BOM, CRLF, empty lines,
non-terminated final records, duplicate keys, float/exponent/NaN/Infinity,
negative zero, unsafe integers, excessive nesting/members/arrays/strings, and
unknown record fields fail closed. A missing terminal LF is explicit truncation.
Depth, member, array, node, and decoded-string checks occur after the standard
strict JSON decode; the 8192-byte per-record and 262144-byte transcript gates
bound that work before parsing.

`seq` is an exact non-negative JSON integer within the safe integer range;
booleans are rejected. It supports only internal venue-observed continuity,
gap, duplicate, and regression indications. `ts` is a strict UTC RFC3339 string
with second or bounded fractional precision and year 1970–9999. Ordering and
equality are evaluated without a wall clock. Future/currentness comparison is
`CURRENTNESS_NOT_EVALUATED` and `REFERENCE_TIME_NOT_PROVIDED`.
These representations are explicitly the local export profile
`LOCAL_EXPORT_PROFILE_SEQ_INTEGER_RFC3339_UTC_V1`; they do not make unsigned
metadata an official signed protocol field or an authenticated venue claim.

The public artifact is reconstructed field by field. It exposes bounded counts,
fixed states, and hashes of exact signed payloads and minimized metadata. It
never exposes transcript/frame text, signatures, DIDs, nonce values, rooms,
statements, contracts, raw seq/ts, arbitrary metadata, URLs, headers, error
bodies, local paths, or exception details.

Valid signatures do not establish Replay validity, transcript completeness,
venue authenticity, final state, the offer-global winner, or settlement. These
remain `REPLAY_EVIDENCE_REQUIRED`, `FINAL_STATE_DERIVATION_BLOCKED`,
`WINNER_UNRESOLVED`, and `SETTLEMENT_UNVERIFIED`. Readiness, authorization, and
live action are always false.

Next package candidate: **Offer-global Winner Verification / Accept Race Classification**, fixture/offline only while completeness and venue ordering evidence are absent.

Backlog: Cursor Integrity Gate; authenticated `{generation,last_delivered_seq}`
checkpoint; authenticated acquisition evidence; manual resync ceremony.
