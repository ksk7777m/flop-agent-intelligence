# Offline TCLK Accept Preflight

`validate_tclk_accept_preflight(offer_bytes: bytes, accept_bytes: bytes)` is a
pure validation boundary for untrusted, bounded UTF-8 JSON candidates. It reads
only the repository-owned snapshot pinned to TCLK commit
`5cc4ab93efbc8999a3a7e1471b639deca25998ea`. It accepts no path, URL, resolver,
schema, expected ID, callback, key, or capability object.

Every call rechecks the retained schema and derivation evidence through the
sealed evidence loader, verifies the schema SHA-256, Git blob identity, byte
length, Draft 2020-12 declaration, local references, canonical rail metadata,
and independent golden contract vector. There is no network fallback.

## Fixed stages and bounds

The result records fourteen ordered stages: pinned integrity, input bounds,
UTF-8, strict JSON, offer schema, accept schema, binding, accept semantics, all
rails, derivation extraction, recomputation, equality, raw canonicality, and
disposition. A failed earlier stage cannot make a later stage pass.

Each input is limited to 4096 bytes. Parsing rejects BOMs, invalid UTF-8,
duplicate keys at every depth, trailing data, non-object roots, floats,
NaN/Infinity, negative zero, lone Unicode surrogates, integers outside the exact JavaScript safe range, more than 16
levels, 64 total members, 32 array members, 1024 characters or 4096 UTF-8 bytes
per string, and more than 192 parsed nodes. Values are never normalized or
coerced. The 4096-byte cap is a local resource-safety policy, not an official
schema requirement. Lexical depth and string-character checks run before JSON
materialization; the byte cap bounds all parser work. The pinned nonce is a
lowercase hexadecimal string of 8–64 characters.

## Conformance, binding, and derivation

The full pinned root schema is evaluated with Draft 2020-12 semantics, including
`oneOf`, same-document `$ref`, `const`, `enum`, patterns, required fields,
nested constraints, and `additionalProperties: false`. Snapshot integrity makes
remote references impossible; no format checker is installed.
The pinned schema contains no conditional or `format` constraints. Its two
`x-tclk-*` rail annotations are explicitly consumed by the separate rail gate;
descriptions and titles remain inert annotations. The package claims complete
validation of this exact pinned schema, not arbitrary future vocabularies.

The validator independently recomputes the offer ID, binds `accept.ref`, rejects
self-acceptance, checks deadline and hash/point semantics, and recomputes the
contract from the complete offer and the accept core. The accept core contains
`from`, `ref`, `statement`, optional `paymentKey`, and `nonce`; `type` and
`contract` are excluded. Comparison uses constant-time digest comparison.
The schema fixes payment keys to lowercase compressed 33-byte hex shape; the
separate semantic stage additionally applies the pinned reference
implementation's secp256k1 on-curve rule. It performs verification only and
does not generate a key or sign.

Canonical derivation is lexicographically sorted, compact JSON with preserved
array order and lowercase UTF-16-code-unit escapes for non-ASCII input. Raw
canonical byte equality is separately required as a local signing-safety gate;
the API does not return canonical or corrected bytes.

All offer rails are checked. Duplicate or non-sorted arrays fail; legacy aliases
and unknown/mixed rail sets are quarantined. This does not verify deployment,
RPC, balance, locking, settlement, or value-bearing maturity.

Deadline checks cover official type/range constraints and the offer-internal
`claimByMs < refundAfterMs` relation only. The API accepts no reference time and
never reads a clock, so current-time expiry is `NOT_EVALUATED`, with
`REFERENCE_TIME_NOT_PROVIDED` and `RUNTIME_CURRENTNESS_OUT_OF_SCOPE` recorded.

## Public and action boundary

The closed result contains only fixed policy identities, input lengths and
SHA-256 evidence identities, stage states, bounded codes, and descriptive
dispositions. It excludes frame bodies, contract IDs, DIDs, nonces, statements,
payment keys, and rail values. Input hashes are not authority or signing targets.

`PREFLIGHT_PASS` does not validate a signature, replay state, winner, lock,
settlement, runtime compatibility, authorization, or permission to post. The
result always has `ready_to_act=false`, `authorized_to_act=false`, and
`live_action_enabled=false`. The API has no signer, writer, poster, wallet,
nonce allocator, corrected-frame output, callback, subprocess, or network path.

Next package candidate: **TCLK Transcript Completeness / Unsigned Venue Metadata Boundary**.
