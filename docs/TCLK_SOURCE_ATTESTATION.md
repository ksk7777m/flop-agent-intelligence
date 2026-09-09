# TCLK Sealed Source Attestation

This package verifies, entirely offline, that a locally pinned acquisition
authority signed a canonical attestation binding exact evidence bytes, exact
source-descriptor bytes, and exact acquisition-context bytes. The production
module exposes verification only. It has no collector, network client, signing
key, signing API, wallet, or settlement path.

The artifact is a closed canonical-JSON object. Its Ed25519 signature covers
the ASCII domain separator `TCLK_SOURCE_ATTESTATION\0V1|` and every artifact
field except `signature`. SHA-256 digests bind exact bytes; inputs are never
parsed and re-encoded before hashing. Descriptor and context documents are
themselves canonical closed JSON and must agree on source identity, source
type, generation, acquisition time, and mode. The signed context also binds the
target offer hash, offer-wide or partial scope, first/high-water sequence
boundaries, explicit lower/upper markers, truncation, dropped count,
bounded-page, retention-loss, and artifact-conflict states. These remain
authority assertions consumed only by a separate completeness verifier.

Authorities resolve only through `data/tclk_source_authorities.json`, which
contains public verification material only. The initial reviewed manifest is
intentionally empty: no production authority is trusted until its public key,
version, policy, allowed source types, and allowed source identities receive a
separate review. Authority
IDs and key IDs are globally unique within the manifest; rollback or any byte
replacement is rejected by the pinned manifest hash. Tests use
only an in-memory ephemeral fixture authority and never write its private key.

Acquisition precedes issuance and issuance cannot exceed expiry; all three are
bounded integers. Verification order is schema, canonical grammar, authority lookup, policy,
signature, exact-byte digests, generation/context, freshness/replay, then
issuance. Replay identity is a minimized hash of authority identity/version and
the exact nonce. A matching entry in the supplied offline replay ledger is
rejected. The caller-provided ledger is not a durable-ledger proof and causes
no side effect.

`SOURCE_TYPE != SOURCE_AUTHORITY`.
`SOURCE_ATTESTATION_VERIFIED != SOURCE_COMPLETENESS_VERIFIED`.
`SOURCE_COMPLETENESS_VERIFIED != OFFER_GLOBAL_WINNER_VERIFIED`.
Winner does not imply lock, and lock does not imply settlement.

Consequently the result always retains `COMPLETENESS_NOT_ESTABLISHED`,
`GLOBAL_WINNER_UNRESOLVED`, unissued race loss, unverified lock/settlement, and
all action booleans false. It proves provenance of one acquired artifact—not
history completeness, content truth, ordering, retention, a winner, or an
external effect.
