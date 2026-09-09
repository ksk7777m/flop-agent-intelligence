# TCLK Offer-wide Completeness Issuance

This offline-only validator is the first boundary allowed to issue
`OFFER_WIDE_COMPLETENESS_VERIFIED`. It consumes exact offer/transcript/source/
context/attestation/checkpoint/replay bytes. Production uses the fixed empty
source-authority manifest, so issuance remains unreachable until a separately
reviewed public authority key is pinned.

The signed acquisition context binds the target offer hash, source identity,
generation, `OFFER_WIDE` scope, first and high-water sequence, lower and upper
boundary markers, truncation, dropped count, bounded-page status, retention
loss, and artifact conflict status. Caller source labels never substitute for a
verified attestation. `MCP_PAGE`, `PROVIDED_EXPORT`, unknown, partial, truncated,
bounded, gapped, malformed, generation-mismatched, or conflicting evidence
fails closed. Source identities are accepted only when present in the pinned
authority policy; no deployment room or board identifier is guessed here.

Issuance requires a verified source attestation, exact offer binding, matching
transcript/context/checkpoint generation, a valid cursor, explicit sealed lower
and upper boundaries, a consecutive exact sequence through the sealed
high-water mark, no truncation or dropped records, valid signed transcript
records, no attested retention loss, and no attested artifact conflict.

Completeness describes only the evidence coverage of this attested offer-wide
scope. Unsigned sequence/timestamp metadata remains observational and is not
winner authority. The result always keeps global winner unresolved, race loss
unissued, lock and settlement unverified, and every action flag false.
