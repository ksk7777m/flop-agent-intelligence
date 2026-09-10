# Upstream Nonce Compatibility

This package treats upstream nonce acceptance as untrusted compatibility data.
Server acceptance is not canonical validity, and numeric equality is not wire
identity. In particular, Python booleans never alias integer nonces locally.

Decimal nonce boundaries accept only their reviewed grammar: an exact ASCII
string, no coercion, no Unicode digits, exponent, hexadecimal, sign, decimal
point, whitespace, or forbidden leading zero. Boundaries with the established
19-digit profile preserve `9007199254740993` (`2^53 + 1`) exactly. The Replay
Journal retains its wider, bounded 128-digit profile because its existing
identity contract is not the Technocore wire profile.

Parsing a decimal for comparison never changes signing bytes. Technocore and
TCLK transcript verification reconstruct `room|nonce|text` from the validated
nonce lexeme itself; they do not serialize an integer back into the signed
payload. Invalid results expose fixed error codes rather than the nonce, signed
text, DID, signature, room, or transcript.

Compatibility evidence distinguishes `RELEASED`, `MERGED_NOT_RELEASED`,
`UNRELEASED`, `LIVE_CONFIRMED`, and `LIVE_CURRENTNESS_UNREVIEWED`. This offline
review does not promote a reported upstream bool fix or large-nonce change to a
release or live-runtime guarantee. The current upstream lifecycle assessment
therefore remains `LIVE_CURRENTNESS_UNREVIEWED`.

The local rule is intentionally stricter:

`SERVER_ACCEPTED` != `CANONICAL` != `SIGNATURE_SAFE` != `REPLAY_SAFE`.
