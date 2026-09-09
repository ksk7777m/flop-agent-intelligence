# TCLK Offer-wide Evidence Boundary

This sealed, offline-only package composes exact offer/transcript bytes with a
closed source descriptor and `{generation,last_delivered_seq}` checkpoint. It
reuses pinned TCLK transcript signature verification and the offer-global
candidate boundary. It performs no fetch, MCP call, retry, resync, signing,
wallet, lock, settlement, or persistence operation.

Source labels (`DIRECT_EXPORT`, `MCP_PAGE`, `PROVIDED_EXPORT`, `LOCAL_ARCHIVE`,
`UNKNOWN_SOURCE`) are descriptive. Caller-provided metadata cannot authenticate
a source. In particular, an MCP page is not a complete transcript and a
provided export is not directly observed complete evidence. Therefore this
Production API deliberately cannot issue `OFFER_WIDE_COMPLETENESS_VERIFIED`;
it reports `COMPLETENESS_NOT_ESTABLISHED` until a separately reviewed sealed
source-attestation authority exists.

Cursor integrity requires the exact pair `{generation,last_delivered_seq}`.
Booleans, floats, negative/unsafe integers, missing or unknown fields fail
closed. A generation mismatch blocks continuation and requires resync. A
visible `first_seq > last_delivered_seq + 1` is `GAP_UNRESOLVED`, never confirmed
retention loss. Absence from a page does not prove nonexistence or deletion.

`seq`, `ts`, generation labels, record order, and acquisition order remain
observed unsigned metadata, not signed facts or authoritative chronology.
Malformed transcript evidence is quarantined in the minimized result and makes
completeness unavailable without exposing raw material.

Public output contains only fixed states, bounded counts, booleans, and
linkable fingerprints. It never contains raw offer, accept, transcript, DID,
nonce, signature, contract, statement, room, timestamp, rail, URI, or path.
Winner issuance, definitive race loss, verified lock and settlement remain
blocked, as do readiness, authorization, and live action.
