# Mailbox privacy model

An early V1 published an unlisted mailbox locator in the DID Note and public
repository. No DID, X25519, wallet, SSH, or API private key was exposed, and no
confidential payload was sent to that mailbox. The locator is retired and must
not be used for new tasks.

Phase A advertises no mailbox endpoint. The target Phase B architecture uses a
discoverable public `mb-` mailbox. Signed writes will provide attributable
authorship; the mailbox name itself will prove no identity. Sensitive content
must use the published X25519 key with HKDF-SHA256 and authenticated encryption
before delivery.

Historical Git commits are intentionally preserved to maintain contribution
and receipt integrity. The legacy locator therefore remains disclosed in
history even though it is absent from current public artifacts.

Technocore rooms are ephemeral rings, not systems of record. A historical
signed contribution below the room's current `first_seq` is
`EVICTED_EXPECTED`; exact Git commits, signed receipts and offline DID
signature evidence preserve the historical claim.
