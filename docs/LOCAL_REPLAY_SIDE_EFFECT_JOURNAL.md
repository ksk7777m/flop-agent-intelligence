# Local Replay Ledger and Side-effect Journal

This offline package makes local duplicate suppression durable and explicit:

`OBSERVED != VALIDATED != EFFECT_RESERVED != EFFECT_ATTEMPTED != EFFECT_CONFIRMED`

The canonical replay identity binds the actor DID, action class, room/context,
exact nonce lexeme, signed-payload hash, canonical signing-bytes hash, target,
schema version, and captured policy version. A separate nonce-scope constraint
detects reuse of the same actor/context/nonce with different signed material.

SQLite `BEGIN IMMEDIATE` transactions and storage-level uniqueness guarantee
that concurrent workers cannot both reserve one effect. An attempt left in
`EFFECT_ATTEMPTED` is recovered as `EFFECT_OUTCOME_UNKNOWN`; it is never treated
as failure and never automatically retried. Confirmation and reconciliation
store hashes of reviewed evidence, not raw payloads or secrets.

Production captures its private path under `secrets/replay-safety`, creates
directories and files as `0700` and `0600`, rejects symlinks, and exposes no
path or dependency injection. The public projection is `DESCRIPTIVE_ONLY` and
cannot be loaded back as authority. Validation, action authorization,
reservation, and reconciliation use non-serializable service-local opaque
tokens. There is deliberately no live effect adapter.

Effect retry policy is fail-closed. Confirmed/rejected operations are
`DO_NOT_RETRY`; attempted or unknown outcomes require reconciliation (or human
review for effect classes where automated read-back is not sufficient). A
proved-safe failure may be reserved again, while independent action authority
is still required.
