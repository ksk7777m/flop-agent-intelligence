# Local Replay Ledger and Side-effect Journal

This offline package makes local duplicate suppression durable and explicit:

`OBSERVED != VALIDATED != EFFECT_RESERVED != EFFECT_ATTEMPTED != EFFECT_CONFIRMED`

The canonical replay identity binds the actor DID, action class, room/context,
exact nonce lexeme, signed-payload hash, canonical signing-bytes hash, target,
schema version, and captured policy version. A separate nonce-scope constraint
detects reuse of the same actor/context/nonce with different signed material.
Every field is revalidated at the sealed service boundary before canonical
material or a replay ID is derived, including objects forged around the frozen
dataclass constructor. Nonces are exact canonical decimal strings and hashes
are exact lowercase SHA-256 hex.

SQLite `BEGIN IMMEDIATE` transactions and storage-level uniqueness guarantee
that concurrent workers cannot both reserve one effect. An attempt left in
`EFFECT_ATTEMPTED` is recovered as `EFFECT_OUTCOME_UNKNOWN`; it is never treated
as failure and never automatically retried. Confirmation and reconciliation
store hashes of reviewed evidence, not raw payloads or secrets.

Production captures its private root under `secrets`, creates directories and
files as `0700` and `0600`, opens path components relative to trusted directory
descriptors with no-follow semantics, and exposes no path or dependency
injection. The verified directory and database descriptors remain open through
SQLite open, and device/inode identity is checked again before schema or ledger
mutation. Store metadata binds schema, policy, store kind, descriptive store
identity, and a digest derived from a process-local family secret plus the
verified inode. The secret is neither persisted nor caller-settable, so visible
metadata, the same database path, or a copied database cannot reconstruct the
authority of a legitimate service family. Test provisioning accepts only a new,
empty non-production store; reopening is performed only by workers issued from
the original family.
The production facade retains only observation, lookup, and canonical replay-ID
operations; it carries no authority issuer or privileged effect mutator.

Nonce conflicts are recorded separately from the authoritative action state.
A conflict detected after confirmation therefore leaves the confirmed result
unchanged while recording the conflicting replay ID and canonical-material hash;
the conflicting identity is never made executable.

The public projection is `DESCRIPTIVE_ONLY` and cannot be loaded back as
authority. Validation, action authorization, reservation, confirmation, and
reconciliation use non-serializable service-local opaque tokens. Confirmation
and reconciliation evidence binds the replay ID, effect identity, reservation,
attempt, effect class, target, evidence kind and hash, related evidence
identity, verifier revision, and policy version. There is deliberately no live
effect adapter.

Effect retry policy is fail-closed. Confirmed/rejected operations are
`DO_NOT_RETRY`; attempted or unknown outcomes require reconciliation (or human
review for effect classes where automated read-back is not sufficient). A
proved-safe failure may be reserved again, while independent action authority
is still required. Possession of a reservation alone cannot assert safe
failure: reserved recovery requires a sealed local no-invocation proof, and an
attempted or unknown result requires sealed read-back/reconciliation evidence.
