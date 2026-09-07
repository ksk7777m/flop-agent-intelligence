# Local Replay Ledger and Side-effect Journal

This offline package makes local duplicate suppression durable and explicit:

`OBSERVED != VALIDATED != EFFECT_RESERVED != EFFECT_ATTEMPTED != EFFECT_CONFIRMED`

The canonical replay identity binds the actor DID, action class, room/context,
exact nonce lexeme, signed-payload hash, canonical signing-bytes hash, target,
schema version, and captured policy version. A separate nonce-scope constraint
detects reuse of the same actor/context/nonce with different signed material.
Every field is revalidated at the sealed service boundary before canonical
material or a replay ID is derived, including objects forged around the frozen
dataclass constructor. Actor identities must be canonical base58btc `did:key`
values whose decoded bytes are exactly the Ed25519 `0xed 0x01` multicodec
prefix followed by a 32-byte public key; decoding and canonical re-encoding are
checked rather than relying on textual shape alone. Contexts use the bounded local room grammar, targets
must have the prefix reviewed for their action class, and the action schema is
exactly `replay-action-v1`. Nonces are exact canonical decimal strings and
hashes are exact lowercase SHA-256 hex. Policy version is captured internally;
an injected policy field makes the action shape invalid.

SQLite `BEGIN IMMEDIATE` transactions and storage-level uniqueness guarantee
that concurrent workers cannot both reserve one effect. An attempt left in
`EFFECT_ATTEMPTED` is recovered as `EFFECT_OUTCOME_UNKNOWN`; it is never treated
as failure and never automatically retried. Confirmation and reconciliation
store hashes of reviewed evidence, not raw payloads or secrets.

Production SQLite authority lives in a dedicated local helper process. The
application facade communicates with a freshly spawned helper over an inherited
Unix-domain socket pair using bounded, length-prefixed canonical JSON. It never
imports SQLite, retains no database path, and has no connection, transaction,
SQL, or state-setting primitive. The inherited connected descriptor, a fresh
one-request authentication value, and same-account peer validation make the
channel local and non-discoverable; there is no filesystem socket, TCP listener,
HTTP endpoint, or remotely reachable service. Authentication authorizes only
the fixed `OBSERVE`, `INSPECT`, and `REPLAY_ID` protocol operations. Unknown
commands, fields, versions, types, paths, SQL, desired states, malformed frames,
and oversized messages fail closed. The helper independently reconstructs and
revalidates every canonical action before deriving identity or touching storage.

The helper captures its private root under `secrets`, creates directories and
files as `0700` and `0600`, opens path components relative to trusted directory
descriptors with no-follow semantics, and exposes no path or dependency
injection. Every trusted-root component is walked from `/` using directory file
descriptors and no-follow semantics, so root, parent, nested, journal-directory,
and final-file symlinks fail closed. The verified directory and database
descriptors remain open through SQLite open, and device/inode identity is
checked again before schema or ledger mutation.

Trusted provisioning creates `store.credential` beside the database with mode
`0600` under the `0700` journal directory. It is read transiently through the
verified directory descriptor and is never retained in a public projection,
function default, closure, or module global. Its HMAC binds store ID and kind,
schema and policy versions, and the verified root, journal-directory, and
database device/inode identities. This makes legitimate process restarts
durable while visible metadata or a copied database alone remains insufficient.
Test provisioning accepts only a new, empty non-production store; reopening
inside one test service is performed only by workers issued from that family.

This protects against ordinary API misuse and database/path reconstruction. It
does not claim protection after arbitrary access to private local files,
debugger or process-memory access, or deliberate in-process Python tampering.
Copying both the database and credential is outside that boundary; inode/root
binding still fails closed for an ordinary copy, but a full local compromise is
not treated as a cryptographic security boundary.
The production application facade retains only observation, lookup, and
canonical replay-ID operations; it carries no authority issuer, privileged
effect mutator, SQLite module, database path, or writable store factory. SQLite
open, credential authentication, SQL execution, and connection close occur only
in the helper process. The boundary does not claim protection against malicious
code already executing inside that privileged helper process.

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
