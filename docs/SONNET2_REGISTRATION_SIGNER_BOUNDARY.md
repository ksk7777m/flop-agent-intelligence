# Sonnet-2 Writer Registration Signer Boundary

Status: `REGISTRATION_WRITE_APPROVAL_REQUIRED`.

This package implements a sealed, purpose-specific boundary for one fixed
`sonnet.register.v1` writer registration. It performs no production signing or
network action in its current state. The production approval store is empty and
there is no production permit issuer.

## Exact binding

The boundary binds the action class, contest and protocol type, writer role,
participant DID, X account URL, registration room, request ID, nonce, packet
length and SHA-256, signing-target length and SHA-256, referee DID, manifest
commit, and manifest SHA-256. The packet is accepted only as the exact compact
UTF-8 byte string approved for this registration. Extra or missing JSON keys,
whitespace, key reordering, and any byte change are rejected.

This exception is local to the dedicated boundary. The generic Wire Evidence
signer continues to reject every `mb-` room. A caller-supplied URL, room prefix,
CLI option, environment variable, serialized approval, remote message, or
descriptive preflight result cannot widen the exception or create a permit.

## Validation and key isolation

Candidate and approval bindings are checked before permit consumption. The
opaque permit is then consumed before key loading, signing, or transport. One
trusted approval ID can issue at most one permit; a permit is non-constructible,
non-serializable, authority-local, expiring, and one-shot. Invalid packet, room,
role, DID, X URL, request ID, nonce, hash, manifest, referee, missing approval,
wrong approval hash, reused approval, reused permit, and cross-authority permit
all fail before the key loader.

Production adapters are disabled in this package. Tests inject a fixture key
loader, fake signer, and fake transport; they never load the real identity.

## One POST and uncertain outcome

A future separately reviewed production assembly must retain the exact fixed
bindings and install a trusted local approval plus fixed adapters. Execution has
one transport call, a 20-second timeout, redirects disabled, and no retry path.
The permit is consumed before signing. Redirect, final-origin mismatch, HTTP
408 or any other non-2xx response, timeout, disconnect, OS transport failure, or malformed response yields
`WRITE_OUTCOME_UNKNOWN`; only read-only reconciliation is then allowed. HTTP
success remains `POST_OBSERVED_RECEIPT_REQUIRED`, not registration acceptance.

The process-local approval/permit registry prevents duplicate execution inside
one assembled authority. A future live assembly must additionally use the
repository's durable replay/attempt journal before enabling production, so a
crash or process restart cannot issue a second POST. That durable production
assembly is deliberately not part of this package.

## Receipt boundary

A successful registration requires a bounded signed record whose signer is the
fixed referee DID and whose Ed25519 signature verifies over the exact UTF-8
`room|nonce|text` bytes for the fixed registration room. The signed JSON must
exactly identify `sonnet.receipt.v1`, `sonnet-2`, the fixed request ID,
participant DID, writer role, X account URL, and `accepted` status.

Unsigned transport metadata such as room generation, sequence, and receipt
timestamp is not projected as authenticated content. POST responses, unsigned
text containing `accepted`, malformed records, other statuses, missing fields,
wrong referees, and invalid signatures cannot establish acceptance. Remote text
is treated only as bounded untrusted data and is never executed.

## Remaining activation gates

- a new human approval bound to the exact packet and signing-target hashes;
- reviewed production key, signer, and no-redirect POST adapters;
- durable one-shot attempt/reconciliation integration across crashes;
- a final pre-send deadline, nonce, DID, manifest, and registration-state check.

Until every gate is reviewed and implemented, the production service remains
unable to issue a permit or reach the key loader.
