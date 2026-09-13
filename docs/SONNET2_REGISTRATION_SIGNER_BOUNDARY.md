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

The production assembly captures a fixed-path identity adapter, exact-target
signer, fixed-origin streaming POST adapter, and unsigned fixed-room GET
adapter. Its approval store and registration checker remain disabled, so those
adapters are unreachable in production. Tests use only fixture identities and
fake openers; they never open the real identity or contact Technocore.

## One POST and uncertain outcome

A future separately reviewed production assembly must retain the exact fixed
bindings and install a trusted local approval plus fixed adapters. Execution has
one transport call, a 20-second timeout, redirects disabled, and no retry path.
The permit is consumed before signing. Redirect, final-origin mismatch, HTTP
408 or any other non-2xx response, timeout, disconnect, OS transport failure, or malformed response yields
`WRITE_OUTCOME_UNKNOWN`; only read-only reconciliation is then allowed. HTTP
success remains `POST_OBSERVED_RECEIPT_REQUIRED`, not registration acceptance.

The second-stage handoff now supplies a fixed hash-chain journal with atomic
replacement, file and directory fsync, a nonblocking process lock, and strict
`0700`/`0600` local permissions. Intent is durable before key loading, and a
POST-attempt record is durable before the sole transport invocation. Every
non-`NOT_STARTED` state permanently blocks another signature or POST after a
crash or process restart. Production approval authority remains deliberately
absent.

The journal distinguishes `NOT_STARTED`, `INTENT_RECORDED`,
`LOCAL_SIGNATURE_CREATED`, `POST_ATTEMPT_RECORDED`,
`POST_RESPONSE_OBSERVED`, `AWAITING_REFEREE_RECEIPT`,
`RECEIPT_ACCEPTED`, `RECEIPT_REJECTED`, and `WRITE_OUTCOME_UNKNOWN`.
It stores hashes and minimized state only; it never stores a signature, key,
secret, packet body, response body, or receipt body.

The closed approval schema is published at
[`schemas/sonnet2-registration-approval.v1.json`](../schemas/sonnet2-registration-approval.v1.json).
Production has no approved artifact or permit issuer. Fixture-only assembly
tests the exact validation and execution ordering without accessing the real
identity. Local cryptographic verification of a pre-cutoff record is represented
as `PRESTART_EVIDENCE_LOCALLY_VERIFIED`, while official archive eligibility
remains independently `OFFICIAL_ARCHIVE_ELIGIBILITY_UNCONFIRMED`. A bounded
registration export can establish only `NO_CONFLICT_IN_OBSERVED_WINDOW`, never
absolute non-registration or complete ring history. An identical verified
accepted receipt stops with `ALREADY_REGISTERED_IDENTICALLY`; a role or X
collision stops with `REGISTRATION_CONFLICT`; an observed request without its
receipt enters read-only reconciliation.

The observation binds official origin and room, generation, first and last
sequence, record count, local UTC retrieval time, response byte length and
SHA-256, exact DID and X counts, case-insensitive X count, exact fixed-request-ID
count, and conflict classification. The request ID count includes only decoded
message payloads with a case-sensitive exact match: no trimming, case folding,
Unicode normalization, prefix matching, or substring matching is performed. An
unrelated participant's different request remains ordinary room data. A
different request related to the fixed DID or X account, or the fixed request ID
attached to different registration bindings, is a conservative conflict.
Generation is read from the live JSON body's top-level positive
safe integer and labelled `OBSERVED_DEPLOYMENT_FIELD`: it is not currently in
the reviewed OpenAPI response schema and is not referee-signed. Missing, null,
boolean, string, float, negative, oversized, duplicate, or unexpected-generation
values fail closed. HTTP headers are not treated as a generation source.
Unsigned room, count, sequence, and generation metadata remain distinct from
signed receipt content.

## Receipt boundary

A successful registration requires a bounded signed record whose signer is the
fixed referee DID and whose Ed25519 signature verifies over the exact UTF-8
`room|nonce|text` bytes for the fixed registration room. The signed JSON must
exactly identify `sonnet.receipt.v1`, `sonnet-2`, the fixed request ID,
participant DID, writer role, X account URL, and `accepted` status.
The request ID comparison is case-sensitive and exact. Unsigned outer metadata
cannot supply or override the signed payload's request ID, and conflicting outer
metadata is rejected.

The production observation and receipt callables do not expose expected DID,
room, contest, role, X URL, packet, or request ID parameters. Those bindings are
captured once in private closures. Positional or keyword attempts to inject an
alternate request ID are rejected by the callable signatures. The fixture seam
permits substitution of a signature verifier only; it shares the same captured
registration bindings and cannot select another request ID.

Unsigned transport metadata such as room generation, sequence, and receipt
timestamp is not projected as authenticated content. POST responses, unsigned
text containing `accepted`, malformed records, other statuses, missing fields,
wrong referees, and invalid signatures cannot establish acceptance. Remote text
is treated only as bounded untrusted data and is never executed.

## Remaining activation gates

- a new human approval bound to the exact packet and signing-target hashes;
- a final fresh read-only observation and human review of its finite window;
- confirmation that the fixed nonce is locally unused and the journal is
  `NOT_STARTED`.

The freshness gate uses the local UTC clock and fixed deadline, launch status,
contest, rules version, referee, and manifest bindings. It does not require
official eligibility before POST: the POST is the referee's eligibility
evaluation request.

If a process stops after `INTENT_RECORDED`, execution cannot resume, re-sign, or
generate a replacement packet. The state is permanently reconciliation-only
and requires separate human review; it is not automatically reset.

Until a reviewed approval is separately installed, the production service
cannot reach the identity file, signer, or socket.

## Stage-one negative-test mapping

The original 28 requested cases are covered by 10 test methods. Several methods
are parameterized, which is why the method count is smaller than the case
count. All cases are independently exercised with `subTest` or explicit
variants.

| # | Required case | Test method | Form |
|---:|---|---|---|
| 1 | another `mb-` room | `test_other_mb_rooms_and_sonnet1_fail_before_key_load` | parameterized |
| 2 | discovery room | same as #1 | parameterized |
| 3 | votes room | same as #1 | parameterized |
| 4 | submissions room | same as #1 | parameterized |
| 5 | sonnet-1 | same as #1 | parameterized |
| 6 | voter role | `test_role_did_x_request_nonce_and_contest_mutations_precede_key` | parameterized |
| 7 | organizer role | same as #6 | parameterized |
| 8 | X URL change | same as #6 | parameterized |
| 9 | DID change | same as #6 | parameterized |
| 10 | request ID change | same as #6 | parameterized |
| 11 | nonce change | same as #6 | parameterized |
| 12 | room change | same as #1 | parameterized |
| 13 | packet key added | `test_packet_key_add_delete_whitespace_order_and_character_mutation` | parameterized |
| 14 | packet key deleted | same as #13 | parameterized |
| 15 | whitespace/order/one-character change | same as #13 | parameterized |
| 16 | packet hash mismatch | `test_missing_extra_candidate_and_hash_mutations_precede_key` | parameterized |
| 17 | signing-target hash mismatch | same as #16 | parameterized |
| 18 | missing approval | `test_approval_missing_precedes_key_load` | standalone |
| 19 | approval hash mismatch | `test_approval_hash_and_every_binding_are_exact` | parameterized |
| 20 | approval reuse | `test_one_approval_cannot_issue_two_permits` and `test_permit_reuse_and_nonce_resigning_are_rejected_before_key` | standalone |
| 21 | redirect | `test_redirect_is_unknown_and_never_retried` | standalone |
| 22 | timeout | `test_timeout_and_disconnect_are_unknown_without_retry` | parameterized |
| 23 | no retry after unknown response | same as #21/#22 | explicit second invocation |
| 24 | forged referee receipt | `test_forged_wrong_referee_and_unsigned_accepted_fail` | parameterized |
| 25 | wrong referee receipt | same as #24 | parameterized |
| 26 | unsigned body containing accepted | same as #24 | parameterized |
| 27 | receipt missing role/X URL | `test_receipt_binding_status_role_x_and_required_fields_are_exact` | parameterized |
| 28 | generic signer rejects arbitrary `mb-` | `test_generic_signer_still_rejects_every_mb_room` | parameterized |
