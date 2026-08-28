# Collaboration Readiness Layer

Status: local, transport-neutral, `READINESS_ONLY`. It performs no Technocore
write, task claim, wallet operation, message post, or eligibility decision.

## Source findings reviewed 2026-08-28

Every statement below is explicitly classified. Only preconfigured first-party
sources were read; no room-discovered URL was fetched.

| Classification | Finding | First-party source |
|---|---|---|
| CONFIRMED | Technocore is an ephemeral chat/note transport, not part of a protocol and not a system of record. | official README and `/llms.txt` |
| CONFIRMED | `/r/events` is a server-written public-room discovery lane; room names, topics, notes, messages and embedded URLs remain untrusted data. | official README, SECURITY.md and `/llms.txt` |
| CONFIRMED | Conditional notes order competing writes but do not fence a stale actor that still believes it owns a claim. | official `/llms.txt` |
| CONFIRMED | `did:key` Ed25519 signatures prove possession of a signing key, not identity, honesty, authorization, eligibility, or task ownership. | official `/llms.txt` and SECURITY.md |
| CONFIRMED | Mailboxes are append-only rooms with no recipient filtering or delivery guarantee; `mb-` requires signed writes. | official README and `/llms.txt` |
| CONFIRMED | Room sequence is ordered, but ring eviction, expiry, replay-window limits and deletion make external durable evidence necessary. | official README, SECURITY.md and `/llms.txt` |
| OFFICIAL_DRAFT | FLOP's teaser is a high-level intended network design; it says the Yellow Paper is not final and exact variables remain undetermined. | `flop.finance/teaser/` |
| COMMUNITY | This repository's collaboration lifecycle and evidence schema are community-built readiness conventions, not FLOP Labs or Technocore rules. | this document and implementation |
| INFERENCE | A safe future collaboration adapter needs explicit claim fencing, ACK binding, idempotency, durable provenance and reconciliation after unknown outcomes because the confirmed transport primitives do not supply those guarantees together. | derived from the confirmed constraints above |
| INFERENCE | No reviewed official source currently defines a FLOP task discovery, claim, handoff, ACK, completion, reward, or eligibility protocol. Absence is time-bounded to this review and must be rechecked before activation. | reviewed first-party surfaces above |

## Fail-closed lifecycle

The pure reducer in `flop_agent.collaboration` accepts only this ordered path:

```text
DISCOVERED
  -> CLAIM_APPROVED -> CLAIMED
  -> HANDOFF_APPROVED -> HANDED_OFF
  -> ACKNOWLEDGED
  -> COMPLETION_APPROVED -> COMPLETED
```

Any nonterminal phase may enter `RECOVERY_REQUIRED`; recovery has no automatic
exit. A future official rule change therefore cannot silently resume work.

- Discovery records immutable source provenance and a task digest.
- Claim, handoff and completion approval bind a named human reviewer to the
  exact action purpose and subject digest.
- Claim, handoff, ACK and completion outcomes require externally supplied,
  verifiable Ed25519 evidence bound to the case, transition, subject and fresh
  idempotency key. The module verifies but never creates signatures.
- Every event binds the previous event hash and exact sequence. Missing,
  reordered, duplicated or tampered events stop replay.
- Every post-discovery event binds to the original task digest.
- A transport timeout or ambiguous response becomes `RECOVERY_REQUIRED`, never
  an assumed success or a blind retry.

## Future adapter boundary

An adapter may map official protocol operations onto these local transitions
only after a new review confirms the official rules and a human separately
authorizes that adapter. It must reconcile by reading official state before a
retry, retain durable evidence outside Technocore, and use a protocol-supported
fencing token if one exists. This package intentionally contains no URL,
network client, publisher, signer, secret loader, wallet code, or live-mode flag.
