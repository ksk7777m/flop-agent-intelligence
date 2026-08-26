# FLOP Ufuk Flow Gap Audit

Audit date: 2026-08-26. No live write was performed.

## Finding

The existing agent already satisfies the currently observable high-value early-participation shape: one stable Ed25519 DID, successful signed activity, and an original useful Technocore contribution. Flop Labs has publicly asked watched agents to create a unique DID and do something useful; Arthur Hayes has said future specific tasks will require a unique DID and reward completion. Neither statement establishes DID notes, contribution KV notes, mailboxes, private rooms, or X posts as eligibility requirements.

## Status matrix

| Activity | Current | Official status | Ufuk Tool | Gap | Action |
|---|---|---|---|---|---|
| DID generation | Done | OFFICIAL REQUIRED for future DID-gated tasks | Yes | None | Keep existing DID |
| DID note | Not written | OFFICIAL RECOMMENDED Technocore identity convention; not confirmed for FLOP eligibility | Yes, legacy path | Optional discoverability only | Dry-run plan |
| Signed message | Done | OFFICIAL RECOMMENDED and cryptographically meaningful | Yes | None | No duplicate |
| Useful contribution | Done | OFFICIAL RECOMMENDED by Flop Labs/Arthur | Yes | None | Maintain quality |
| Contribution note | Not written | COMMUNITY PRACTICE | Yes | Unsigned pointer only | Prepare only |
| Mailbox | Not created | OFFICIAL Technocore feature, UNKNOWN for FLOP | Yes | No current receiving use case | Do not create yet |
| Public proof | Local log + signed permalinks | Recommended evidence practice | Yes | Evidence fields can be clearer | Implement locally |
| X sharing | No | UNKNOWN as a requirement; community distribution practice | Yes | No eligibility proof | Draft only if requested |
| Testnet/faucet | Not available | Future official DID-gated task per Arthur; details unavailable | No settled implementation | API absent | Wait |

## Note semantics

The current Technocore DID directory convention uses the first 16 lowercase hex characters of SHA-256(DID), split into `/kv/did-<first2>/<remaining14>`. It is an ordinary world-writable note: unsigned, mutable, durable only relative to rooms, and not proof of key control. Readers verify ownership continuity using signed messages. Ufuk currently generates the legacy `/kv/did/<fingerprint>` form and places profile, mailbox, contribution, X, and guide pointers in it.

Ufuk's `/kv/contrib/<fingerprint>` record is a tool-defined `technocore-contribution-v1` string. It is also an ordinary unsigned, overwriteable note. The official Technocore manual defines generic KV notes but does not define a contribution registry schema. The signed contribution message already provides stronger authorship evidence, while the KV note provides only a discoverable pointer.

## Mailbox and X

`mb-` rooms are an official transport feature: unsigned writes are rejected and `mb-p-` combines attributable messages with an unlisted name. A mailbox does not itself prove identity, has no recipient filtering, and has no documented FLOP scoring role. Creating one without a polling/task-delivery use case adds activity but not value.

Ufuk creates X intent text and proof exports as convenience features. Flop Labs asks agents to spread useful Technocore work, but no official source reviewed specifies that X posting, a DID in an X bio/post, or an X proof URL is a formal eligibility condition.

## Proof taxonomy

| proof_type | source | verification method | persistence |
|---|---|---|---|
| `did_key` | local public DID | Decode multicodec and derive public key | Stable while key is retained |
| `signed_message` | Technocore room record | Verify Ed25519 over swept `room|nonce|text` | Ephemeral ring; keep local receipt |
| `did_note` | Technocore KV | Resolve pointer, then corroborate with signed activity | Mutable/world-writable; idle expiry applies |
| `contribution_note` | Community KV convention | Treat as pointer only; corroborate DID and artifact independently | Mutable/world-writable; idle expiry applies |
| `mailbox_message` | `mb-`/`mb-p-` room | Verify signed sender DID | Ephemeral room |
| `external_artifact` | Git commit/repository | Verify host, commit and content independently | Host-dependent |
| `x_post` | X | Account/post availability only; not DID key control unless separately signed | Platform-dependent |

## Decision

- Implement now: explicit local proof schema and dry-run plans using the current sharded DID-note convention.
- Prepare only: DID profile and community contribution-note plans, both clearly marked unsigned and overwriteable.
- Wait: testnet, faucet, task schema, snapshot, wallet linking, claim and contract details.
- Do not implement: duplicate signed posts, empty mailbox activity, private-room demos, farming loops, or automatic X sharing.

