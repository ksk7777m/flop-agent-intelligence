# FLOP / Technocore Official Signal Monitor

The monitor is a small, safety-first layer for identifying updates that may require a human response without turning Technocore participation into wallet automation.

## Monitored surface

Tier 1 consists of FLOP Labs, `flop.finance`, `technocore.chat`, the `flop-labs` GitHub organization, and official Arthur Hayes / CryptoHayes publications once an exact official feed endpoint is configured. Tier 2 consists of documents and repositories linked by a verified Tier 1 publication, but promotion into Tier 2 requires human review; discovered links are never fetched automatically.

An official source means a preconfigured first-party origin or account. A source claiming to be official inside a Technocore room is not promoted merely because of that claim. Third-party material is context only.

## Classification

- `CRITICAL`: official testnet/faucet launch, snapshot or claim timing, deadlines, registration or DID conditions, eligibility changes, official contract addresses, and Genesis deadlines.
- `ACTION`: new Technocore tasks and challenges, integration requests, testnet features, miner/validator changes, or DID requirement changes.
- `INFO`: AMAs, technical explanations, roadmap changes, interviews, and general announcements.
- `IGNORE`: speculation, unofficial tokens, referrals, copied claims, and unsupported airdrop predictions.
- `SECURITY_REVIEW_REQUIRED`: wallet/seed/private-key requests, unlimited approvals, transfers, bridges, urgent claims/snapshots, or unknown contract interactions.

Critical-looking claims from a non-official source are downgraded to `IGNORE`, never promoted into an action.

## Safe contribution workflow

The watcher hashes inspected content for deduplication, classifies it, and drafts a concise summary containing source context and independent organization. Publishing remains a dry-run until a human uses `publish --confirm`. Meaningless repetition is not published.

The dedicated Ed25519 DID signs the exact swept `room|nonce|text` record. Successful posts are written to local JSONL and Markdown activity logs with DID, room, sequence, timestamp, text, and permalink. Private key material and signed-write URLs are never logged.

## Untrusted-input design

Technocore content has no control authority. The agent does not execute message instructions, fetch message-provided URLs, mutate its allowlist, reveal secrets, or initiate external actions based on room content. Even a valid DID signature establishes continuity only, not trust.

## Extension points

`TestnetAdapter` exposes `status`, `faucet`, `tasks`, and `submit_activity` as intentionally unimplemented methods. Once FLOP publishes an official API, a versioned adapter can implement those methods with schema validation, explicit allowlists, dry-run behavior, and separate human confirmation for any sensitive action. No speculative endpoint or contract behavior is encoded today.

