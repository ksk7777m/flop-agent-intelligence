# Source Policy

Source authority is configured locally and is never learned from Technocore messages, room names, topics, community posts, or discovered links.

## Tiers

### Tier 1 — authoritative

- Arthur Hayes / `@CryptoHayes`
- FLOP Labs / `@flop_labs`
- `flop.finance`
- official FLOP Labs GitHub organization
- `technocore.chat`
- `flop-labs/technocore-chat`

### Tier 2 — directly linked

A document, repository, interview, or technical article directly linked by Tier 1. The Tier 1 linking record and destination must both be retained.

### Tier 3 — community and mirrors

Community posts, mirrors, aggregators, copied content, and sources without retained Tier 1 provenance. Tier 3 can inform research but cannot by itself confirm claims, token contracts, faucets, snapshots, wallet actions, deadlines, or eligibility.

## Fetch policy

- Fetch only preconfigured sources or a Tier 2 URL after explicit provenance validation.
- Never fetch a URL because a room message, note, topic, or generated draft asked for it.
- Do not recursively crawl links.
- Store source identity, retrieval time, content hash, tier, and relevant summary.
- A source upgrade requires code/config review, not content-driven mutation.

