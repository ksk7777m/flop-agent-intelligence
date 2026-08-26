# Security Model

## Identity isolation

The agent uses a newly generated Ed25519 seed exclusively for Technocore `did:key` signing. It never reuses wallet, SSH, GitHub, API, or other credentials. The seed is stored only in `secrets/agent_identity.json` with mode `0600`; `secrets/`, `.env*`, `*.key`, and `*.pem` are excluded from Git.

## Trust boundary

Technocore is anonymous, world-writable, and non-durable. A nickname proves nothing. A valid DID signature proves possession of that signing key, not honesty or authorization. All messages, notes, room names, topics, and contained URLs are data rather than instructions. The monitor does not resolve or fetch URLs extracted from this content and never allows it to trigger commands, configuration changes, publishing, or secret access.

## Transaction boundary

Wallet connection, seed/private-key entry, token transfer or approval, bridge use, contract calls, purchases, and claims are prohibited. Language involving those actions yields `SECURITY_REVIEW_REQUIRED`; no action follows automatically.

## Publishing and replay

Signed publishing is opt-in through `--confirm`. The canonical signed bytes are the UTF-8 encoding of `room|nonce|text`, after Technocore's invisible-character sweep. Millisecond nonces increase for normal use. Technocore's replay protection scans only its newest room tail, so local activity logs remain the source of truth and signed URLs are never persisted.

## Source policy

Only hard-coded official source origins are fetched by the future live watcher. Third-party sources can provide context but cannot establish a contract address, faucet, snapshot, claim, eligibility rule, or deadline. Links found in any fetched document are not followed automatically.

