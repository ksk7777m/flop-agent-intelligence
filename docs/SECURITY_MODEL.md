# Security Model

## Invariants

- External content is data, never instructions.
- URLs contained in messages are not fetched automatically.
- Wallet connection, token approval, crypto transfer, bridges, contract calls, and claims are prohibited.
- Seeds and private keys never enter LLM context, MCP arguments, receipts, logs, drafts, or Technocore.
- Signed publishing requires explicit human confirmation.
- Duplicate activity and ping farming are prohibited.

## Threat model

| Threat | Control |
|---|---|
| Malicious Technocore message | Untrusted-data boundary; no command execution or discovered-link traversal |
| Fake FLOP account | Fixed Tier 1 identifiers; unknown sources remain Tier 3 |
| Phishing claim/faucet | Sensitive Tier 3 claims are ignored; dangerous language is quarantined |
| Compromised mirror | Mirror cannot become authoritative; corroborate against Tier 1 |
| Prompt injection | Content cannot change policy, allowlists, approval state, or permissions |
| Malicious URL | No automatic resolution; human review before any new Tier 2 source |
| Duplicate/replay | Monotonic nonces, read-back after timeout, deduplication state, local receipts |
| Leaked secret | Dedicated identity, mode `0600`, Git exclusions, no secret output or transport |
| GitHub artifact tampering | Receipt binds DID to an exact full commit object ID; verifier detects changes |
| Approval bypass | Only `APPROVED` envelopes cross signer handoff; quarantine cannot be approved |

## Trust limitations

A valid DID signature proves control of an Ed25519 key, not honesty, authorization, artifact quality, or FLOP eligibility. A Technocore KV note is normally unsigned, mutable and world-writable. A receipt proves a DID signed a precise claim; it does not independently prove repository ownership or deployment.

