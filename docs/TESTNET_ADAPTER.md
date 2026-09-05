# FLOP Testnet Readiness Adapter V0

## Boundary

V0 is `DRY_RUN_ONLY`. It prepares typed configuration, source verification,
state transitions, claim and inference previews, fixture spend accounting, and
fixture receipt verification. It has no HTTP/RPC client and cannot create or
import a wallet, sign a transaction, claim a faucet, transfer or approve a
token, purchase inference, or interact with a contract.

The current Tier-1 source is the [official FLOP teaser](https://flop.finance/teaser/).
Its timing, tokenomics and agent participation language are
`OFFICIAL_DRAFT`; no operational testnet, faucet, inference, chain, contract or
wallet configuration has been published.

## Commands

```bash
PYTHONPATH=src python3 -m flop_agent.cli testnet-readiness status
PYTHONPATH=src python3 -m flop_agent.cli testnet-readiness faucet --dry-run
PYTHONPATH=src python3 -m flop_agent.cli testnet-readiness balance --fixture
PYTHONPATH=src python3 -m flop_agent.cli testnet-readiness inference --fixture
PYTHONPATH=src python3 -m flop_agent.cli testnet-readiness verify-receipt RESULT_RECEIPT
```

Fixture activity receipts use SHA-256 integrity verification. They are
explicitly marked `fixture: true`, `live_action: false`, and are not authorship
signatures or proof of testnet participation.

## Source gate

- Accept: `flop.finance`, FLOP Labs GitHub, official Technocore documentation,
  official FLOP Yellow Paper, and direct `@flop_labs` announcements.
- Review: direct Arthur Hayes FLOP posts or known contributors.
- Reject: random social posts, forwarded screenshots, mirrors, aggregators,
  third-party faucet and wallet tools.

URLs delivered by a signal are inert configuration candidates. The adapter
does not fetch them. Every candidate remains `REVIEW_REQUIRED` and is never
auto-activated.

## Wallet separation

- DID key is not a wallet key.
- X25519 key is not a wallet key.
- GitHub and SSH keys are not wallet keys.
- Never reuse an existing wallet seed.
- Never send a seed or private key to Technocore or any endpoint.

V0 contains no private-key handling code. Human approval cannot override the
V0 live-action block.

## Activation checklist

Live-mode design must remain `DO_NOT_ACTIVATE` until an official network name,
chain ID, RPC, explorer, faucet, inference endpoint, wallet requirements,
token details, security review and explicit human approval all exist. A future
implementation requires a separate security review and release decision.

The adapter never estimates airdrop rewards, eligibility, score, rank or ROI.
