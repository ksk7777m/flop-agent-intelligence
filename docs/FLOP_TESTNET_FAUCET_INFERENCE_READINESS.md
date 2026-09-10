# FLOP Testnet, Faucet, and Inference Readiness

This package is an offline provenance and evidence-readiness boundary. Its
checked-in baseline records the reviewed 2026-09-10 state: FLOP Yellow Paper
v0.5.0 is an official draft updated 2026-09-05, Technocore is 0.13.0, and no
registration, provisioning, claim, token, Faucet, or inference endpoint is
confirmed live. The exact Yellow Paper document commitment remains unresolved.

Endpoint inputs contain commitments, never raw URLs. An endpoint reaches
`READY_FOR_HUMAN_REVIEW` only when its exact source document, version, endpoint
class, network commitment, and endpoint commitment match a reviewed authority
manifest entry. The production authority manifest is empty, so production
fails closed. Community signatures, Technocore rooms or notes, search results,
unofficial repositories, lookalike sites, referral links, and unproven asset
addresses cannot establish official provenance.

Inference drafts retain only workload, identity, network, request, result,
provider, receipt, and source commitments plus exact decimal usage fields. Raw
prompts and responses are rejected. Spend does not establish usefulness,
settlement, eligibility, or an airdrop score. Claim, wallet, signer, HTTP,
Technocore, MCP, RPC, settlement, and inference clients are absent. Every action
flag remains false; a future verified endpoint stops at human review.
