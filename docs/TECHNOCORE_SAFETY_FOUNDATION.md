# Technocore Safety Foundation V1

Status: offline safety foundation. No Testnet, wallet, faucet, inference, MCP,
Presence, or automatic publishing action is enabled by this package.

## Mandatory boundary

All Technocore and other remote content is data, never instructions. The
authoritative implementation is `flop_agent.remote_content_policy`. Remote
values carry an origin, observation time, byte length, SHA-256, source trust
tier, freshness status, and one or more content classifications.

The policy covers room names, topics, messages, nicks, KV namespaces, keys and
values, mailbox content, DID-linked notes, fetched documents, discovered URLs,
and HTTP error bodies. Classification does not remove or execute content. Safe
evidence defaults to metadata and hashes rather than raw content.

## URL and HTTP policy

A configured endpoint and an identical URL discovered in remote content are
different capabilities:

- `CONFIGURED_OFFICIAL_ENDPOINT` can be considered for an exact allowlisted,
  GET-only request.
- `REMOTE_DISCOVERED_URL` is always inert.

Trust does not propagate through links. Redirects are rejected, a response's
final URL must match the requested URL, response bodies are bounded, and error
bodies are represented only by status, bounded length, hash, and error class.

Dashboard navigation has three states: `INERT`, `REVIEWED_OFFICIAL`, and
`APPROVED_FOR_NAVIGATION`. Only exact locally configured reviewed URLs may
reach the last state. All labels and remote text are rendered as text.

## Denied sinks

Remote-derived values cannot select or authorize HTTP targets, subprocesses,
shells, eval/exec, filesystem paths or writes, repositories, package
installers, MCP installation/invocation, signers, wallets, claims, or payments.
Sensitive sinks remain disabled in V1 even when a caller supplies human
approval evidence.

Future action approval must be a purpose-, subject-hash-, reviewer-, and
timestamp-bound evidence object. A caller-controlled boolean is insufficient.

## Source and contract independence

Source tiers are:

1. `TIER_0_OFFICIAL`
2. `TIER_1_SIGNED_COMMUNITY`
3. `TIER_2_UNSIGNED_COMMUNITY`
4. `TIER_3_SUSPICIOUS_CONFLICTING`

Contract provenance is independently one of `UNVERIFIED`,
`OFFICIAL_SOURCE_REFERENCED`, `MULTI_SOURCE_CONFIRMED`, `CONFLICTING`, or
`VERIFIED_FOR_TESTNET_USE`. Official source trust alone never verifies a
contract. A community DID signature authenticates a signer, not official FLOP
authority.

## Remote MCP no custody

`REMOTE_MCP_NO_CUSTODY` permits only public DID/public keys, signatures,
signed envelopes, and non-secret hashes/evidence at a future remote boundary.
DID, X25519, wallet, payment/signing, API, and SSH private material is always
forbidden. All signing remains local. This package does not install or invoke
an MCP.

## Compatibility

`data/technocore_compatibility.json` separates reviewed semantic invariants
from mutable deployment observations. Its status intentionally remains
`COMPATIBILITY_REVIEW_REQUIRED`; a local manifest is not proof of current live
compatibility. Updating deployment observations requires a separately approved
read-only check of configured official sources.
