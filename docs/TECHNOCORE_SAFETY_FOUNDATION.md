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

A reviewed endpoint is resolved from the repository-owned `ReviewedSourceId`
registry. Callers cannot supply a URL, trust tier, or allowlist to create that
authority. A registry endpoint and an identical URL discovered in remote
content are different capabilities:

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
Legacy Technocore reads resolve an internal source ID; local writes, signing,
record lookup, and Presence-note reads require a typed, hash-bound local intent.
Serialized remote data cannot be deserialized directly into that capability.

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
authority. Final provenance is derived only from a repository-owned evidence
bundle containing exact contract, artifact hash, reviewed source identity,
observation time, and independent-source identity records. Configuration
strings and caller counts/booleans are ignored.

## Remote MCP no custody

`REMOTE_MCP_NO_CUSTODY` permits only bounded public DID/public keys, signatures,
strict public-only signed envelopes, and non-secret hashes/evidence at a future
remote boundary. Keys and values are recursively checked with depth, key-count,
type, and string-size limits.
DID, X25519, wallet, payment/signing, API, and SSH private material is always
forbidden. All signing remains local. This package does not install or invoke
an MCP.

## Compatibility

`data/technocore_compatibility.json` separates reviewed semantic invariants
from mutable deployment observations. Its status intentionally remains
`COMPATIBILITY_REVIEW_REQUIRED`; a local manifest is not proof of current live
compatibility. Updating deployment observations requires a separately approved
read-only check of configured official sources.
`COMPATIBILITY_REVIEW_REQUIRED` blocks future faucet, inference, contract,
wallet, and protocol-dependent signing readiness. It does not block the
independent Engagement observational GET contract.

## Evidence and navigation

Unknown activity origin defaults to hash-only `REMOTE_OR_UNKNOWN`. Bounded raw
text requires a typed, hash-bound local capability and an explicitly local-only
output scope. Public output remains hash-only. Dashboard links resolve exact
URLs from a static reviewed-source ID registry; serialized `link_state` values
have no authority. All other URLs render as text without an `href`.
