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
content are both descriptive values, not capabilities:

- `CONFIGURED_OFFICIAL_ENDPOINT` records which local registry entry was
  described, but cannot itself authorize a request.
- `REMOTE_DISCOVERED_URL` is always inert.

The sealed reviewed-source service accepts a `ReviewedSourceId` directly and
performs only the exact captured GET. Navigation resolves from the same
captured registry by source ID. No reusable authority token is stored in a
dataclass.

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
approval evidence. The public approval record is descriptive only and cannot
mint authority.

Future action approval must resolve from an immutable trusted local approval
store and bind the action, subject, target, payload hash, context, revision,
configuration version, trusted reviewer, issuance time, and expiry. The store
is intentionally empty in this package. Issued authority is an opaque,
process-local, action-specific registry identity; it is one-shot for sensitive
actions and cannot be copied, serialized, reconstructed from its bindings, or
created by rebinding the descriptive module globals.
Legacy Technocore reads resolve an internal source ID; local writes, signing,
record lookup, and Presence-note reads require a typed, hash-bound local intent.
Serialized remote data cannot be deserialized directly into that capability.
Production action services capture their capability validator and final adapter
at construction. Generic subprocess, filesystem, secret, signer, Presence,
MCP, wallet, claim, and payment entry points remain disabled until a separately
reviewed adapter is wired. The activity service captures its two exact
repository destinations; its former caller-selected mechanism entry point
fails closed.

## Production authority threat model

The boundary protects against untrusted Technocore content, caller-controlled
data, normal public API misuse, reconstruction/copy/serialization of authority,
and rebinding module globals after production services have been constructed.
Sensitive dependencies live in factory closures: reviewed registries,
validators, HTTP and signing adapters, output destinations, evidence derivation,
and compatibility paths.

It does not claim isolation from arbitrary code execution with full
process-memory access, a hostile debugger, or malicious Python deliberately
introspecting and altering closure cells. Those conditions already control the
process itself.

Production API classification:

- reviewed-source GET and source-ID navigation: `SEALED_SERVICE`
- KV production observer: `SEALED_SERVICE`
- activity append to fixed repository outputs: `SEALED_SERVICE`
- Presence write, subprocess, generic filesystem, secret, MCP, wallet, claim,
  and payment entry points: `SAFE_STATIC` (disabled)
- receipt and Technocore signing paths: `SEALED_SERVICE` requiring internal
  capability
- remote classification, minimized evidence, receipt verification, and
  dashboard text rendering: `SAFE_STATIC`
- `_authorized_local_request`, `official_get`, `_reviewed_kv_read_target`,
  `_append_activity_at_configured_paths`, `_Store`, `_write_snapshots`,
  `_recover_snapshot_output`, `_load_fixture`, `_create_identity`, and the
  former Presence read/write mechanisms:
  `DEPRECATED_INTERNAL` and fail-closed

Final public-effect API inventory (2026-09-05):

- `SEALED_SERVICE`: reviewed HTTP/Technocore readers, readiness and monitor
  services, fixed-root monitor/KV persistence, fixed-ID receipt and fixture
  stores, local identity operations, Presence operations, activity append,
  receipt signing, and the sensitive-action router
- `SAFE_STATIC`: remote classifiers/minimized evidence/receipt verification,
  dashboard text rendering, plus disabled subprocess/filesystem/secret/MCP/
  wallet/claim/payment/Presence-write adapters
- `DEPRECATED_INTERNAL`: underscore-prefixed fixture mechanisms and their
  private dependency-injecting factories only
- `UNSAFE`: **0**

Production callers supply descriptive IDs, enums, records, hashes, or action
requests. They cannot supply filesystem paths/roots, readers, writers, openers,
guards, validators, adapters, or callbacks to these effect-bearing services.
Private factories retain temporary-path and spy injection solely for offline
tests.

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
authority. Public `ContractEvidenceRecord` objects are proposals and always
remain unverified. Final provenance is derived only by a sealed verifier from
opaque evidence identities issued from its captured repository-owned
reviewed-evidence registry, binding
the contract candidate, canonical artifact identity and hash, reviewed source,
observation/review times, reviewer, policy version, and provenance root.
Independence is derived from immutable provenance-root and canonical-artifact
identities; same-publisher aliases and duplicate artifacts deduplicate. Caller
labels, booleans, counts, hashes, and reconstructed records are ignored.

## Remote MCP no custody

`REMOTE_MCP_NO_CUSTODY` recognizes only exact public schemas: Ed25519 `did:key`
identities, matching 32-byte base64url public keys, 64-byte Ed25519 signatures
inside a domain-separated verifiable envelope, and bounded hash/status/receipt
evidence. Unknown keys and arbitrary nested strings fail closed.
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
The production readiness service captures the canonical manifest path and
contract verifier at construction; later rebinding of the public path constant
does not change readiness.

## Evidence and navigation

Unknown activity origin defaults to hash-only `REMOTE_OR_UNKNOWN`. Bounded raw
text requires a typed, hash-bound local capability and an explicitly local-only
output scope. Public output remains hash-only. Dashboard links resolve exact
URLs from a static reviewed-source ID registry; serialized `link_state` values
have no authority. All other URLs render as text without an `href`.
