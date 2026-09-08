# Technocore Runtime Compatibility Evidence / Read-only Observation

Status: one-shot, bounded, descriptive-only observer. The documented baseline is
Technocore `0.13.0` at revision
`45921c3e3699e01a55cde391674815367e0cff6b`. A live document observation is
not action authorization and does not by itself establish full deployment
compatibility.

## Existing coverage and package scope

| Concern | Initial classification | Result |
|---|---|---|
| source identity and fixed URL resolution | `ALREADY_COVERED` | Existing `ReviewedSourceId` registry reused; one exact OpenAPI ID added |
| sealed GET, redirect rejection, bounded response, timeout, retry zero | `ALREADY_COVERED` / `PARTIALLY_COVERED` | Captured production opener and registry; exact final URL, fixed bounds and one attempt per source |
| document hashing | `ALREADY_COVERED` | SHA-256 and bounded byte count only |
| JSON canonicalization | `PARTIALLY_COVERED` | JSON is structurally parsed; no raw or canonical document is retained |
| semantic capability verification | `MISSING` | Fixed per-source predicates added; caller regex, JSONPath and expected values are impossible |
| cache metadata minimization and freshness | `MISSING` | Age state, cache-control class and validator presence only; freshness is never confirmed by a single GET |
| deployment version evidence | `BLOCKED_BY_OBSERVATION` | Explicit top-level version only; hash or semantic similarity cannot establish it |
| compatibility and drift derivation | `PARTIALLY_COVERED` | Sealed descriptive derivation; compatibility always requires review |
| public projection and retention | `PARTIALLY_COVERED` | Closed schema and field reconstruction; no persistence or replacement interface |
| watcher action isolation | `ALREADY_COVERED` | No scheduler, retry, writer, MCP, signer, wallet or capability issuer |
| runtime nonce outcome | `BLOCKED_BY_LIVE_ACTION` | Remains `BLOCKED_BY_LIVE_SIGNED_WRITE`; no nonce request is made |

## Fixed live source set

- `TECHNOCORE_LLMS`
- `TECHNOCORE_OPENAPI`
- `TECHNOCORE_AGENT_MANIFEST`
- `TECHNOCORE_CONFIG`

These identifiers resolve through the repository-owned registry. Callers cannot
supply a URL, resolver, transport, redirect policy, timeout, byte cap, predicate,
filesystem path or trust tier to the production observer. Remote-discovered URLs
are never navigated. There is no fixed general-purpose public note source suitable
for cache observation, so arbitrary namespace/key selection is prohibited and that
coverage remains unknown.

## Evidence semantics

Each source records request completion, status, exact-final-URL result, redirect,
size/content-type acceptance, schema/semantic result, hash/length, minimized cache
state and observation time. Raw bodies, error bodies, headers, URLs, cookies and
tokens are neither projected nor persisted.

OpenAPI requires version 3.1 and fixed read route structures. The agent manifest
requires typed limits and capabilities. Config requires the service identity and
fixed settings structure. Text evidence requires a document heading, not an
arbitrary capability string. Exact body hashes describe bytes only; they do not
prove version or compatibility.

`Age` and `Cache-Control` can establish only unknown, potentially stale, or
conflicting evidence in this package. They never prove latest state, ownership,
revocation or authorization. Failed or partial observations are coverage gaps and
cannot overwrite a prior record because the observer exposes no persistence API.

## One-shot observation

At `2026-09-08T04:34:36Z`, exactly one GET was attempted for each fixed source.
All four requests completed with status 200, exact final URL, accepted bounded
size and accepted content type. OpenAPI, agent-manifest and config predicates
matched. The initial reviewed llms predicate did not match its document heading,
so that source is retained as a semantic gap for this observation; the predicate
was corrected against the pinned repository after the run and the live request
was not repeated.

Agent manifest and config exposed an explicit `0.13.0` version. This is one-shot
deployment-version evidence, while overall compatibility remains
`COMPATIBILITY_REVIEW_REQUIRED`. All four responses exposed minimized cache
evidence classified as potentially stale. No raw response, header or URL was
stored. Public-note cache behavior remains a coverage gap because there is no
suitable fixed generic note source.

The public projection always remains `COMPATIBILITY_REVIEW_REQUIRED`,
`ready_to_act=false`, `authorized_to_act=false`, and `live_action_enabled=false`.
No remote MCP is invoked or given key custody. No retry, write, signing, wallet,
claim, faucet, inference spend, scheduler or automatic polling exists.

## Remaining blocked evidence

- runtime nonce consumption requires a prohibited live signed-write experiment;
- public note cache behavior lacks a fixed reviewed note source;
- a one-shot document match does not establish testnet readiness or authorization;
- observation gaps require human review, never an automatic action.
