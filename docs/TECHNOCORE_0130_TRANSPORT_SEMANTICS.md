# Technocore 0.13.0 Transport Semantics

Status: offline defensive model; review-ready. It performs no HTTP or MCP
request, retry, write, signing, wallet, claim, Faucet, inference, process, or
filesystem action. Official source revision
`45921c3e3699e01a55cde391674815367e0cff6b` is tagged `v0.13.0` and
`mcp-v0.13.0`. That establishes documented behavior only. The live deployment
was not observed, so compatibility remains `COMPATIBILITY_REVIEW_REQUIRED`.

## Coverage reconciliation

| 0.13.0 concern | Initial classification | Existing coverage | This package |
|---|---|---|---|
| MCP `list_notes` truncation | `PARTIALLY_COVERED` | Evidence Transport keeps MCP pages `UNKNOWN`/`PARTIAL` and never proves absence | Recognizes only the exact final 0.13.0 footer with matching shown/limit/key counts; malformed, duplicate, ambiguous, oversized, or legacy output stays unknown |
| POST upload HTTP 408 | `PARTIALLY_COVERED` | Replay Journal preserves unknown effects and requires reconciliation | Separates new-connection transport advice from retry authority; outcome remains unknown |
| conditional-note HTTP 409 body | `PARTIALLY_COVERED` | Remote Content Policy and Presence retain only bounded hash metadata | Adds hash-only conditional-write outcome; no CAS rebase, target, payload or capability |
| sweep and signature target | `ALREADY_COVERED` | Identity and Wire Evidence sweep first, reconstruct exact stored bytes, reject empty output and preserve Unicode code points | Adds cross-package regression only; no duplicate implementation |
| nonce consumption and retry | `PARTIALLY_COVERED` | Wire Evidence preserves exact decimal strings; Replay Journal gates retry | Adds explicit `UNKNOWN` nonce outcome while runtime version is unverified |
| note cache freshness | `PARTIALLY_COVERED` | Runtime Capability already separates observation and freshness | Adds note-read metadata/cache-evidence fields; HTTP 200 remains freshness `UNKNOWN` |

Live deployment-dependent claims for nonce consumption, cache behavior and
runtime version are additionally `BLOCKED_BY_RUNTIME_EVIDENCE`. No item is
`NOT_APPLICABLE`; no wholly missing safety foundation was found.

## Independent semantics

`request_completion`, `http_status`, `response_schema`,
`content_completeness`, `content_truncated`, `freshness`, retry disposition,
side-effect certainty and nonce outcome are independent. In particular:

- a completed request is not necessarily schema-valid, complete, fresh, or authorized;
- a truncated MCP listing is partial and dropped keys do not prove absence,
  deletion, inactivity, or zero activity;
- a 408 requires a new connection at the transport layer, but that is not
  permission to resend; reconciliation and new authorization remain required;
- a 409 body is another caller's untrusted remote content and does not prove
  ownership, authorization, freshness, condition, target, or payload;
- an HTTP 200 note read proves retrieval only. Without reviewed cache evidence
  and a separately verified runtime it cannot establish current ownership,
  revocation, authorization, latest state, or compatibility.

The MCP footer parser consumes the bounded byte result directly. Caller-supplied
truncation booleans or dropped counts are not accepted, and remote key or text
content cannot mint truncation evidence. Count evidence is bounded to a signed
64-bit representation; this is an evidence-format bound, not a deployment-capacity
claim.

The public projection is a strict field-by-field reconstruction validated by
`schemas/technocore-transport-semantics.v1.json`. It includes only structured
classifications, bounded counts, HTTP status, body length and SHA-256. Raw MCP
output, HTTP/error bodies, headers, cookies, tokens, authorization values,
private URLs, conditions and write payloads are excluded. Arbitrary additional
properties fail both schema and semantic validation; errors contain only fixed
codes and safe type/length metadata.

## Signing and replay boundary

Existing Identity and Wire Evidence remain authoritative for local canonical
construction. They sign and verify the exact text after Technocore's
single-line sweep, reject sweep-empty content, perform no Unicode
normalization, and keep NFC and NFD byte-distinct. Display transformations and
unswept input are not signature evidence and raw input is not added to this
package's public projection.

Nonce values remain exact decimal strings and are never converted from JSON
numbers or floats. HTTP status alone never determines whether a nonce was
consumed. Any possible re-execution remains subject to the Replay / Side-effect
Journal, reconciliation evidence and a newly issued exact authorization. This
package provides none of those authorities and performs no automatic resend.

## Remaining blocked items

- proof that the live deployment is running the reviewed 0.13.0 revision;
- runtime-observed nonce behavior for malformed conditions and failures;
- trustworthy response-path cache metadata sufficient to classify freshness;
- any CAS rebase workflow or retry executor;
- all live MCP write, signer, wallet, claim, Faucet and inference capability.

Remote MCP custody remains prohibited. Human approval records and serialized
evidence remain descriptive and cannot mint a capability.
