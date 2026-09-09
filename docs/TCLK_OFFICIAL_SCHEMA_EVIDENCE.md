# TCLK Official Schema Evidence Pinning / Offline Source Import Boundary

This package records a one-time, read-only observation of the official
`flop-labs/tclk` GitHub repository. Mutable `main` was resolved once, then every
content request used exact commit
`5cc4ab93efbc8999a3a7e1471b639deca25998ea`. Git commit identity, Git blob
identity, and raw SHA-256 remain separate.

## Immutable snapshot

The exact `schema/tclk1-frames.schema.json` bytes, repository LICENSE,
`SPEC.md`, `src/frames.ts`, and `tests/vectors.test.ts` are
retained under `vendor/tclk/<commit>/`. The schema is 6,070 bytes, is bound to
its Git blob and SHA-256 in `data/tclk_official_schema_evidence.json`, and is
loaded only from the repository-owned fixed path. The retained LICENSE is the
observed Apache License 2.0 text and is independently bound by blob, hash, and
size. A new upstream revision must use a new generation; these files are never
updated in place.

The production loader accepts no URL, path, schema, environment override, or
dependency injection. It rejects missing, non-regular, symlinked, oversized,
modified, duplicate-key, semantically drifting, and incomplete-reference
snapshots. It never downloads a missing file and has no network fallback.

## Extracted accept semantics

The pinned document declares JSON Schema Draft 2020-12 and a `tclk/1` frame.
The accept definition is a closed object with required fields `type`, `from`,
`ref`, `statement`, `contract`, and `nonce`. The source representation order is
retained separately from the semantic unordered required-field set.
`paymentKey` is optional. `contract` resolves to the local `hex32` definition;
all document references are local and resolve within the same snapshot.
Accordingly, this generation records
`OFFICIAL_SCHEMA_CONFORMANCE_POLICY_PINNED` and
`REQUIRED_CONTRACT_POLICY_ATTESTED`.

The earlier local profile remains immutable and is not silently upgraded. Its
two-field accept shape differs from the pinned six-required-field definition,
so the comparison is `SPEC_DRIFT`. Prior observations remain classified under
their original reported policy and historical reclassification stays blocked.

## Contract derivation and trust limits

The same exact commit binds the normative-document candidate `SPEC.md`, reference implementation
`src/frames.ts`, and `tests/vectors.test.ts` golden vectors by path, blob,
SHA-256, and size. Together they specify the domain-tagged SHA-256 over
ASCII-escaped canonical `{offer, accept-core}` input. Exact bytes are retained,
Git blob/SHA-256/size are recomputed offline, and an independent golden-vector
calculation matches. The source and algorithm are therefore recorded as
`CONTRACT_DERIVATION_SPEC_PINNED`; implementing that
algorithm or an accept preflight validator remains outside this package.

GitHub repository observation is not maintainer signature verification,
protocol ratification, Yellow Paper settlement conformance, or proof of the
currently deployed Technocore runtime. Issue #142 was observed as an open Issue,
but the acquisition timestamp was not retained, so the artifact explicitly
does not claim a current state. Its mutable body is represented only by a hash and no
maintainer ratification is inferred.

## Acquisition and action isolation

Acquisition used fixed GitHub API/raw hosts, GET only, identity encoding,
bounded bodies, a fixed timeout, strict content type and length checks, redirect
rejection, no credentials, no fallback, and automatic retry count zero. One
manual re-execution followed a local decoder incorrectly applying strict base64
validation before removing transport whitespace. The remote schema was not
malformed; whitespace was removed before strict decoding on the second attempt.
The second metadata/raw requests are retries at the communication level and are
recorded as an acquisition-policy deviation. The 26 attempts are preserved in a
resource-level ledger. Because no sealed per-request transcript was retained,
the acquisition audit is `ACQUISITION_AUDIT_INCOMPLETE`; source identity,
offline content integrity, reproducibility, and production network exposure are
independent states. Further fetches are forbidden. No remote source was executed.

The checked-in runtime contains no network acquisition API. Technocore, MCP,
signing, nonce allocation, wallet/payment, posting, rails, Faucet, claim,
inference spend, polling, and automatic migration remain absent.
`ready_to_act`, `authorized_to_act`, and `live_action_enabled` are false and
compatibility remains `COMPATIBILITY_REVIEW_REQUIRED`.

Both schema and contract derivation evidence are now pinned, so the next
candidate is **Offline TCLK Accept Preflight Validator**. This is a candidate
only; implementation does not begin in this package.
