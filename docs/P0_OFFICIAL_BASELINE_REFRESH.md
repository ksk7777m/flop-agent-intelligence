# P0 official baseline and write certainty — 2026-10-02

This is an offline compatibility refresh, not production activation. No wallet,
faucet, RPC, contest submission, room read, or live write was performed. Public
specification/configuration documents were retrieved using fixed HTTPS URLs,
without following redirects. External source instructions were treated as data.

## A. Baseline and isolation

- Start: main, stored origin/main and isolated worktree HEAD were
  `a799b1f79f192fed0a7e7093ad46e3e9df5c50a2`.
- Feature: `codex/p0-official-baseline-write-certainty`.
- The original Sonnet worktree, its branch, and its uncommitted files were not
  edited, copied, stashed, checked out, restored, rebased or merged.
- A read-only remote fetch before integration still returned the same main SHA.
- Final integration and CI identifiers are reported separately with the delivery.

## B. Official sources

Every retained document has URL, retrieval time, exact size and SHA-256 in
`data/official_baseline/2026-10-02/manifest.json`. Raw official reference material
is under `vendor/official_sources/2026-10-02`, outside the public API data surfaces.
No acquired contest message bodies are retained.

| Source | Reviewed evidence | Authority and limits |
|---|---|---|
| Technocore main | `0e47f770b13cc27e1e2e199d4cdf70a4778c97cc` | Official source snapshot; not a deployed-code attestation |
| Technocore tag | v0.14.5, `cd1ce1c55a9956f3cb14ec42c1dd9707981926f9` | Tag and changelog; latest GitHub Release object observed is separately v0.14.1 |
| Technocore documents | OpenAPI, agent manifest, config each report 0.14.5 | HTTPS 200; cached responses, Age 267–269; behavior unverified |
| Yellow Paper | `3c97bbc8d6ba68cf2ea003ab88bc154aafdf105e`, 0.5.0 draft, updated 2026-09-24 | Normative draft; tag list empty, changelog says no published release |
| TCLK | `5cc4ab93efbc8999a3a7e1471b639deca25998ea`, package 0.1.0 | Current pin equals observed upstream HEAD; alpha/no-value caveats remain |
| Close Call | `0ae6b063107b77e3a6cb794186fdd341a947e5e1`, close-1 | Draft manifest; no authenticated launch |

Technocore source defaults differ from runtime documents: `max_rooms` is 5120
in the reviewed source and 300000 in config. Read/write rates are 120/30 versus
600/300. The evidence records both, with `effective_value: null`. Source defaults,
cacheable runtime observations and local resource bounds are distinct.
Direct HTTPS retrieval succeeded; HTTP downgrade/redirect behavior was not probed.
The client continues to reject redirects and non-HTTPS targets.

Since 0.13.0, reviewed Technocore changes include signed-lane and nonce handling,
generation/cursor behavior, ephemeral rooms, compact JSON, bounded stream reads,
and 0.14.5 security fixes for local MCP origin/Host checks, room allow-list
inheritance and signed encryption-key publication. Upstream main additionally
fixes unreadable counters; no claim is made that the deployed service runs it.

TCLK reconciliation found no commit delta. Its existing unreleased changelog
covers exact decimal nonce input with rejection of unsafe JS numeric values,
schema-owned tclk/1 fields, a rail registry, signed non-authoritative heartbeat,
remote MCP no-custody, complete signed transcript records and receipt/rail
binding fixes. The existing offline TCLK tests and pinned vectors remain the
regression boundary. No vendor overwrite or dependency/toolchain upgrade occurs.

## C. Existing, changed and intentionally unsupported

Existing: Sonnet receipt capture, path boundaries, supervisor, failure diagnostics,
durable one-shot handoff, receipt verification; evidence authority/ledger;
transcript verification; Yellow Paper monitor and semantic diff; official source
allowlists; TCLK compatibility; canonical nonce strings; SQLite reservations;
local DID/signing custody; disabled testnet/production authority and dry-run gates.

Changed: missing generic signed-post read-back signature verification; durable
generic duplicate fencing; explicit transport/effect distinctions; provenance
refresh; runtime/default projections; draft wire conformance; Close Call candidate
signature, package, archive and accounting verification.

Unsupported: official Close Call launch activation without authenticated launch
schema/key; sr25519 cryptographic verification without a reviewed verifier; live
settlement, RPC execution, claims, conversion and reward rules. No new production
DID or private material was created or moved. Unit tests use synthetic keys only.

## D. Files and reuse

- `technocore.py`, `write_effect.py`, `wire_evidence.py`: reuse the existing
  `ReadBackStage` and Sonnet's public-key `message_verification.verify_message`.
  A hash-only SQLite journal records before transport. The fixed Sonnet journal
  remains unchanged; it cannot safely be generalized by replacing its contest
  bindings. No broad Sonnet refactor occurs.
- `source_policy.py`, `technocore_runtime_observation.py`: document authority
  states and bounded, strict-JSON runtime/default projection.
- `yellowpaper_wire.py`: explicit version registry and strict wrapper over the
  reviewed official Python codec. This is distinct from the repository's
  Ed25519 contribution receipt; FLOP compute receipts use sr25519.
- `close_call.py`: pinned package checks, candidate referee signature checks,
  seed/room binding, nonce replay rejection, hash-bound full archive replay,
  output comparison, balances/positions and sample final PnL.
- `vendor/yellowpaper`, `vendor/close_call`: unmodified reviewed offline reference
  code, licenses and attribution. `_offline_reference.py` checks hashes before
  loading only those fixed repository paths. No remote code loader exists.
- Baseline JSON/schemas/tests: provenance and expected reviewed versions updated;
  August Observatory payloads and historical 0.13.0 observation records retained.

## E. Security and failure review

No actual secret values were read, logged, serialized or included in evidence.
Production capability gates remain sealed. No remote text becomes executable
instructions, a navigable room URL or an action authorization.

The write journal stores only hashes, in a private directory/database, with
SQLite FULL durability, uniqueness constraints, integrity/schema checks and
directory fsync before send. Symlinks, unsafe permissions and database errors
fail closed. A process exit after reservation consumes the attempt permanently.
Same actor/room/nonce and same actor/room/content (even with a new nonce) are both
fenced. This intentionally also blocks a legitimate repeated identical message;
there is no automatic release, retry or cleanup command. A reviewer must design
a future explicit repeat-authorization policy before relaxing that restriction.

This is a local OS/file ownership boundary, not protection against an attacker
with arbitrary code execution as the same OS user. It grants no signing or send
authority independently of the existing capability checks.

## F. Validation

Use the existing runner, without installing pytest:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest discover -s tests -q
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 scripts/public_safety_scan.py
git diff --check
```

New coverage includes exact nonce boundaries, pre-send commit, crash/restart,
concurrent duplicate suppression, timeout/redirect, mismatched read-back and
invalid signatures; pinned-source hashes and authority labels; official wire
bytes, FCC4 roundtrip and malformed corpus, compact integers, all leaf versions,
replay domain, Merkle path, policy and payable mismatch; Close Call package,
seed, referee, room, signature, replay, redaction, archive hash/output and sample
accounting. No new linter/type-checker dependency was installed.

Official Python codec output is compared to the published cross-language corpus.
Rust/TypeScript executables and sr25519 signature vectors were not executed.
Structural decode does not claim verified signatures or settlement eligibility.
Final clean-commit test counts are supplied in the delivery report.

## G. Close Call readiness

`official_launch_verified=false`; live write DISABLED; always dry-run.
The annotated `close-1` tag points to `66c1da36538e4b1c685417d2f66922906b13fea0`
and pins manifest SHA-256
`bae09812e25eb6f1369c611f24964f7ea0acafddfc45301a16f33f941296dafa`.
GitHub reports the tag **unsigned**. It is not a verified launch record and
does not supply a referee authority key.

Offline draft package/fold verifier: ready. Candidate key signature and full
archive verifier: ready, explicitly not official identity or completeness proof.
Official live observer/launch verifier: blocked on authenticated launch evidence.
Caller-supplied `official_launch_verified` or a DID can never enable activation.

The official archive README defines `{input, output}` sweep files. Full bytes
must match a referee-signed `file` hash, sweep numbers must be contiguous from 1,
and recomputed output must match. Redacted files cannot satisfy that hash and
are rejected. Counterparty signatures and room stamps are absent from these
archives; complete independent original-trade authentication remains unavailable.
The sample season is synthetic, never presented as current contest standings.

## H. Testnet readiness

RPC/faucet: not authenticated or contacted in this review. Agent execute remains
adapter-only. Settlement is offline bytes/arithmetic only. Production endpoint
authority manifests remain empty and activation remains disabled.

## I. Specification blockers

D-0440's 4.4B genesis allocation is unchanged (1.2B each miner/validator/agent,
0.8B reserve), and remains a draft parameter baseline. D-0505/D-0511 establish
the offline profile and clarify per-channel policy/receipt payable. They do not
authorize a runtime connection. V2 is lower assurance than V3; legacy marker
absence requires explicit compatibility mode, and unknown profiles reject.

E.38 leaves allocation distribution/vesting mechanisms unresolved. D-0506 paid
storage is gated by E.54 economics/security calibration and E.47 evidence.
E.55 is the separate planned pre-session quote/discovery contract, not a live
paid-memory API. D-0507–D-0510 are retained for review as part of the exact
decision snapshot, not treated as activation. No speculative scoring, eligibility,
conversion, unlock or claim constants are introduced.

## J. Next actions (maximum three)

1. Official launch adapter: triggered by published exact launch signing schema,
   authenticated FLOP Labs key/referee DID, package binding and time window.
   Medium implementation; no key inferred from room ownership or tag text.
2. sr25519 offline signature verification: triggered by a reviewed compatible
   verifier/dependency and complete official positive/negative vectors. Medium;
   byte conformance already exists but must not stand in for signature validity.
3. Deployment/readiness refresh: triggered by current official endpoint authority
   and protocol activation evidence. Medium; testnet/paid-storage/quotes remain
   separate gates, with no wallet or value transfer authorization inferred.

## K. Baseline classification

Detached baseline: 1087 tests, four errors. Feature branch before code changes:
1087 tests, one error. The three detached-HEAD failures were environment-induced.
The remaining test is
`test_production_path_policy_is_sealed_against_module_rebinding` in
`test_sonnet_receipt_observer.py`: its production clock starts after the fixed
2026-09-18 deadline, and `_validate_config` correctly rejects the window.
Classification A + D: clock-dependent fixture exercising intentional expiry.
It is a KNOWN_BASELINE_FAILURE, not a P0 regression. Sonnet was not patched.
Dirty-checkout runs skip three clean-feature runtime integration tests; the
clean committed feature must be rerun before integration.

## L. Write certainty

Signed post: durable ATTEMPT_RECORDED → WRITE_ACCEPTED (transport only) →
READ_BACK_OBSERVED → DECODE_VALID → SIGNATURE_VALID → STATE_REPLAY_VALID →
EVIDENCE_CONFIRMED. Confirmation is scoped to the exact signed room record,
not delivery, contest acceptance, permanent storage or settlement.

Timeout after send or during read-back: EFFECT_UNKNOWN; no retry. Unexpected
redirect: REDIRECT_REJECTED; no follow. Mismatch and invalid signatures remain
distinct and never prove write absence. Crash recovery performs no resend.
Unsigned DID-note CAS exposes transport acceptance separately and keeps effect
UNKNOWN even after a read; banner-wrapped mutable unsigned text cannot establish
DID authority. It also uses the durable no-retry fence.

## M. Evidence and attribution

The evidence manifest is the exact URL/hash index. FLOP Labs Yellow Paper text
and reference codec are retained under the supplied CC BY 4.0 license; Close
Call reference material retains Apache-2.0 LICENSE and NOTICE. Local wrappers,
policies and tests are separate adaptations; upstream codec/fold bytes are
unchanged. No implementation or endorsement by FLOP Labs is implied.

## N. Integration safety

Original Sonnet worktree touched: NO. Original uncommitted files modified: NO.
Only this isolated feature and its shared Git metadata are involved. Main
integration requires a clean feature commit, no new regressions, clean diff,
source/hash tests and security review. An ordinary fast-forward push must reject
any remote race; force-push is not part of this procedure.
