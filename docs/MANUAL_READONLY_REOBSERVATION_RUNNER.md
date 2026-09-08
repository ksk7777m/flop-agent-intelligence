# Manual One-shot Read-only Reobservation Runner / Human Execution Boundary

Status: implemented-disabled in production, fixture HTTP tested. Production has
no permit issuer, execution function, CLI command, scheduler, configuration or
environment activation switch. Import and public projection perform zero GETs.

## Fixed plan and authority boundary

The sealed plan binds predicate v2 and its hash, the existing four-source set
and order, generation zero, GET only, one request per source, retry zero, the
existing timeout/body limits, rejected redirects, and no alternate URL,
fallback, MCP, signing, external write, scheduler or automatic resume. Its ID is
a strict typed canonical SHA-256 identity. Callers cannot replace its sources,
order, transport, policy, limits or generation.

Human review is descriptive and does not create a live capability. The only
permit issuer and runner constructor are private fixture seams. A permit is an
opaque, non-copyable, non-serializable, process- and service-local object bound
to the exact plan and generation. It is consumed once. Foreign, forged,
cross-process and reused permits fail before network invocation. No production
path can issue a permit or invoke the runner.

## Fixture execution and crash order

The fixture integration uses the existing sealed runtime observer and durable
journal. Its order is: plan prepared, permit consumption durable, attempt intent
durable, source intent durable, request boundary durable, one GET, minimized
result durable; after all four sources, sealed v2 evidence commit and finalization.
The source sequence is fixed. There is no retry, fallback or continuation after
a semantic/transport gap.

An exception after the request boundary is `OUTCOME_UNKNOWN`. Recovery is
inspection-only: it performs zero network invocations, issues no permit, never
resumes or retries, and requires reconciliation plus a new human review and
plan. Absence, torn state, corruption and unknown durability do not establish a
safe retry.

## Evidence and privacy

Only field-by-field minimized source results are hashed and journaled. The
runner accepts only the sealed runtime observer result type and exact closed
projection; arbitrary mappings, nested metadata, raw bodies, headers, errors,
URLs or provider payloads cannot become evidence. Exception text is not echoed.
The public schema closes both the descriptive plan and disabled status.

Even a complete four-source fixture observation remains
`CURRENTNESS_UNKNOWN`, `FRESHNESS_NOT_CONFIRMED`, and
`COMPATIBILITY_REVIEW_REQUIRED`. It cannot establish nonce state, readiness,
authorization, Testnet values, eligibility, payment, inference execution or any
side effect. `ready_to_act=false`, `authorized_to_act=false`, and
`live_action_enabled=false` remain independent and fixed.

## Follow-up boundary

Production activation, a real human ceremony, retention/rotation policy,
continuous compatibility, and any deliberate live read remain separate future
reviews. Live signed write and nonce work, wallet/claim/faucet/Testnet and
inference spend remain blocked and are not follow-ups of this runner package.
