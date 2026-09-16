# Sonnet-2 Observer Failure Diagnostics

This package closes the diagnostics and long-poll semantics of the fixed,
GET-only production receipt observer. `OBSERVER_UNCONFIRMED` means that the
observer did not establish a verified terminal receipt. It is not a referee
rejection, registration failure, or evidence that registration was absent.

## Safe terminal diagnostics

The runner may emit only the terminal state, a category and phase from fixed
enums, a retryable boolean, a UTC timestamp, a bounded read-attempt count, and
an integer HTTP status when it is needed. The journal projection uses the same
sanitized vocabulary. Private paths, URLs and queries, room names, bodies,
headers, exception messages, addresses, DIDs, request IDs, X bindings,
receipt text, signatures, nonces, checkpoint content, private configuration,
and environment values are excluded from output, serialization, and repr.

The fixed categories are:

- `READ_HTTP_400`: a documented room-read request rejection; no retry.
- `READ_HTTP_429`: rate limited. A single decimal `Retry-After` from 1 through
  30 seconds is eligible for bounded retry; invalid or exhausted cases stop.
- `READ_HTTP_UNEXPECTED_STATUS`: a GET status outside 200/400/429. GET 408 and
  5xx are eligible only for the bounded read retry policy.
- `READ_NETWORK_TIMEOUT` and `READ_CONNECTION_FAILURE`: bounded retryable read
  transport failures.
- `READ_TLS_FAILURE`: TLS/certificate/hostname verification failed; no retry.
- `READ_CONTENT_TYPE_MISMATCH`, `READ_MALFORMED_RESPONSE`, and
  `READ_RESPONSE_LIMIT`: fail-closed response validation; no retry.
- `READ_GENERATION_CHANGE` and `READ_CURSOR_REGRESSION`: unsigned deployment
  continuity changed or regressed; no retry.
- `READ_CURSOR_GAP` and `READ_EXPORT_FAILURE`: retained-ring coverage could not
  be reconciled; no inference of completeness.
- `READ_STORAGE_FAILURE` and `READ_CHECKPOINT_FAILURE`: private evidence or
  checkpoint operation failed; no retry.
- `READ_CLEANUP_FAILURE`: resource cleanup failed when there was no earlier
  result. Cleanup never overwrites an earlier failure or verified receipt.
- `READ_STOPPED`, `READ_WALL_TIMEOUT`, `READ_BOUND_EXHAUSTED`, and
  `READ_CONTEST_DEADLINE`: fixed lifecycle terminals after readiness.
- `READ_RECEIPT_CONFLICT`: mutually conflicting valid referee receipts; review
  is required and neither disposition wins.
- `READ_INTERNAL_FAILURE`: every otherwise unclassified exception.

Phases are limited to `BOOTSTRAP`, `POLL`, `EXPORT`, `CHECKPOINT`, and
`CLEANUP`. After the maximum two consecutive retries or the 60-second total
retry-wait limit, a terminal diagnostic has `retryable: false`. This read-only
policy is not shared with registration POST, signing, nonce, or approval code.

## Long-poll contract

The official wait ceiling is ten seconds. A valid empty 200 response with
`wait_held: true` means the request was held while the room stayed quiet; the
observer reissues with the same verified cursor. `wait_held: false` means no
waiter slot was available; the observer performs an interruptible monotonic
wait equal to the requested wait, then reissues with the same cursor. A waited,
empty JSON response without a boolean `wait_held` is ambiguous and fails closed
as `READ_MALFORMED_RESPONSE`; it is never guessed to be true.

429 accepts only one bounded decimal `Retry-After`; dates, negative values,
multiple values, and values above the local ceiling are rejected. Network
timeout, connection failure, unexpected GET 408, and 5xx have at most two
consecutive retries with fixed two-second fallback backoff and a 60-second
aggregate retry-wait ceiling. Every attempt consumes the read bound and all
waiting remains inside the 1,800-second wall clock and stop signal.
Bootstrap attempts and the first observer read share the same interruptible,
monotonic two-second request-start gate, so bootstrap retry cannot add requests
on top of the 30-GET/minute pacing boundary.

The OpenAPI 408 describes POST body upload timeout. Registration POST retains
its outcome-unknown/no-auto-resend behavior. An unexpected GET 408 is merely a
bounded read failure and never creates write retry authority.

## Durability and operation

No new diagnostic file is created. The sanitized terminal result and existing
private checkpoint are sufficient, while a second durable format would enlarge
the private filesystem and migration boundary. Existing checkpoint bytes are
not guessed, repaired, or rewritten outside normal verified observation.

There is no automatic restart, daemon, scheduler, or PID file. Before any new
production run, an operator must provide fresh explicit approval and perform a
read-only revalidation of the external root, fixed child, checkpoint, and lock
state. The production supervisor remains GET-only and has no signer, identity
loader, private-key loader, nonce allocator, request-ID generator, registration
adapter, approval/permit issuer, wallet, claim, or X-posting capability.
Terminal-output failure is not retried and never prints an exception or
traceback to stderr. A stop signal during bootstrap or retry backoff is emitted
as `OBSERVER_STOPPED`, while cleanup failure cannot replace its earlier cause.
