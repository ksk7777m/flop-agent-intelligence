# Sonnet-2 Production Receipt Observer Supervisor

This package supplies a foreground-only, GET-only lifecycle around the existing
Sonnet-2 production receipt observer. It is not a registration runner. It has no
registration POST, signed GET, signer, identity loader, nonce allocator,
request-ID generator, approval issuer, wallet, claim, or participation action.
Running it does not authorize registration.

## Fixed production boundary

The public production builder accepts only the local private runtime `Path`.
It seals `FixedReadonlyTransport`, the reviewed production observer factory,
and a UTC clock in a closure. Origin, room, writer binding, request binding,
referee, manifest, generation handling, cursor tracking, gap recovery, receipt
verification, and storage remain owned by the existing receipt-observer package.
There is no general HTTP client, URL, transport, verifier, or duration argument.

Receipt signature verification is isolated in a verification-only module. The
supervisor import graph does not import the registration adapter that owns the
production signer and POST transport. The fixture factory with dependency seams
is private and is not used by the production entrypoint.

The launcher resolves the already provisioned private root through the existing
same-account, local-only runtime contract. It accepts no command-line
configuration and reads no environment fallback. Consequently, a private path,
DID, request binding, or X binding is not copied to process arguments or the
environment. The fixed receipt child must already be provisioned and pass the
P0.1 descriptor boundary.

## Session lifecycle

Startup makes one bounded unsigned GET to the fixed registration-room JSON view
to obtain the live response body's deployment generation and high-water cursor.
Those fields are unsigned `OBSERVED_DEPLOYMENT_FIELD` inputs, not referee-signed
facts. The bootstrap transport is closed before the existing production factory
starts its own session. The observer then validates storage and all sealed
bindings, performs its initial gap-free read, and durably checkpoints the cursor.

Only after that sequence does the foreground launcher emit
`OBSERVER_READY`. The same process, observer object, store, lock, checkpoint
lineage, and transport continue polling after readiness; readiness never ends
the process or grants write authority.

The production bounds are fixed:

- maximum monotonic wall time: 1,800 seconds;
- minimum interval between request starts: 2 seconds;
- hard read budget: 902 reads, including page reads and any bounded export
  fallback;
- page limit: 200 records and 256 KiB;
- export limit: 50,000 records and 12 MiB;
- individual request timeout: 20 seconds; and
- server long poll request: at most 10 seconds.

The two-second pacing caps immediately returned reads at 30 per minute. At the
recently observed busy-room order of magnitude, this keeps the expected records
per page well below the fixed 200-record window, while ensuring that the 902-read
budget cannot be exhausted before the 30-minute wall boundary solely by instant
responses. A gap still invokes the existing single bounded export recovery. An
unresolved gap terminates for review; it does not loop exports. HTTP 408,
transport errors, malformed data, and unsupported rate-limit responses end as
unconfirmed and are never converted into POST or retry behavior.

The monotonic deadline is independent of system-clock changes. No request starts
when less than one request timeout remains. Pacing waits are interruptible.
`SIGINT` and `SIGTERM` handlers only set a stop event; normal process code closes
the active read, transport, private store, lock, and descriptors. The process is
not detached, creates no PID file, and has no restart loop or scheduler.

## Redacted status contract

Output is one-key compact JSON containing only one of these fixed values:

- `OBSERVER_STARTING`
- `OBSERVER_READY`
- `OBSERVER_ACCEPTED`
- `OBSERVER_REJECTED`
- `OBSERVER_UNCONFIRMED`
- `OBSERVER_REVIEW_REQUIRED`
- `OBSERVER_STOPPED`
- `OBSERVER_TIMEOUT`

Exactly one terminal status is emitted. Output never includes private paths,
DIDs, request IDs, X bindings, cursors, room content, receipts, signatures,
process IDs, or descriptor numbers. A valid signed fixed-referee receipt is the
only source of accepted or rejected status. Timeout or inability to retrieve a
receipt is not registration rejection. Archive eligibility remains pending until
the referee's valid signed receipt supplies the formal disposition.

## Operational boundary

Production launch requires a separate explicit human approval. The reviewed
entrypoint is `scripts/run_sonnet_receipt_observer.py`; its path is documented
for review, not as authorization to execute it. Once separately approved, the
operator keeps it in the foreground, waits for `OBSERVER_READY`, and separately
decides whether to authorize the one-shot registration path. The supervisor
must already be running before any such write and must remain running afterward.

The observer may create only the P0-approved private lock, checkpoint, minimal
metadata, target-matching verified receipt, and conflict marker. It stores no
room dump, export dump, participant list, registration payload, key material,
nonce material, approval, permit, or public journal. It never auto-restarts.
