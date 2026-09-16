# Sonnet-2 Attended Registration Orchestration

This boundary connects one explicitly created post-gap observation interval to
the existing one-shot durable writer-registration handoff.  It does not resolve
the earlier cursor gap and never treats that gap as proof that the request was
not sent.  The prior active evidence and migration archive remain immutable.

## Fixed new interval

The interval uses the fixed `sonnet-registration-live-interval` child directly
under the existing operator-supplied external private root.  It never falls back
from the old child and never selects a caller-supplied basename.  The child must
be separately provisioned as an empty owner-controlled `0700` directory before
production use.  Provisioning, observer startup, approval issuance, signing and
registration each remain separately authorized operations.

`scripts/provision_sonnet_registration_interval.py` is read-only without an
argument.  Its separately authorized `--apply` mode creates only the fixed empty
child with mode `0700`; it creates no parent, checkpoint, lock or approval.  The
creation operation repeats the repository, linked-worktree, cloud-sync,
symlink-component, owner, mode and local-filesystem checks while pinning the
root directory FD; the fixed child is created descriptor-relative only after
that revalidation.  The
first attended start creates the fixed session lock, which also permanently
marks that interval as started even if bootstrap fails before a checkpoint.

Starting the interval rechecks that the durable registration journal is
`NOT_STARTED`.  The original request ID, participant DID, writer role, X binding,
referee and manifest remain sealed by the existing full-lineage digest and
registration boundary.  A nonempty new-interval child is never reset or reused
as a new interval.

## Same-process attended handoff

`begin_attended_registration` starts the reviewed GET-only supervisor and
returns a non-serializable one-shot session.  Registration remains unavailable
until that exact session has reached READY, is still running, has enough time
for the fixed POST timeout, and the journal is still `NOT_STARTED`.  These gates
are checked again immediately before the durable handoff.

Before READY, the same GET-only supervisor classifies both the validated
high-water record and the bounded retained export.  It then feeds each validated
registration-room page to the existing fixed registration classifier.  READY is
therefore not itself treated as proof of no conflict: the observed window must classify as
`NO_CONFLICT_IN_OBSERVED_WINDOW`.  An identical previously observed request,
another role for the participant, an X collision, or a related verified receipt
stops the session before signing.  Immediately before `POST_ATTEMPT`, the
handoff rechecks liveness and atomically reserves the clear observed window;
only the expected request from that durable attempt may then appear.

The human approval uses the existing closed approval schema and the fixed local
reviewer identity `local-human-operator`.  Missing, expired, altered or extra
fields fail before key loading.  No approval is checked in or installed by this
package.  The production state therefore remains unapproved after deployment.

Once the handoff records durable intent, its existing crash semantics apply.
`POST_ATTEMPT_RECORDED` precedes the sole transport call.  Timeout, HTTP 408,
disconnect, malformed response and non-2xx yield `WRITE_OUTCOME_UNKNOWN` with no
automatic resend.  The observer remains a separate GET-only component and owns
no signer or POST capability.

The liveness check is an immediate same-process gate, not a promise that the
network or observer can never fail during the subsequent bounded POST.  Such a
failure leaves the journal reconciliation-only and requires the already defined
read-only receipt reconciliation path.

## Production sequence (not authorized by this document)

1. Separately provision only the fixed new-interval child.
2. Start `scripts/run_sonnet_attended_registration.py` in an interactive
   foreground terminal.  Piped or detached approval input is rejected.
3. Wait for READY from that same process and confirm it remains running.
4. After reviewing the fixed request described in
   `SONNET2_REGISTRATION_SIGNER_BOUNDARY.md`, enter exactly
   `APPROVE_FIXED_SONNET2_WRITER_REGISTRATION`.  The process issues a
   five-minute, in-memory approval using the existing closed schema and
   immediately consumes it on the same session.
5. The session and approval cannot be reused.
6. Keep the same observer running until a verified terminal receipt or bounded
   terminal condition.  On ambiguous POST outcome, do not resend.
