# TCLK Authenticated Winner Issuance

This offline-only boundary can issue `OFFER_GLOBAL_WINNER_VERIFIED` only when a
validated offer-wide completeness artifact is bound to the exact offer and
transcript, every derived candidate is locally eligible, a hash-pinned policy
is used, and a pinned winner authority signs both an exact chronology artifact
and the final winner decision.

Candidate commitments are sorted only to commit to set membership. That sort
is never winner order. Winner order comes solely from the separately signed
chronology artifact, which must contain exactly the complete candidate set,
declare unique ordering, and bind the offer and candidate-set digests. The
decision additionally binds the exact completeness and chronology bytes, policy
digest, offer, candidate set, selected commitment, nonce, and freshness window.
The replay identity consumes the decision nonce at the authority-version and
key scope. Changing the offer, candidate set, policy, or selected winner cannot
make the same authority nonce reusable.

Both local authority manifests are intentionally empty in production. Tests use
only in-memory ephemeral keys. Until a reviewed public winner authority is
pinned, the production API fails closed with an unresolved winner.

The public result exposes only a winner commitment, fixed states, counts, and
generic codes. It never exposes DIDs, signatures, nonces, records, statements,
room or venue metadata. A verified winner is coordination evidence only: race
loss remains unissued, lock and settlement remain unverified, and all action
flags remain false. It does not prove payment, quality, reputation, commercial
truth, or eligibility.
