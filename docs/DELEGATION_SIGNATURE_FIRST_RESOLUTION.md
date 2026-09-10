# Delegation Signature-first Resolution

This pure offline boundary resolves only records supplied in an untrusted
Technocore delegation-note carrier. It validates canonical bytes and grammar,
verifies Ed25519 signatures and reviewed root commitments, filters expired
records, and only then ranks lossless decimal nonces per agent. Forged records
never participate in supersession. Equal-nonce valid conflicts fail closed and
duplicate exact records are counted once.
Different reviewed roots for the same agent are conflicting chains and never
supersede one another. Public records expose only a dense relative nonce rank,
which lets semantic validation prove that a supersession target is a higher
current record in the same root-agent chain without exposing the nonce.

The provided note is not assumed to contain complete history. Current means
current only within the provided evidence scope. Production's reviewed root
authority registry is empty, so caller labels and caller-supplied keys cannot
establish a delegation. Public output contains fixed states, bounded counts,
and commitments—not DIDs, scopes, nonces, signatures, note content, or paths.

A current delegation is permission evidence only. It never authorizes network,
room, wallet, faucet, inference, signing, payment, or claim activity. The base
delegation feature is recorded as merged upstream while the signature-first
upstream correction remains open and is not treated as a runtime guarantee.
