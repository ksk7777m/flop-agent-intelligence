# Testnet Readiness and Runtime Capability

This Safety Layer package keeps five independent claims separate:

`IMPLEMENTED != DOCUMENTED != RUNTIME_OBSERVED != READY_TO_ACT != AUTHORIZED_TO_ACT`

The canonical assessment covers Identity, Technocore, Export Evidence, Faucet,
Testnet Network, Inference, Settlement Rail, and Evidence Durability. Missing or
old evidence produces explicit blockers. The overall state is the least
justified critical-domain state, never an average.

## Evidence and authority

Documentation, reviewed repository sources, signed official sources, direct
runtime observations, third-party reports, and local fixtures have distinct
provenance. Third-party reports are `UNTRUSTED_CONTEXT` and cannot promote
runtime readiness. Runtime evidence is an opaque process-local token issued by
the sealed verifier for a fixed reviewed-source probe. Its public projection is
`DESCRIPTIVE_ONLY`; it cannot be copied, serialized, reconstructed, or used
across verifier authorities.

The checked-in package performs no live probe. Future read-only probes are
inert specifications binding an exact reviewed source ID, method, endpoint ID,
redirect policy, retry policy, timeout, response cap, and safe response
classes. A separate human approval is required before any future probe is run.
Observations are evidence only and can never initiate a claim, signature,
wallet operation, inference spend, payment, or Technocore write.

## Freshness and conflicts

The local Safety Layer default TTL is six hours. It is conservative policy, not
a protocol truth. A future or expired observation is
`STALE_RUNTIME_OBSERVATION`. Documentation claiming availability while the
reviewed runtime reports unavailability is
`CONFLICTING_CAPABILITY_EVIDENCE`; neither record rewrites the other.

## Action boundary

`ready_to_act` and `authorized_to_act` are separate fields. This package has no
configured action-authorization store, so it cannot mint authorization. Faucet
claims and inference execution remain disabled. PaperRail protocol validity is
not economic value: `economic_value_verified` remains false until independent
economic and finality evidence exists.
