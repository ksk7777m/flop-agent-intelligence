# Compatibility and Security Consolidation

This consolidation adds no capability. It records the current reviewed
compatibility assumptions and tests that independent package boundaries cannot
promote one another. Source type is not authority; authenticity is not
completeness; completeness is not winner; winner is not settlement. Discovery,
review, delegation, referral, rail metadata, and evidence readiness never imply
authorization or execution.

All six checked-in production authority manifests and registries are empty.
Production APIs remain offline-only and expose minimized states, booleans,
bounded counts, safe commitments, and fixed error codes. Cross-package tests
reject bool-as-int and noncanonical identifiers, unknown fields, oversized
inputs, unknown authorities, secret-bearing inputs, and reachable live clients.

Current compatibility assumptions keep release, repository main, official
documentation, and deployed runtime distinct. Historical observations remain
immutable. Material official changes to Testnet, Faucet, claim/provisioning,
Yellow Paper, value-bearing rails, or KOL rules are triggers for a separate
review—not automatic activation.

The general-purpose `runtime-capability` schema retains a future `AUTHORIZED`
state, but it is not an authority issuer and is separate from current
Production policy. No checked-in Production manifest or consolidation artifact
can select that state. This package fixes `authorized_to_act=false` and
`live_action_enabled=false`; callers cannot override either flag.
