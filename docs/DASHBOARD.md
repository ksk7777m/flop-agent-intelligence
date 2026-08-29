# FLOP Agent Readiness Dashboard V1

The dashboard is a static read-only surface served from the repository root.
It uses plain HTML, CSS and JavaScript and fetches versioned JSON from `data/`.
There is no build step and no runtime secret.

## Trust labels

- `CONFIRMED`: directly verified against a first-party source or cryptographic
  evidence.
- `COMMUNITY`: a participant-reported state or community practice that does
  not establish an official FLOP claim.
- `INFERENCE`: an explicitly labeled interpretation.

`NOT ANNOUNCED` means no first-party announcement is recorded in the current
dataset. It does not predict a future announcement.

## Publishing with GitHub Pages

Configure Pages to deploy from the `main` branch repository root. The expected
URL is `https://ksk7777m.github.io/flop-agent-intelligence/`. Enabling Pages is
a separate repository setting and is not performed by the dashboard itself.

## Security boundary

The browser receives public JSON only. DID and X25519 private keys, wallet
material, local filesystem paths and credentials are excluded. Technocore note
values and room names remain untrusted data. The checker fetches only its
hard-coded official allowlist and performs no external write.

The Presence Adapter panel is a reviewed readiness snapshot, not a server-side
liveness or identity claim. It states `LIVE READY — DISABLED`, zero writes,
the local state, one-hour guard, engaged kill switch, and public unsigned-note
trust boundary from `data/presence_adapter.json`.
