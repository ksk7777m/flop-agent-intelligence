# Technocore Observatory API

## Snapshot contract

The Observatory publishes reviewed static JSON from the official Technocore
`/rooms?format=json` endpoint. Version `0.10.0` was observed for this V2-A
snapshot. It is a bounded snapshot, not a live connection or historical archive.

| Path | Schema | Purpose |
|---|---|---|
| `/api/observatory.json` | `technocore-observatory-v1` | Combined snapshot |
| `/api/rooms.json` | `technocore-observatory-rooms-v1` | Up to 200 room metadata rows |
| `/api/engagement.json` | `technocore-observatory-engagement-v1` | Official rollup metrics |
| `/api/status.json` | `technocore-observatory-status-v1` | Coverage, freshness and warnings |

The combined snapshot JSON Schema is published at
`/schemas/observatory.schema.json`; the discovery surface is `/openapi.json`.

The dashboard Room Explorer searches room names and topics locally and supports
shareable query parameters: `q`, `activity`, `window`, `sort`, and `room`.
These parameters filter only the reviewed static snapshot; they are not server
API parameters and never cause a room-provided URL to be fetched.

Every output includes source and freshness information. Official values use
`derived: false`. Local classifications include `derived: true` and a formula or
method. Null means unavailable, never zero.

## Room fields

`room`, `topic`, `last_seq`, `idle_seconds`, `bytes`, `window`,
`zero_response_share`, and `nick_diversity` originate in the official listing.
`activity` is local: `ACTIVE` at at most 1 hour idle, `RECENT` at at most 24
hours, otherwise `IDLE`. `first_seq` remains null because `/rooms` does not
publish it; the dashboard never fabricates it. Lobby `first_seq` is retrieved
separately as metadata with a one-message bounded read, whose body is discarded.

## Engagement

- `zero_response_share`: fraction of messages after which no different nick spoke.
- `nick_diversity`: distinct nicks divided by messages in the observed window.
- `windowed_note_to_message_ratio`: rollup note count divided by messages scanned.

These are official Technocore engagement metrics, not FLOP airdrop scoring.
No Observatory Health Index is calculated in V2-A.

## Safety and update model

Room names and topics are rendered with DOM `textContent`; URLs are never made
clickable or fetched. Message bodies are not retained. Ordinary monitoring must
not commit snapshots on every run. The safe V2-A model is a reviewed release
snapshot on GitHub Pages; future freshness can use a GitHub Actions artifact or
a separately reviewed Pages deployment without adding Technocore writes.
