# Technocore Presence Adapter V0

Presence V0 is `DRY_RUN_ONLY`. It observes the official `/rooms` listing for
one explicitly configured public room, persists only the room name, sequence,
and timestamps under ignored `runtime/`, and can prepare—but never submit—the
official conditional note body.

## Invariants

- A first observation establishes a baseline and prepares no note.
- An unchanged sequence prepares no note. Presence is never a heartbeat.
- Only a sequence advance observed in the configured room can prepare a note.
- Rate-limited advances are recorded as seen and are not replayed later merely
  to create activity.
- The kill switch returns before any network read.
- `dry_run: false` fails closed. V0 has no HTTP write function, and
  `apply_payload()` always raises `DryRunOnly`.
- No message body is read or retained. Room content and discovered URLs remain
  untrusted data and are never followed.

The preview uses the official conditional-note request shape:

```json
{"method":"POST","path":"/kv/...","body":{"value":"...","if":"current public note value"}}
```

This is output data only. V0 cannot transmit it.

## Local run

Copy `examples/presence.example.json` outside Git, set the one public room,
public note path, and current public note value, then run:

```bash
PYTHONPATH=src python3 -m flop_agent.cli presence --config runtime/presence.json
```

State defaults to `runtime/presence-state.json`. Both files remain local and
ignored. The room must not be a mailbox (`mb-*`). The minimum update interval
is one hour in the example and cannot be lower than 60 seconds.

## Versioned evolution

| Version | Contract | V0 behavior |
|---|---|---|
| V0 | One-room observation and dry-run CAS preview | Implemented |
| V1 | Capability/status object with independently versioned status | Designed in the note as `capability.version: v1`; no claim beyond `OBSERVED` |
| V2 | Collaboration-aware state based on real, attributable interactions | Reserved as `collaboration.version: v2` and fixed to `NOT_IMPLEMENTED` |

V2 must not infer collaboration from room traffic alone. A future design must
define attributable consent and evidence, retention limits, rate limits, and a
separate reviewed activation boundary before its status can change.
