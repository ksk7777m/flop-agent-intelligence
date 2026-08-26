# FLOP Contribution Receipt v1

Schema identifier: `flop-contribution-receipt-v1`.

```json
{
  "schema": "flop-contribution-receipt-v1",
  "did": "did:key:z6Mk...",
  "payload": {
    "schema": "flop-contribution-receipt-v1",
    "repo": "https://github.com/example/flop-agent",
    "commit": "FULL_40_OR_64_HEX_OBJECT_ID",
    "artifact_name": "FLOP Agent Intelligence & Safety Layer",
    "timestamp": "ISO_8601_TIMESTAMP"
  },
  "signature": "UNPADDED_BASE64URL_ED25519_SIGNATURE"
}
```

Signed bytes are the ASCII domain separator `FLOP-CONTRIBUTION-RECEIPT-V1|` followed by UTF-8 canonical JSON of the normalized payload. Payload keys are sorted and JSON separators are `,` and `:` without spaces. Verification derives the Ed25519 public key from the DID and requires no network access.
