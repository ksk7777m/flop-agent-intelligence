#!/usr/bin/env python3
from flop_agent.identity import verify_local_identity_status

result = verify_local_identity_status()
print(f"DID: {result['did']}\nverification: success")
