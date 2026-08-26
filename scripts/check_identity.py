#!/usr/bin/env python3
from pathlib import Path
from flop_agent.identity import load_identity, sign_message, verify_message

root = Path(__file__).resolve().parents[1]
key, did = load_identity(root / "secrets/agent_identity.json")
signature, text = sign_message(key, "local-check", 1, "identity verification")
verify_message(did, signature, "local-check", 1, text)
print(f"DID: {did}\nverification: success")

