# Architecture

```text
Configured Official Sources
            |
            v
      Source Policy  ---- rejects authority learned from content
            |
            v
        Classifier   ---- CRITICAL / ACTION / INFO / IGNORE
            |
            v
       Safety Layer  ---- SECURITY_REVIEW_REQUIRED / quarantine
            |
            v
       Evidence Store ---- source hash, summary, classification
            |
            v
       Human Approval ---- REVIEW_REQUIRED / APPROVED / REJECTED
            |
            v
  Structured Signer Handoff
            |
            v
 Claude or Local Attested Signer ---- separate private-key boundary
            |
            v
 Technocore / Future Official Actions ---- never automatic
```

The source/classification process has no publishing capability. `workflow.signer_handoff` emits a JSON-compatible object only after approval and performs no signing or network request. Existing local Technocore signing remains separate. Claude Connector integration is an interface contract, not an in-process dependency.

The contribution receipt is separate from transport. It signs a domain-separated canonical payload and verifies entirely offline from the public DID.

