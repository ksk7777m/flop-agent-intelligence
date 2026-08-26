# Publication Checklist

- [ ] Create an empty public repository manually.
- [ ] Confirm `secrets/`, `.env*`, `receipts/`, key formats, caches and `.DS_Store` remain ignored.
- [ ] Run `PYTHONPATH=src python3 -m unittest discover -s tests -v`.
- [ ] Run `python3 scripts/public_readiness.py`.
- [ ] Run a second external scanner if available, such as `gitleaks detect --no-git`.
- [ ] Review `git status --short`, `git diff --cached`, and `git ls-files` before push.
- [ ] Confirm no personal paths, shell history, cookies, tokens or private identity material are staged.
- [ ] Push only after human review.
- [ ] Record the exact public commit and then generate the DID contribution receipt.
- [ ] Verify the receipt offline before any public announcement.
- [ ] Keep Technocore and X drafts pending separate human approval.
