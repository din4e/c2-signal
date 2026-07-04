# Public release checklist

- [x] Select and add an OSI-approved project license (MIT).
- [ ] Replace placeholder security-reporting instructions with an enabled private reporting channel.
- [ ] Confirm repository owner, copyright holder and project contact.
- [ ] Run `make test`.
- [ ] Run a clean Docker build with no local layer cache.
- [ ] Start once without `rulesets/` and once after `make rules`.
- [ ] Verify upload, history, deletion, YARA management and rule-source viewing.
- [ ] Run a secret scanner over the Git history and working tree.
- [ ] Review all third-party licenses and pinned revisions.
- [ ] Confirm no samples, scan history, local rule edits or generated files are committed.
- [ ] Add release tags and image publishing only after provenance/signing policy is decided.
