# Contributing

## Development workflow

1. Create a focused branch.
2. Keep third-party rule repositories out of commits; `rulesets/` is ignored.
3. Run backend tests and the production frontend build.
4. Explain detection assumptions, false-positive risk and verification evidence in the pull request.

```bash
cd backend && go test ./...
cd ../frontend && npm ci && npm run build
```

## Detection content

New detection rules must include:

- author and description metadata;
- source and license provenance;
- the artifact types the rule is intended for;
- a safe positive test or reproducible generation method;
- known false-positive conditions.

Do not submit live malware, stolen data, credentials or rules copied from sources that do not permit redistribution.

## Code expectations

- Preserve the strict format router: YARA for artifacts, Sigma for EVTX and Suricata for packet captures.
- Do not execute uploaded artifacts.
- Treat filenames and rule names as untrusted input.
- Keep collection fields as JSON arrays, including while jobs are running.
- Add regression tests for security-sensitive path, upload and persistence changes.

## Commit scope

Generated directories (`node_modules`, `.next`, `out`) and downloaded rule repositories must not be committed.
