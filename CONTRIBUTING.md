# Contributing to KDNA

## Issues

Open an issue at the repository. Include:
- `kdna version` output
- OS and shell
- Minimal reproduction steps
- Expected vs actual behavior

If proposing a feature, tag with `[RFC]` and describe the problem before the solution.

## Pull Requests

1. Fork and branch from `main`.
2. Keep PRs focused — one logical change per PR.
3. All commits must be signed off: `git commit -s`
4. Use the PR template. Title format: `area: what changed`.
5. Verify before opening:
   - `npm test` passes
   - `npm run lint` passes (if available)
   - `kdna validate` works against a test .kdna file
   - For CLI changes: verify `kdna --help` output is correct
   - For asset changes: include SHA256 and validation output

PRs that fail any verification command will be reviewed with requested changes.

## Developer Certificate of Origin (DCO)

All commits must include a `Signed-off-by:` line. Use `git commit -s` to add it automatically.

This certifies that you wrote the code or have the right to submit it under the project's license (Apache-2.0). No CLA is required.

## Repository scope

This repository is the activation server component. KDNA CLI commands live in
the separate `kdna-cli` repository; do not add CLI shims or command
implementations here.

Notes on the current CLI surface (the `kdna-cli` source is authoritative):

- `install`, `registry`, `setup`, `validate`, and `version` are live commands.
- Registry resolution requires an explicit `KDNA_REGISTRY_URL`; there is no
  default public registry.
- There is no `kdna create` command. Do not reference one in docs, examples,
  or PR text.

The whole KDNA ecosystem is pre-release. No component — including this server,
currently 0.3.0-rc.current-observer.2 — is Beta, stable, or GA. Do not describe any version line as
"the public stable line" in code, docs, or PR text.

## Current observer validation

Use `npm test`, `npm run lint`, `npm run check:public-surface` and `npm pack --ignore-scripts --dry-run --json` for this candidate. The current package has no CLI or HTTP server entry; historical tests are retained separately. New identity semantics or production trust deployment require a separate explicit decision.
