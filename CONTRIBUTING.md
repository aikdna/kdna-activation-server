# Contributing to KDNA

## Issues

Open an issue at the repository. Include:
- Node.js version and the exact package/dependency coordinates
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
   - `npm run check:public-surface` passes
   - For asset or binding changes: include SHA256 and the exact current
     Core/Read observation, with synthetic data and explicit scope

PRs that fail any verification command will be reviewed with requested changes.

## Developer Certificate of Origin (DCO)

All commits must include a `Signed-off-by:` line. Use `git commit -s` to add it automatically.

This certifies that you wrote the code or have the right to submit it under the project's license (Apache-2.0). No CLA is required.

## Repository scope

This repository is the activation server component. KDNA CLI commands live in
the separate `kdna-cli` repository; do not add CLI shims or command
implementations here.

The current CLI source supports explicit-file `inspect`, `validate` and `read`.
Its separate README and exact dependency binding are authoritative; do not
restore installation, registry or legacy loading commands in this observer.
Published CLI releases retain their own versioned command contracts.

The whole KDNA ecosystem is pre-release. This observer's exact current package
coordinate is in `package.json` and `public-contract-binding.json`; source
availability does not establish a registry release, Beta, stable or GA status.

## Current observer validation

Use `npm test`, `npm run lint`, `npm run check:public-surface` and `npm pack --ignore-scripts --dry-run --json` for this candidate. The current package has no CLI or HTTP server entry; historical tests are retained separately. New identity semantics or production trust deployment require a separate explicit decision.
