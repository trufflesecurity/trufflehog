---
name: dep-updates
description: Plan and apply Go dependency updates, including advisory-driven bumps, Trivy/govulncheck validation, and supply-chain review. Use when the user asks to update dependencies, refresh modules for security alerts, or run dependency vulnerability scans.
---

# Dependency updates

Use this skill when the user wants to **update dependencies** in this repo—whether driven by security advisories, Dependabot, or general maintenance.

This repository is primarily **Go** (`go.mod` / `go.sum`). There is no root Node workspace; follow the Go workflow below.

**Project convention:** Do **not** create or maintain `docs/vuln-residual-risk.md` (or similar residual-risk documents) unless the user explicitly asks. Summarize anything still open in the PR description or chat instead.

## Quick Start

1. Run Trivy from the project root as a container, not a locally installed binary:

```bash
docker run --rm -v "$PWD:/src" -w /src aquasec/trivy@sha256:bcc376de8d77cfe086a917230e818dc9f8528e3c852f7b1aff648949b6258d1c fs --scanners vuln .
```

2. Optionally supplement with Go’s official checker (reports module vulnerabilities from the Go vulnerability database):

```bash
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...
```

3. Use `gh` against the upstream repo when helpful, for example Dependabot security alerts:

```bash
gh api repos/trufflesecurity/trufflehog/dependabot/alerts --paginate
```

4. Triage each finding as:
- `Actionable`: a fixed version exists and the current constraint allows, or can be relaxed to allow, the update.
- `Blocked`: a fix exists, but taking it would require a major-version bump in a sibling dependency or a broader refactor the user did not ask for.
- `No fix available`: upstream has not published a patched release.

5. Apply module updates, rerun the scans, and note remaining gaps in the PR or response (not in a standing residual-risk doc).

## Triage notes

- For Dependabot or advisory-driven work, note the affected module, vulnerable version range, fixed version, and exploit conditions called out in the advisory.
- Check whether this repo is actually affected: look for imports, direct usage of the vulnerable APIs or code paths, and any required configuration, input shape, or runtime exposure described in the alert.
- Verify that any advisory-listed "fixed version" actually exists upstream before planning around it; scanners can report versions that are not yet published.
- For each incoming dependency update, spawn a sub-agent to inspect the new version for malicious or suspicious supply-chain changes before you adopt it.
- Have the sub-agent review release notes and the module diff for typosquat signals, maintainer churn, unexpected build tags or generated code, obfuscated code, unexpected network or process behavior, credential or filesystem access, and unexplained new transitive dependencies.
- Use sub-agents for per-package advisory and diff review, but keep `go.mod` / `go.sum` edits in a single coordinating agent.
- Even if the alert appears non-exploitable here, still take the patch when the upgrade is reasonable and low risk.
- If something cannot be upgraded yet, explain why in the PR or chat (upstream tag missing, incompatible API, etc.); do not create standing residual-risk documentation files unless the user asks.

## Go workflow

Use this path for findings in `go.mod` or `go.sum`.

- Prefer targeted upgrades: `go get example.com/module@vX.Y.Z` (or a compatible minor/patch as appropriate).
- After changes, run `go mod tidy` from the project root.
- Never edit `go.sum` manually; it is generated.
- Run `make lint` (or `./scripts/lint.sh`) to match CI’s golangci-lint configuration.
- Run tests appropriate to what changed. Broad checks often use:
  - `make test` for the default unit test sweep, or
  - `go test -timeout 30s -tags "integration detectors" ./...` when exercising integration and detector-tagged packages (narrow the path when only specific packages changed).
- Use `make test-integration` or `make test-detectors` when the change touches integration-only or detector code paths.

## Validation

After making updates:

1. Re-run the same Trivy container command from the project root and confirm the vulnerability count decreased or the actionable findings were removed.
2. Re-run `govulncheck ./...` if you use it in this pass.
3. Run `make lint` and the relevant `go test` / `make test*` targets for the areas you touched.

## Execution notes

- Do not install Trivy locally as part of this workflow; use the containerized command.
- Never edit `go.sum` manually; regenerate with `go mod tidy` after `go get` / `go mod` changes.
- Do not create commits unless the user explicitly asks for them.
- Use sub-agents wherever practical for read-only research and independent validation; keep `go.mod` and `go.sum` edits under one coordinating agent.
- Include the analysis in the PR description: what the alert or upgrade was, how you checked impact, what the supply-chain review found, and what you changed.
- Follow nearby project conventions and add tests when dependency updates require behavioral changes.
