# Changelog

All notable changes to kube-shield are tracked here.

## Unreleased

- Restructures the repository to the conventional Go CLI layout: the entrypoint moves to `cmd/kube-shield/`, application packages move from `pkg/` to `internal/`, and the docs generator moves to `internal/tools/`. **Install with `go install github.com/RamazanKara/kube-shield/cmd/kube-shield@latest`.** The former `pkg/` packages are now internal and are no longer importable as a library. The CLI, flags, output, and container/Helm usage are unchanged.
- Reorganizes documentation into an audience-based structure and publishes a MkDocs Material site to GitHub Pages at https://ramazankara.github.io/kube-shield/.
- Adds CI/CD integration, recipes, troubleshooting, FAQ, CLI reference, and configuration reference documentation, plus an `examples/` directory with a sample config, suppressions file, and GitHub Actions, GitLab CI, and Jenkins snippets.
- Fixes stale documentation (release signature extension, pinned example versions, Helm chart version) and adds a Helm chart README.

## v1.0.5 - 2026-06-28

- Hardens supply-chain posture for a higher OpenSSF Scorecard: adds a CodeQL SAST workflow, scopes GitHub Actions token permissions to the job level (least privilege), pins Docker base images by digest, and fixes the Scorecard results upload.
- Renames release signature bundles from `.sigstore.json` to `.sigstore` so OpenSSF Scorecard recognizes signed release artifacts. The `cosign verify-blob --bundle` workflow is unchanged apart from the file name.

## v1.0.4 - 2026-06-28

- Recovers from scanner panics so one faulty scanner degrades to a partial result instead of crashing the whole scan, and reports nil scanner results as scanner errors.
- Fixes a deduplication edge case where finding titles with whitespace around a `/` produced an untrimmed target key (found by fuzzing).
- Adds Go native fuzz tests for finding fingerprinting, deduplication title parsing, and suppression parsing, with a committed regression corpus.
- Documents shell completion setup for bash, zsh, fish, and PowerShell.
- Extracts the scoring penalty weights into named constants for readability.

## v1.0.3 - 2026-06-27

- Adds rule catalog metadata, generated scanner docs, and `kube-shield rules list/show` for auditable finding rationale, confidence, data access, standards, and references.
- Adds deterministic finding fingerprints and expiring suppressions with JSON/SARIF audit output.
- Hardens secret handling so default secret scans use metadata-only Secret inventory; `SEC-010` now requires explicit `--read-secret-data`.
- Raises CI coverage gating to 80%, adds Dependabot and OpenSSF Scorecard, and pins GitHub Actions to immutable SHAs where practical.
- Adds a threat model covering Kubernetes API access, Secret handling, AI data egress, suppressions, release integrity, and non-goals.
- Removes overclaimed graph/remediation surfaces, adds de-duplicated scoring for known CIS/core overlaps, and pins Go to the patched 1.25.11 toolchain.
- Refines README, support, security, contributor, release, architecture, scanner, and development docs for first-time readers and maintainers.
- Adds a reproducible README TUI demo animation and documents how to regenerate it.
- Clarifies release verification, scanner severity documentation, and repository maintenance guidance.

## v1.0.1 - 2026-05-24

- Updates vulnerable `golang.org/x/net` dependency family after `govulncheck` found reachable issues.
- Refreshes CI action pins and runs gosec directly at a pinned version.
- Updates the local Docker runtime image path to Alpine 3.23 while keeping the Go 1.25 release toolchain.
- Fixes scanner/reporting bugs around filtered summaries, partial scanner failures, NetworkPolicy default-deny detection, secret references, and narrow TUI rendering.

## v1.0.0 - 2026-05-23

- First open-source-ready release.
- Adds five scanner families: workload, CIS, RBAC, network policy, and secrets.
- Adds interactive TUI dashboard, JSON/table/SARIF output, AI explanations, Docker image, Helm chart, and GoReleaser binary artifacts.
- Adds release signing, SBOMs, GHCR images, Helm OCI publishing, Homebrew cask publishing, and GitHub artifact attestations.

## v0.1.0

- Initial project release.
