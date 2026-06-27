# Changelog

All notable changes to kube-shield are tracked here.

## Unreleased

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
