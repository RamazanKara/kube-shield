# Changelog

All notable changes to kube-shield are tracked here.

## Unreleased

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
- Adds interactive TUI dashboard, JSON/table/SARIF output, AI remediation support, Docker image, Helm chart, and GoReleaser binary artifacts.
- Adds release signing, SBOMs, GHCR images, Helm OCI publishing, Homebrew cask publishing, and GitHub artifact attestations.

## v0.1.0

- Initial project release.
