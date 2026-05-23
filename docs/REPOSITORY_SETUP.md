# Repository Setup Checklist

Use this checklist before publishing `v1.0.0`.

## Metadata

- Description: `Kubernetes Security Posture Manager - k9s for security`
- Website: GitHub releases or README URL
- Topics: `kubernetes`, `security`, `k8s`, `cis-benchmark`, `rbac`, `network-policy`, `secrets`, `sarif`, `devsecops`
- Visibility: public
- Private vulnerability reporting: enabled

## Branch Protection

Protect `main` with:

- Pull request required before merge.
- Required approvals: at least 1.
- Required checks: `CI`, `E2E Tests`, and `Release Dry Run`.
- Require branches to be up to date before merge.
- Block force pushes and deletions.

## Secrets

- `CODECOV_TOKEN` for coverage upload, if Codecov remains enabled.
- `HOMEBREW_TAP_TOKEN` with content write access to `RamazanKara/homebrew-tap`.

## Packages

- GHCR image package `ghcr.io/ramazankara/kube-shield` is public.
- GHCR chart package `ghcr.io/ramazankara/charts/kube-shield` is public.

## Release Validation

- `v1.0.0` GitHub release exists.
- Release artifacts include checksums, SBOMs, signatures, and attestations.
- Container tags `v1.0.0`, `1.0.0`, and `latest` pull successfully.
- Helm OCI chart installs successfully.
- Homebrew cask installs successfully.
