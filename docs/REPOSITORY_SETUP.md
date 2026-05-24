# Repository Operations Checklist

Use this checklist when reviewing repository settings, onboarding maintainers, or preparing a new release line.

## Repository Metadata

- Description: `Kubernetes Security Posture Manager - k9s for security`.
- Website: the README or latest GitHub release URL.
- Visibility: public.
- License: Apache-2.0.
- Topics:
  - `cis-benchmark`
  - `cli`
  - `cloud-native`
  - `devsecops`
  - `golang`
  - `helm`
  - `kubernetes`
  - `kubernetes-security`
  - `network-policy`
  - `rbac`
  - `sarif`
  - `sbom`
  - `secrets-scanning`
  - `security`
  - `sigstore`

## Branch Protection

Protect `main` with:

- Pull request required before merge.
- At least one approving review.
- Required checks:
  - CI
  - E2E Tests
  - Release Dry Run
- Branches must be up to date before merge.
- Block force pushes and branch deletion.
- Restrict bypass permissions to maintainers.

## Security Settings

- Enable GitHub private vulnerability reporting.
- Enable Dependabot security updates.
- Enable Dependabot version updates from `.github/dependabot.yml`.
- Enable secret scanning and push protection.
- Review CodeQL or equivalent static analysis if the project expands beyond Go.

## Repository Secrets

- `CODECOV_TOKEN`, if Codecov upload remains enabled.
- `HOMEBREW_TAP_TOKEN`, with content write access to `RamazanKara/homebrew-tap`.

The release workflow uses `GITHUB_TOKEN` for GitHub releases, GHCR packages, OIDC signing, and attestations.

## Packages

After each release:

- GHCR image package `ghcr.io/ramazankara/kube-shield` is public.
- GHCR chart package `ghcr.io/ramazankara/charts/kube-shield` is public.
- Tags `vX.Y.Z`, `X.Y.Z`, and `latest` point at the expected image digest.
- Helm chart version and appVersion match the release version.

## Release Validation

For the latest release:

- GitHub release is published, not draft or prerelease unless intentionally marked.
- Release contains archives for Linux, macOS, and Windows on amd64/arm64.
- Release contains `checksums.txt`.
- Release contains `.sbom.json` files.
- Release contains `.sigstore.json` signature bundles.
- GitHub artifact attestations verify.
- GHCR image pulls on amd64 and arm64.
- Helm OCI chart resolves and installs.
- Homebrew cask points at the latest version.

## Periodic Maintenance

- Review open Dependabot PRs weekly.
- Run `govulncheck` after dependency updates.
- Keep GitHub Actions pins current with maintained Node runtimes.
- Confirm release tooling versions in `.github/scripts/install-release-tools.sh`.
- Review README install commands after each release.
- Keep [SCANNERS.md](SCANNERS.md) aligned with scanner code and tests.
