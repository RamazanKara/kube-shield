# Release Process

This project publishes signed binaries, checksums, SBOMs, container images, a Helm OCI chart, and a Homebrew cask.

## Prerequisites

- Repository secret `HOMEBREW_TAP_TOKEN` with write access to `RamazanKara/homebrew-tap`.
- GitHub Actions permissions enabled for OIDC, packages, and attestations.
- `main` is protected with required CI, E2E, and release dry-run checks.
- GHCR package visibility is public after the first release.

## Local Release Checks

```shell
go test ./...
go test -race ./...
go vet ./...
golangci-lint run ./...
goreleaser check
goreleaser release --snapshot --clean --skip=publish,sign
helm lint deploy/helm
helm template kube-shield deploy/helm
```

The `Release Dry Run` workflow runs the snapshot check with keyless signing enabled through GitHub OIDC. Local checks skip signing because developer machines usually do not have that OIDC context.

## Publishing v1.0.1

`v1.0.0` is already public. Publish follow-up fixes as `v1.0.1`:

```shell
git fetch origin main --tags
git switch main
git pull --ff-only
git tag v1.0.1
git push origin refs/tags/v1.0.1
```

Do not rewrite public release tags.

## Post-release Verification

```shell
gh release view v1.0.1 --repo RamazanKara/kube-shield
gh release download v1.0.1 --repo RamazanKara/kube-shield \
  --pattern checksums.txt \
  --pattern checksums.txt.sigstore.json \
  --pattern kube-shield_1.0.1_linux_amd64.tar.gz
gh attestation verify kube-shield_1.0.1_linux_amd64.tar.gz --repo RamazanKara/kube-shield
cosign verify-blob --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp 'https://github.com/RamazanKara/kube-shield/.github/workflows/release.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
docker pull ghcr.io/ramazankara/kube-shield:v1.0.1
helm install kube-shield oci://ghcr.io/ramazankara/charts/kube-shield --version 1.0.1
brew install --cask ramazankara/tap/kube-shield
```

Verify that the GitHub release contains archives, checksums, `.sigstore.json` files, and `.sbom.json` files for release artifacts.
