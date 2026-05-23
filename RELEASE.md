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

## Publishing v1.0.0

The original `v1.0.0` tag did not create a GitHub release. After merging the release-readiness PR:

```shell
git fetch origin main --tags
git switch main
git pull --ff-only
git tag -f v1.0.0
git push --force origin refs/tags/v1.0.0
```

If a public `v1.0.0` release exists before this step, do not force-move the tag. Release `v1.0.1` instead.

## Post-release Verification

```shell
gh release view v1.0.0 --repo RamazanKara/kube-shield
gh release download v1.0.0 --repo RamazanKara/kube-shield --pattern checksums.txt
gh attestation verify checksums.txt --repo RamazanKara/kube-shield
cosign verify-blob --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp 'https://github.com/RamazanKara/kube-shield/.github/workflows/release.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
docker pull ghcr.io/ramazankara/kube-shield:v1.0.0
helm install kube-shield oci://ghcr.io/ramazankara/charts/kube-shield --version 1.0.0
brew install --cask ramazankara/tap/kube-shield
```

Verify that the GitHub release contains archives, checksums, `.sigstore.json` files, and `.sbom.json` files for release artifacts.
