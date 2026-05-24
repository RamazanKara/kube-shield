# Release Process

kube-shield releases publish:

- GitHub release archives for Linux, macOS, and Windows.
- `checksums.txt`, SBOMs, and Sigstore signature bundles.
- GitHub artifact attestations.
- GHCR container images tagged as `vX.Y.Z`, `X.Y.Z`, and `latest`.
- Helm OCI chart at `oci://ghcr.io/ramazankara/charts/kube-shield`.
- Homebrew cask in `RamazanKara/homebrew-tap`.

Public release tags are immutable. If a release is already public, ship follow-up fixes as the next patch version.

## Prerequisites

- `HOMEBREW_TAP_TOKEN` repository secret with write access to `RamazanKara/homebrew-tap`.
- GitHub Actions permissions for `contents`, `packages`, `id-token`, and `attestations`.
- Public GHCR packages for the image and chart after first publication.
- Branch protection or rulesets for `main` with CI, E2E, and release dry-run required.
- Local tools for dry-runs: Go, Docker, Helm, GoReleaser, Syft, and golangci-lint.

## Version Prep

Choose the next version:

```shell
VERSION=1.0.2
TAG="v${VERSION}"
```

Update versioned files before tagging:

- `deploy/helm/Chart.yaml`: `version` and `appVersion`.
- `CHANGELOG.md`: add the release date and user-facing changes.
- README examples when the latest published version changes.
- Any scanner counts or check severities if scanner behavior changed.

## Required Checks

Run these before pushing a tag:

```shell
go test ./...
go test -race ./...
go vet ./...
golangci-lint run ./...
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
go run github.com/securego/gosec/v2/cmd/gosec@v2.26.1 ./...
go test -race -coverprofile=coverage.out ./...
go tool cover -func=coverage.out | tail -n 1
goreleaser check
goreleaser release --snapshot --clean --skip=publish,sign
docker build -f Dockerfile -t kube-shield:release-check .
docker run --rm kube-shield:release-check version
helm lint deploy/helm
helm template kube-shield deploy/helm
make test-e2e
```

The release dry-run workflow validates snapshot packaging in GitHub Actions. Local GoReleaser checks skip signing because keyless signing and attestations require GitHub OIDC.

## Publish

```shell
git fetch origin main --tags
git switch main
git pull --ff-only
git status --short
git tag "${TAG}"
git push origin "refs/tags/${TAG}"
```

Watch the workflow:

```shell
gh run list --repo RamazanKara/kube-shield --workflow Release --limit 5
gh run watch <run-id> --repo RamazanKara/kube-shield --exit-status
```

## Post-release Verification

Replace `1.0.2` with the published version:

```shell
VERSION=1.0.2
TAG="v${VERSION}"

gh release view "${TAG}" --repo RamazanKara/kube-shield
gh release download "${TAG}" --repo RamazanKara/kube-shield \
  --pattern checksums.txt \
  --pattern checksums.txt.sigstore.json \
  --pattern "kube-shield_${VERSION}_linux_amd64.tar.gz"

gh attestation verify "kube-shield_${VERSION}_linux_amd64.tar.gz" \
  --repo RamazanKara/kube-shield

cosign verify-blob --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp 'https://github.com/RamazanKara/kube-shield/.github/workflows/release.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt

docker pull "ghcr.io/ramazankara/kube-shield:${TAG}"
docker pull "ghcr.io/ramazankara/kube-shield:${VERSION}"
docker pull ghcr.io/ramazankara/kube-shield:latest
docker run --rm "ghcr.io/ramazankara/kube-shield:${TAG}" version

cosign verify "ghcr.io/ramazankara/kube-shield:${TAG}" \
  --certificate-identity-regexp 'https://github.com/RamazanKara/kube-shield/.github/workflows/release.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

helm show chart "oci://ghcr.io/ramazankara/charts/kube-shield" --version "${VERSION}"
brew install --cask ramazankara/tap/kube-shield
```

Confirm the GitHub release contains archives, checksums, `.sbom.json` files, `.sigstore.json` files, and attestations for the release artifacts.
