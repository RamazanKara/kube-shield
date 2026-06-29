# Release Process

This runbook is for maintainers publishing a new kube-shield version. It covers the human checks around the automated release workflow.

Each release publishes:

- GitHub release archives for Linux, macOS, and Windows.
- `checksums.txt`, SBOMs, and Sigstore signature bundles.
- GitHub artifact attestations.
- GHCR container images tagged as `vX.Y.Z`, `X.Y.Z`, and `latest`.
- Helm OCI chart at `oci://ghcr.io/ramazankara/charts/kube-shield`.
- Homebrew cask in `RamazanKara/homebrew-tap`.

Public release tags are immutable. If a release is already public, ship follow-up fixes as the next patch version.

## Release Principles

- Keep scanner behavior, check IDs, output schemas, and exit-code behavior stable within a release line.
- Prefer a patch release over rewriting any tag that already has a public GitHub release.
- Run local packaging checks before pushing a tag; let GitHub Actions handle keyless signing and attestations.
- Verify every install channel after the workflow succeeds.

## Prerequisites

- `HOMEBREW_TAP_TOKEN` repository secret with write access to `RamazanKara/homebrew-tap`.
- GitHub Actions permissions for `contents`, `packages`, `id-token`, and `attestations`.
- Public GHCR packages for the image and chart after first publication.
- Branch protection or rulesets for `main` with CI, E2E, and release dry-run required.
- Local tools for dry-runs: Go, Docker, Helm, GoReleaser, Syft, and golangci-lint.

## Version Prep

Choose the next version (replace `X.Y.Z` with the actual release version):

```shell
VERSION=X.Y.Z
TAG="v${VERSION}"
```

Update versioned files before tagging:

- `deploy/helm/Chart.yaml`: `version` and `appVersion`.
- `CHANGELOG.md`: move user-facing changes from `Unreleased` under the new version and date.
- Generated scanner docs: run `go generate ./...` after any rule catalog changes.
- README install, Docker, Helm, and verification examples when the latest published version changes.
- Any scanner counts or check severities if scanner behavior changed.

Before tagging, confirm `main` contains only changes intended for the release:

```shell
git fetch origin main --tags
git switch main
git pull --ff-only
git status --short
git log --oneline -5
```

## Required Checks

Run these before pushing a tag:

```shell
go test ./...
go test -race ./...
go vet ./...
golangci-lint run ./...
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
go run github.com/securego/gosec/v2/cmd/gosec@v2.26.1 ./...
go generate ./...
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

## Publish The Tag

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

These mirror the user-facing commands in the README's "Release Verification" section, parameterized for maintainers. Replace `X.Y.Z` with the published version:

```shell
VERSION=X.Y.Z
TAG="v${VERSION}"

gh release view "${TAG}" --repo RamazanKara/kube-shield
gh release download "${TAG}" --repo RamazanKara/kube-shield \
  --pattern checksums.txt \
  --pattern checksums.txt.sigstore \
  --pattern "kube-shield_${VERSION}_linux_amd64.tar.gz"

gh attestation verify "kube-shield_${VERSION}_linux_amd64.tar.gz" \
  --repo RamazanKara/kube-shield

cosign verify-blob --bundle checksums.txt.sigstore \
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

Confirm the GitHub release contains archives, checksums, `.sbom.json` files, `.sigstore` files, and attestations for the release artifacts.

## If Something Fails

- If the tag exists but no public GitHub release was created, fix `main`, move the tag to the fixed commit, and push the tag again.
- If a public GitHub release exists, do not rewrite the tag. Ship a new patch version.
- If Homebrew publishing fails after the GitHub release succeeds, fix the tap publishing issue and rerun the release workflow only after confirming artifact digests remain unchanged.
- If signing or attestation fails, treat the release as incomplete until verification commands pass.
