# Installation

Pick the install path that matches how you want to run scans. All release artifacts are signed and accompanied by SBOMs and attestations — see [Release verification](#release-verification).

## Homebrew

```bash
brew install --cask ramazankara/tap/kube-shield
```

Homebrew also installs shell completions automatically.

## Go

```bash
go install github.com/RamazanKara/kube-shield/cmd/kube-shield@latest
```

## Docker

```bash
docker run --rm \
  -v ~/.kube:/home/kubeshield/.kube:ro \
  ghcr.io/ramazankara/kube-shield:latest scan
```

Images are published to `ghcr.io/ramazankara/kube-shield` for `linux/amd64` and `linux/arm64`.

## Binary archives

Download Linux, macOS, and Windows archives from the [GitHub releases page](https://github.com/RamazanKara/kube-shield/releases). Each release includes checksums, SBOMs, and Sigstore signature bundles.

## Helm (in-cluster scheduled scans)

```bash
helm install kube-shield oci://ghcr.io/ramazankara/charts/kube-shield \
  --namespace kube-shield --create-namespace
```

See the [Helm chart README](https://github.com/RamazanKara/kube-shield/blob/main/deploy/helm/README.md) for values.

## Release verification

Install `gh` (with attestation support) and `cosign`, then verify a release:

```bash
gh release download v1.0.5 --repo RamazanKara/kube-shield \
  --pattern checksums.txt \
  --pattern checksums.txt.sigstore \
  --pattern kube-shield_1.0.5_linux_amd64.tar.gz

gh attestation verify kube-shield_1.0.5_linux_amd64.tar.gz --repo RamazanKara/kube-shield

cosign verify-blob --bundle checksums.txt.sigstore \
  --certificate-identity-regexp 'https://github.com/RamazanKara/kube-shield/.github/workflows/release.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
```

## Next steps

Continue to the [Quick start](quickstart.md).
