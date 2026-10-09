# Installation

Build this checkout with `make build`, then run `./bin/kube-shield version`. Go 1.26.9 is the pinned toolchain. On Windows, the binary is `bin/kube-shield.exe`; run `.\bin\kube-shield.exe version` from PowerShell.

The release-channel commands below require published artifacts. Homebrew, container execution, signatures, and attestations were not verified in this maintenance pass; check the selected release before installing.

## Homebrew

```bash
brew install --cask ramazankara/tap/kube-shield
```

## Go

```bash
go install github.com/RamazanKara/kube-shield/v2/cmd/kube-shield@latest
```

## Docker

```bash
docker run --rm \
  -v "$HOME/.kube:/kube:ro" \
  ghcr.io/ramazankara/kube-shield:latest scan --kubeconfig /kube/config
```

The release workflow is configured to publish images to `ghcr.io/ramazankara/kube-shield` for `linux/amd64` and `linux/arm64`.

## Binary archives

Download Linux, macOS, and Windows archives from the [GitHub releases page](https://github.com/RamazanKara/kube-shield/releases). Check the selected release for checksums, SBOMs, and Sigstore signature bundles.

## Helm (in-cluster scheduled scans)

```bash
helm install kube-shield oci://ghcr.io/ramazankara/charts/kube-shield \
  --namespace kube-shield --create-namespace
```

See the [Helm chart README](https://github.com/RamazanKara/kube-shield/blob/main/deploy/helm/README.md) for values.

## Release verification

Install `gh` (with attestation support) and `cosign`, then verify a release:

```bash
gh release download v2.0.0 --repo RamazanKara/kube-shield \
  --pattern checksums.txt \
  --pattern checksums.txt.sigstore \
  --pattern kube-shield_2.0.0_linux_amd64.tar.gz

gh attestation verify kube-shield_2.0.0_linux_amd64.tar.gz --repo RamazanKara/kube-shield

cosign verify-blob --bundle checksums.txt.sigstore \
  --certificate-identity-regexp 'https://github.com/RamazanKara/kube-shield/.github/workflows/release.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
```

## Next steps

Continue to the [Quick start](quickstart.md).
