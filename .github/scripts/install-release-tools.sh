#!/usr/bin/env bash
set -euo pipefail

GORELEASER_VERSION="${GORELEASER_VERSION:-v2.15.4}"
COSIGN_VERSION="${COSIGN_VERSION:-v3.0.6}"
SYFT_VERSION="${SYFT_VERSION:-v1.44.0}"
HELM_VERSION="${HELM_VERSION:-v3.21.0}"
INSTALL_BIN_DIR="${INSTALL_BIN_DIR:-/usr/local/bin}"
export PATH="${INSTALL_BIN_DIR}:${PATH}"

tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT

install_tool() {
  local source="$1"
  local name="$2"

  mkdir -p "${INSTALL_BIN_DIR}" 2>/dev/null || true
  if [ -w "${INSTALL_BIN_DIR}" ]; then
    install -m 0755 "${source}" "${INSTALL_BIN_DIR}/${name}"
  else
    sudo install -m 0755 "${source}" "${INSTALL_BIN_DIR}/${name}"
  fi
}

gh release download "${GORELEASER_VERSION}" \
  --repo goreleaser/goreleaser \
  --pattern goreleaser_Linux_x86_64.tar.gz \
  --dir "${tmpdir}"
tar -xzf "${tmpdir}/goreleaser_Linux_x86_64.tar.gz" -C "${tmpdir}"
install_tool "${tmpdir}/goreleaser" goreleaser

gh release download "${COSIGN_VERSION}" \
  --repo sigstore/cosign \
  --pattern cosign-linux-amd64 \
  --output "${tmpdir}/cosign"
install_tool "${tmpdir}/cosign" cosign

gh release download "${SYFT_VERSION}" \
  --repo anchore/syft \
  --pattern "syft_*_linux_amd64.tar.gz" \
  --dir "${tmpdir}"
tar -xzf "${tmpdir}"/syft_*_linux_amd64.tar.gz -C "${tmpdir}"
install_tool "${tmpdir}/syft" syft

curl -fsSL "https://get.helm.sh/helm-${HELM_VERSION}-linux-amd64.tar.gz" \
  -o "${tmpdir}/helm-${HELM_VERSION}-linux-amd64.tar.gz"
tar -xzf "${tmpdir}/helm-${HELM_VERSION}-linux-amd64.tar.gz" -C "${tmpdir}"
install_tool "${tmpdir}/linux-amd64/helm" helm

goreleaser --version
cosign version
syft version
helm version
