# Local Release Preparation

GitHub Actions is unavailable. The repository has one check-only workflow; it does not publish releases, containers, charts, or the documentation site. Run the local gates and prepare binaries before a maintainer decides what to publish. No commands in this runbook commit, tag, push, or publish.

## Prerequisites

- Go 1.26.9, Git, GNU make, and a POSIX shell. On Windows, use Git Bash or w64devkit with `make`, `sh`, and `sha256sum` on `PATH`.
- golangci-lint v2.12.2 (includes Staticcheck) and govulncheck v1.8.0.
- Python with `pip install -r requirements-docs.txt` for documentation checks.
- A C compiler if `go env CGO_ENABLED` is `1`; race tests require cgo. With cgo disabled, `make test` prints the race skip and runs normal tests.

Install the pinned Go check tools if needed:

```shell
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2
go install golang.org/x/vuln/cmd/govulncheck@v1.8.0
```

## Required Local Checks

```shell
make fmt-check vet staticcheck lint
make test fuzz vuln
make build docs
git diff --check
```

Review the real output and any skipped checks. `make fuzz` exercises each parser target for ten seconds with two workers. `make vuln` needs access to the Go vulnerability database. Cluster E2E tests (`make test-e2e`) additionally need Docker, kubectl, and kind; they are required when scanner or Kubernetes client behavior changes.

Before a release, review `CHANGELOG.md` under `Unreleased`, CLI/config compatibility, and version metadata. Move changelog entries to the chosen release version/date only when publishing is approved. Keep public tags immutable.

## Build Binaries and Checksums

From a POSIX shell, including Git Bash on Windows:

```shell
make release-local VERSION=2.0.1-dev
```

This builds the host platform with cgo disabled and `-trimpath`, embeds version/commit/UTC build date, and writes a platform-named binary plus `dist/local/SHA256SUMS`. Windows amd64 produces `dist/local/kube-shield_windows_amd64.exe`. The version defaults to `git describe --tags --always --dirty`; a dirty checkout remains identifiable when using that default. These are unsigned local binaries, not attestations or published archives.

Go can cross-build without a C compiler. To prepare the same six platforms as the archive configuration:

```shell
for os in linux darwin windows; do
  for arch in amd64 arm64; do
    GOOS="$os" GOARCH="$arch" make release-local VERSION=2.0.1-dev
  done
done
```

Each invocation updates `SHA256SUMS` for all `kube-shield_*` files currently in `dist/local/`. Review that directory for older binaries before sharing it. Cross-building verifies compilation; it does not test execution on the target OS.

From PowerShell with the prerequisite tools on `PATH`:

```powershell
make release-local VERSION=2.0.1-dev
.\dist\local\kube-shield_windows_amd64.exe version
```

Override `COMMIT` and `DATE` in the make invocation when a fixed build identity is needed, for example `DATE=2026-10-09T00:00:00Z`. Keep those values consistent across platforms.

## Verify SHA256SUMS

Linux or Git Bash/w64devkit:

```shell
cd dist/local
sha256sum -c SHA256SUMS
```

macOS:

```shell
cd dist/local
shasum -a 256 -c SHA256SUMS
```

PowerShell:

```powershell
Push-Location dist/local
try {
  Get-Content SHA256SUMS | ForEach-Object {
    $expected, $file = $_ -split '  ', 2
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $file).Hash -ne $expected) {
      throw "Checksum mismatch: $file"
    }
  }
} finally {
  Pop-Location
}
```

Run `version`, `--help`, and `config validate` with the native binary before sharing. Keep the checksums next to the exact binaries that were checked.

## Optional Packaging Checks

The existing `.goreleaser.yml`, Dockerfiles, and Helm chart remain available for maintainers who need archives, images, or chart packages. These need additional tools and are separate from the Go-only local binary build:

```shell
make release-check
make release-snapshot
make helm-lint
```

GoReleaser snapshots require GoReleaser, Syft, and Docker. Signing and GitHub OIDC attestations are not part of this local preparation. Verify any existing published release using its supplied checksums and, where available, the signature/attestation instructions in the README. Publishing and site deployment require a separate, explicit maintainer action.
