# Development Guide

This guide is for contributors changing code, scanner behavior, packaging, or documentation media.

## Prerequisites

- Go 1.26.9 (the toolchain pinned in `go.mod` and CI)
- Docker
- kubectl
- kind, for E2E tests
- Helm, for chart validation
- GNU make and a POSIX shell (Git Bash or WSL on Windows)
- A C compiler for Go race tests when cgo is enabled (GCC on Windows)
- golangci-lint v2.12.2, for lint checks
- govulncheck v1.8.0, for vulnerability checks
- Python with `pip install -r requirements-docs.txt`, for docs checks
- GoReleaser and Syft, for release snapshots

## Quick Start

```shell
git clone https://github.com/RamazanKara/kube-shield.git
cd kube-shield
go mod download
make build
./bin/kube-shield scan
```

Windows builds produce `bin/kube-shield.exe`. Use Git Bash or WSL for the shell examples and make targets.

If you do not have a cluster available, you can still run unit tests, linting, docs checks, and release snapshot validation. E2E tests create their own kind cluster.

Build with explicit version metadata:

```shell
VERSION="$(git describe --tags --always --dirty)" make build
./bin/kube-shield version
```

## Common Commands

```shell
make build        # build bin/kube-shield
make test         # coverage; race-enabled when CGO_ENABLED=1
make lint         # golangci-lint
make staticcheck  # Staticcheck from the pinned golangci-lint installation
make fmt-check    # check gofmt without editing files
make vet          # go vet
make fuzz         # bounded runs of all fuzz targets
make vuln         # govulncheck
make docs         # strict MkDocs build
make test-e2e     # kind-based E2E suite
make helm-lint    # helm lint + template
make release-check
make release-snapshot
make release-local # native binary and SHA256SUMS in dist/local
```

Use the smallest check set that matches your change while developing, then run the broader set before opening or merging a pull request.

## Test Strategy

### Unit and Integration Tests

```shell
make test
make test-coverage
go tool cover -func=coverage.out | tail -n 1
go tool cover -html=coverage.out
```

Compare package and total coverage before and after changes. The Make targets enable race tests only when `go env CGO_ENABLED` is `1`; otherwise `make test` reports the skip. CI has no coverage threshold.

Run these for any change that touches scanner logic, config precedence, report output, CLI validation, or TUI rendering.

### Static and Security Checks

```shell
go vet ./...
golangci-lint run ./...
make staticcheck
make vuln
go run github.com/securego/gosec/v2/cmd/gosec@v2.26.1 ./...
go mod verify
```

Run these after dependency updates, release tooling changes, Dockerfile changes, or anything security-sensitive.

### End-to-End Tests

E2E tests create a kind cluster, deploy vulnerable fixtures, run kube-shield, and destroy the cluster.

```shell
make test-e2e
go test -v -tags e2e -timeout 10m -count=1 -run TestWorkloadScanner ./test/e2e/...
```

The E2E suite validates:

- Workload, CIS, RBAC, network policy, and secrets findings.
- Namespace and scanner filtering.
- JSON and SARIF output.
- `--exit-code` behavior.
- Full scan summary counts.

Run E2E for scanner behavior, Helm chart changes, Kubernetes client changes, and release packaging changes that could affect the container runtime.

Fixtures live in `test/e2e/testdata/fixtures/`:

| File | Purpose |
|------|---------|
| `workload-vulnerable.yaml` | Privileged pods, host namespaces, dangerous capabilities |
| `rbac-vulnerable.yaml` | Wildcard roles, cluster-admin bindings, privilege escalation |
| `netpol-vulnerable.yaml` | Allow-all policies, wide CIDR ranges |
| `secrets-vulnerable.yaml` | Env-exposed secrets, permissive volume modes |
| `cis-vulnerable.yaml` | Root containers and CIS policy gaps |

## Adding Scanner Logic

1. Add or update code under `internal/scanner/<scanner>/`.
2. Keep check IDs stable once released.
3. Return a clear title, severity, category, resource, description, and remediation.
4. Add unit tests with Kubernetes fake clients.
5. Add or update E2E fixtures when API-server behavior matters.
6. Update the rule catalog in `internal/scanner/engine/rules.go`, then run `go generate ./...` to refresh [the scanner reference](../reference/scanners.md).
7. Add a `CHANGELOG.md` entry when user-visible findings, severities, or output change.

Every scanner implements:

```go
type Scanner interface {
    Name() string
    Category() Category
    Description() string
    Scan(ctx context.Context, client kubernetes.Interface, namespace string) (*ScanResult, error)
}
```

Scanners should be stateless and safe to run concurrently. Use `engine.ContextScanner` only when a scanner needs scan options or the metadata client; the secrets scanner uses it so default scans can validate Secret references without requesting Secret data.

## Output and CLI Changes

For changes to flags, config, output formats, or exit behavior:

- Update validation tests under `internal/cli/`.
- Update report tests under `internal/report/` when JSON, table, or SARIF changes.
- Keep config precedence as CLI flags > env vars > config file > defaults.
- Update README, [the architecture guide](../design/architecture.md), and [RELEASE.md](https://github.com/RamazanKara/kube-shield/blob/main/RELEASE.md) if release behavior changes.
- Preserve backwards-compatible values unless a breaking change is intentional and documented.
- For suppressions, keep malformed and expired entries fail-closed and preserve suppressed findings in JSON/SARIF for auditability.

## Packaging Checks

```shell
goreleaser check
goreleaser release --snapshot --clean --skip=publish,sign
docker build -f Dockerfile -t kube-shield:dev .
docker run --rm kube-shield:dev version
helm lint deploy/helm
helm template kube-shield deploy/helm --namespace kube-shield
```

The local `make release-local` target needs only the build toolchain and a SHA256 utility. See [local release preparation](https://github.com/RamazanKara/kube-shield/blob/main/RELEASE.md). Signing and GitHub OIDC attestations are not verified by the local checks.

## Documentation Media

The README TUI animation is generated with [VHS](https://github.com/charmbracelet/vhs) from a synthetic report, so it does not require a live Kubernetes cluster. VHS also needs `ttyd`, `ffmpeg`, and a Chromium-compatible browser available locally.

```shell
go install github.com/charmbracelet/vhs@latest
PATH="$(go env GOPATH)/bin:$PATH" vhs docs/demo/tui.tape
```

The tape runs [docs/demo/tui_demo.go](../demo/tui_demo.go) and writes [docs/assets/kube-shield-tui.gif](../assets/kube-shield-tui.gif).

## CI/CD

- `ci.yml`: one job on pushes/PRs to main and manual dispatch, using the same Make targets as local checks. It checks formatting, vet, Staticcheck, lint, tests, fuzzing, vulnerabilities, build, and docs.
- Release and Pages publishing are manual; no workflow writes to releases, registries, or Pages.

GitHub Actions is currently unavailable due to billing. Run `make fmt-check vet staticcheck lint test fuzz vuln build docs` locally as the gate. E2E and release snapshot checks remain local make targets with their additional prerequisites.

## Code Style

- Use `gofmt` and keep Go code idiomatic.
- Prefer structured APIs over string parsing.
- Keep scanner implementations focused and testable.
- Avoid logging or outputting secret values.
- Do not read Kubernetes Secret data unless a feature is explicitly opt-in and documented in [the threat model](../design/threat-model.md).
- Use `kubernetes.Interface` rather than concrete clientsets.
- Keep docs and tests in the same PR as user-visible behavior changes.
