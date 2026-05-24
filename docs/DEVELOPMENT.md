# Development Guide

This guide is for local development, scanner work, and release-adjacent validation.

## Prerequisites

- Go 1.25+
- Docker
- kubectl
- kind, for E2E tests
- Helm, for chart validation
- golangci-lint, for lint checks
- GoReleaser and Syft, for release snapshots

## Quick Start

```shell
git clone https://github.com/RamazanKara/kube-shield.git
cd kube-shield
go mod download
make build
./bin/kube-shield scan
```

Build with explicit version metadata:

```shell
VERSION="$(git describe --tags --always --dirty)" make build
./bin/kube-shield version
```

## Common Commands

```shell
make build        # build bin/kube-shield
make test         # race-enabled tests with coverage
make lint         # golangci-lint
make vet          # go vet
make test-e2e     # kind-based E2E suite
make helm-lint    # helm lint + template
make release-check
make release-snapshot
```

## Test Strategy

### Unit and Integration Tests

```shell
go test ./...
go test -race ./...
go test -race -coverprofile=coverage.out ./...
go tool cover -func=coverage.out | tail -n 1
go tool cover -html=coverage.out
```

The v1 release line keeps the total coverage gate at 60%.

### Static and Security Checks

```shell
go vet ./...
golangci-lint run ./...
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
go run github.com/securego/gosec/v2/cmd/gosec@v2.26.1 ./...
go mod verify
```

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

Fixtures live in `test/e2e/testdata/fixtures/`:

| File | Purpose |
|------|---------|
| `workload-vulnerable.yaml` | Privileged pods, host namespaces, dangerous capabilities |
| `rbac-vulnerable.yaml` | Wildcard roles, cluster-admin bindings, privilege escalation |
| `netpol-vulnerable.yaml` | Allow-all policies, wide CIDR ranges |
| `secrets-vulnerable.yaml` | Env-exposed secrets, permissive volume modes |
| `cis-vulnerable.yaml` | Root containers and CIS policy gaps |

## Adding Scanner Logic

1. Add or update code under `pkg/scanner/<scanner>/`.
2. Keep check IDs stable once released.
3. Return a clear title, severity, category, resource, description, and remediation.
4. Add unit tests with Kubernetes fake clients.
5. Add or update E2E fixtures when API-server behavior matters.
6. Update [SCANNERS.md](SCANNERS.md) and README scanner counts.

Every scanner implements:

```go
type Scanner interface {
    Name() string
    Category() Category
    Description() string
    Scan(ctx context.Context, client kubernetes.Interface, namespace string) (*ScanResult, error)
}
```

Scanners should be stateless and safe to run concurrently.

## Output and CLI Changes

For changes to flags, config, output formats, or exit behavior:

- Update validation tests under `cmd/`.
- Update report tests under `pkg/report/` when JSON, table, or SARIF changes.
- Keep config precedence as CLI flags > env vars > config file > defaults.
- Update README, [ARCHITECTURE.md](ARCHITECTURE.md), and [RELEASE.md](../RELEASE.md) if release behavior changes.

## Packaging Checks

```shell
goreleaser check
goreleaser release --snapshot --clean --skip=publish,sign
docker build -f Dockerfile -t kube-shield:dev .
docker run --rm kube-shield:dev version
helm lint deploy/helm
helm template kube-shield deploy/helm --namespace kube-shield
```

GoReleaser signing and attestations are validated in GitHub Actions because they require GitHub OIDC.

## CI/CD

- `ci.yml`: unit/race tests, coverage gate, lint, security checks, and build matrix.
- `e2e.yml`: kind-based E2E tests.
- `release-dry-run.yml`: GoReleaser, Docker, SBOM, and Helm snapshot validation.
- `release.yml`: tag-triggered publishing for GitHub releases, GHCR images, Helm OCI chart, signatures, attestations, and Homebrew cask.

## Code Style

- Use `gofmt` and keep Go code idiomatic.
- Prefer structured APIs over string parsing.
- Keep scanner implementations focused and testable.
- Avoid logging or outputting secret values.
- Use `kubernetes.Interface` rather than concrete clientsets.
- Keep docs and tests in the same PR as user-visible behavior changes.
