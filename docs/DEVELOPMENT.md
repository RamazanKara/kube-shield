# Development Guide

## Prerequisites

- Go 1.25+
- [kind](https://kind.sigs.k8s.io/) (for E2E tests)
- kubectl
- Docker (for kind)

## Quick Start

```shell
# Clone and enter the repo
git clone https://github.com/RamazanKara/kube-shield.git
cd kube-shield

# Install dependencies
go mod download

# Build
make build

# Run against your current kubeconfig context
./bin/kube-shield scan
```

## Building

```shell
# Build binary to bin/kube-shield
make build

# Build with version info
VERSION=1.0.0 make build
```

## Running Tests

### Unit Tests

```shell
# All unit tests
make test

# With coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### End-to-End Tests

E2E tests create a kind cluster, deploy vulnerable fixtures, and run kube-shield against them.

```shell
# Full E2E suite (creates/destroys kind cluster automatically)
make test-e2e

# Run a specific E2E test
go test -v -tags e2e -timeout 10m -count=1 -run TestWorkloadScanner ./test/e2e/...
```

The E2E tests use the build tag `e2e` and are excluded from regular `go test ./...`.

**What the E2E suite does:**

1. Creates a kind cluster named `kube-shield-e2e`
2. Deploys vulnerable fixtures from `test/e2e/testdata/fixtures/`
3. Waits for all pods to be ready
4. Runs each scanner against the cluster
5. Verifies expected findings are detected
6. Tests CLI output formats (JSON, SARIF) and exit-code behavior
7. Tears down the cluster

### Test Fixtures

Located in `test/e2e/testdata/fixtures/`:

| File | Purpose |
|------|---------|
| `workload-vulnerable.yaml` | Privileged pods, host namespaces, dangerous capabilities |
| `rbac-vulnerable.yaml` | Wildcard roles, cluster-admin bindings, privilege escalation |
| `netpol-vulnerable.yaml` | Allow-all policies, wide CIDR ranges |
| `secrets-vulnerable.yaml` | Env-exposed secrets, permissive volume modes |
| `cis-vulnerable.yaml` | Root containers, writable filesystems |

## Adding a New Scanner

1. Create a new package under `pkg/scanner/<name>/`.
2. Implement the `engine.Scanner` interface:

```go
package myscanner

import (
    "context"
    "github.com/RamazanKara/kube-shield/pkg/scanner/engine"
    "k8s.io/client-go/kubernetes"
)

type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string        { return "myscanner" }
func (s *Scanner) Category() engine.Category { return engine.Category("myscanner") }
func (s *Scanner) Description() string  { return "My custom scanner" }

func (s *Scanner) Scan(ctx context.Context, client kubernetes.Interface, namespace string) (*engine.ScanResult, error) {
    var findings []engine.Finding
    // ... scan logic ...
    return &engine.ScanResult{
        Scanner:  s.Name(),
        Findings: findings,
    }, nil
}
```

3. Register it in `pkg/scanner/registry.go`:

```go
func DefaultRegistry() *engine.Registry {
    r := engine.NewRegistry()
    r.Register(workload.New())
    r.Register(cis.New())
    r.Register(rbac.New())
    r.Register(netpol.New())
    r.Register(secrets.New())
    r.Register(myscanner.New())  // Add here
    return r
}
```

4. Add E2E test fixtures and a test file in `test/e2e/`.

## Project Structure

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full package layout and data flow.

## Code Style

- Follow standard Go conventions (`gofmt`, `go vet`)
- Use `golangci-lint` for linting
- Keep scanner implementations stateless
- Use `kubernetes.Interface` (not `*kubernetes.Clientset`) for testability
- Use structured logging via `pkg/logging`

## CI/CD

- **ci.yml**: Runs on every push/PR — builds, lints, unit tests
- **e2e.yml**: Runs E2E tests with kind on PRs to main
