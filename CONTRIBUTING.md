# Contributing to kube-shield

Thank you for your interest in contributing to kube-shield! This guide explains how to get started.

## Development Setup

### Prerequisites

- Go 1.25 or later
- A Kubernetes cluster (or `kind`/`minikube` for local testing)
- `kubectl` configured with cluster access

### Build from Source

```bash
git clone https://github.com/RamazanKara/kube-shield.git
cd kube-shield
go mod tidy
go build -o bin/kube-shield .
```

### Run Tests

```bash
go test ./...
```

### Lint

```bash
golangci-lint run
```

### Make Targets

All common tasks are available via `make`:

```bash
make help       # Show all targets
make build      # Build binary
make test       # Run tests
make lint       # Run golangci-lint
make fmt        # Format code
make vet        # Run go vet
make clean      # Remove build artifacts
```

## Project Structure

```
pkg/
├── ai/          # AI-powered remediation (OpenAI, Ollama)
├── config/      # Configuration management
├── graph/       # Attack path graph model
├── k8s/         # Kubernetes client wrapper
├── report/      # Output formatters (table, JSON, SARIF)
├── scanner/
│   ├── cis/     # CIS Kubernetes Benchmark checks
│   ├── engine/  # Scanner engine and types
│   ├── netpol/  # Network policy scanner
│   ├── rbac/    # RBAC scanner
│   ├── secrets/ # Secrets scanner
│   └── workload/# Workload security scanner
└── tui/         # Terminal UI (bubbletea)
```

## Adding a New Scanner Check

1. Identify the correct scanner package under `pkg/scanner/`.
2. Add the check logic in the `Scan()` method.
3. Use the next available check ID for that scanner (e.g., `WL-034`, `RBAC-033`).
4. Create a `engine.Finding` with appropriate severity, description, and remediation.
5. Add a test case in the corresponding `*_test.go` file.

### Severity Guidelines

| Severity   | When to use                                                       |
|------------|-------------------------------------------------------------------|
| CRITICAL   | Direct cluster compromise, privileged containers, cluster-admin   |
| HIGH       | Secret exposure, privilege escalation, missing network isolation  |
| MEDIUM     | Non-root not enforced, secrets as env vars, wide CIDR ranges      |
| LOW        | Missing resource quotas, informational best practices             |
| INFO       | Empty secrets, minor configuration observations                  |

## Pull Requests

1. Fork the repository and create a feature branch from `main`.
2. Write tests for new functionality.
3. Ensure `go test ./...` passes.
4. Ensure `golangci-lint run` passes (or fix any warnings).
5. Keep commits focused — one logical change per commit.
6. Open a PR with a clear description of the change.

## Code Style

- Follow standard Go conventions (`gofmt`, `go vet`).
- Use meaningful variable and function names.
- Keep functions focused and short.
- Add comments only when the code isn't self-explanatory.

## Reporting Issues

- Use GitHub Issues with a clear title and description.
- Include steps to reproduce, expected behavior, and actual behavior.
- For security vulnerabilities, please report privately via GitHub Security Advisories.

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
