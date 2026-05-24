# Contributing to kube-shield

Thanks for helping improve kube-shield. This project scans Kubernetes clusters for security posture issues, so changes should favor correctness, clear remediation, and predictable output over cleverness.

## Getting Started

```shell
git clone https://github.com/RamazanKara/kube-shield.git
cd kube-shield
go mod download
make build
make test
```

Use a focused feature branch:

```shell
git switch -c feature/my-change
```

## Development Checks

Run these before opening a pull request:

```shell
gofmt -s -w .
go test ./...
go test -race ./...
go vet ./...
golangci-lint run ./...
```

For scanner or release-sensitive changes, also run:

```shell
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
go run github.com/securego/gosec/v2/cmd/gosec@v2.26.1 ./...
go test -race -coverprofile=coverage.out ./...
go tool cover -func=coverage.out | tail -n 1
```

For release-related changes, also run:

```shell
goreleaser check
goreleaser release --snapshot --clean --skip=publish,sign
helm lint deploy/helm
helm template kube-shield deploy/helm
```

Keyless signing is validated in GitHub Actions where OIDC is available. Local snapshot builds skip signing by default.

## Pull Request Guidelines

- Keep changes focused and explain the user-visible behavior.
- Add or update tests for scanner logic, report output, CLI validation, and config precedence.
- Do not include real kubeconfig files, cluster names, tokens, API keys, or secret values.
- For scanner changes, update `docs/SCANNERS.md` and README scanner counts.
- For public CLI, config, output, packaging, or release changes, update README and `RELEASE.md`.
- For docs-only changes, still check links, command examples, and version references.

## Adding a Scanner Check

1. Add the check to the appropriate scanner package under `pkg/scanner/`.
2. Return a stable `CheckID`, severity, category, affected resource, and remediation.
3. Add unit tests with Kubernetes fake clients.
4. Add or update E2E fixtures when the behavior should be validated against a real API server.
5. Document the check in `docs/SCANNERS.md`.

## Security Work

Please do not open public issues for vulnerabilities. Follow `SECURITY.md` so reports can be handled privately first.
