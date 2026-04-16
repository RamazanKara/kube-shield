# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-04-17

### Added
- Interactive TUI dashboard with real-time cluster security overview
- AI-powered finding explanations (OpenAI and Ollama support)
- Attack path graph analysis with BFS traversal
- CIS Kubernetes Benchmark scanner (23 checks covering 4.1–4.4)
- RBAC security scanner (wildcard permissions, cluster-admin bindings, privilege escalation)
- Workload security scanner (privileged containers, host namespaces, capabilities)
- Network policy scanner (default deny, wide CIDRs, allow-all rules)
- Secrets scanner (env var exposure, permissive volume modes, sensitive paths)
- Multiple output formats: table, JSON, SARIF
- Helm chart for scheduled CronJob deployments
- Docker multi-arch images (amd64/arm64)
- Homebrew tap and Krew plugin index for easy installation
- `--category` flag for filtering scan results by category
- `--exit-code` flag for CI/CD pipeline integration
- Configurable severity thresholds
- Filter and search in TUI dashboard

### Fixed
- `os.Exit` in cobra `RunE` replaced with proper error return
- Shared AI context replaced with per-call timeouts
- HTTP client reuse in AI providers (was creating per request)
- Unbounded error response body reads capped at 1MB
- Config `Load()` preserves defaults when viper returns empty strings
- Graph analysis cached in TUI model (was rebuilding every render)
- Helm templates use `_helpers.tpl` functions consistently

### Security
- Non-root container user in Dockerfile and Helm chart
- Read-only root filesystem in container security context
- All capabilities dropped in pod security context
- SECURITY.md with responsible disclosure policy
