<p align="center">
  <h1 align="center">🛡️ kube-shield</h1>
  <p align="center"><strong>Kubernetes Security Posture Manager — k9s for security</strong></p>
</p>

<p align="center">
  <a href="https://github.com/RamazanKara/kube-shield/actions"><img src="https://github.com/RamazanKara/kube-shield/workflows/CI/badge.svg" alt="CI"></a>
  <a href="https://goreportcard.com/report/github.com/RamazanKara/kube-shield"><img src="https://goreportcard.com/badge/github.com/RamazanKara/kube-shield" alt="Go Report Card"></a>
  <a href="https://github.com/RamazanKara/kube-shield/releases"><img src="https://img.shields.io/github/v/release/RamazanKara/kube-shield" alt="Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License"></a>
  <a href="https://codecov.io/gh/RamazanKara/kube-shield"><img src="https://codecov.io/gh/RamazanKara/kube-shield/branch/main/graph/badge.svg" alt="Coverage"></a>
</p>

---

**kube-shield** is a comprehensive Kubernetes security posture management tool with a beautiful interactive terminal UI. It scans your clusters for security issues including CIS benchmark violations, RBAC misconfigurations, network policy gaps, secret exposure, and more — then helps you fix them with AI-powered remediation suggestions.

## ✨ Features

- **🔍 5 Built-in Scanners** — Workload security, CIS Kubernetes Benchmark v1.12, RBAC analysis, network policy validation, secrets exposure detection
- **🖥️ Interactive TUI Dashboard** — Security score (A–F grade), findings explorer, RBAC panel, network policy view, attack path graph, vim-style navigation
- **🤖 AI-Powered Remediation** — Context-aware YAML patches and plain-English explanations via OpenAI or Ollama (local models)
- **📊 Multiple Output Formats** — Colored table, JSON, SARIF (GitHub Code Scanning)
- **🔧 Enterprise Ready** — Multi-cluster, namespace filtering, severity thresholds, CI/CD exit codes, Helm chart

## 🚀 Installation

### Go Install

```bash
go install github.com/RamazanKara/kube-shield@latest
```

### Docker

```bash
docker run --rm -v ~/.kube:/home/kubeshield/.kube:ro ghcr.io/ramazankara/kube-shield scan
```

### Download Binary

Pre-built binaries for Linux, macOS, and Windows are available on the
[GitHub Releases](https://github.com/RamazanKara/kube-shield/releases) page.

| OS | Architecture | File |
|----|-------------|------|
| Linux | amd64 | `kube-shield_*_linux_amd64.tar.gz` |
| Linux | arm64 | `kube-shield_*_linux_arm64.tar.gz` |
| macOS | amd64 | `kube-shield_*_darwin_amd64.tar.gz` |
| macOS | arm64 (Apple Silicon) | `kube-shield_*_darwin_arm64.tar.gz` |
| Windows | amd64 | `kube-shield_*_windows_amd64.zip` |

## 📖 Usage

### Scan your cluster

```bash
# Scan all namespaces with all scanners
kube-shield scan

# Scan a specific namespace
kube-shield scan -n production

# Run only RBAC and network policy checks
kube-shield scan --scanners rbac,netpol

# Filter by category
kube-shield scan --category rbac,secrets

# Show only high and critical findings
kube-shield scan --severity high

# Output as JSON
kube-shield scan -o json

# Output as SARIF for GitHub Code Scanning
kube-shield scan -o sarif > results.sarif

# Use a specific kubeconfig context
kube-shield scan --context staging-cluster

# Set a custom timeout
kube-shield scan --timeout 10m

# Fail CI if critical findings exist (non-zero exit code)
kube-shield scan --exit-code --severity critical
```

### Launch the TUI Dashboard

```bash
# Interactive security dashboard
kube-shield dashboard

# Dashboard for a specific namespace
kube-shield dashboard -n production

# Dashboard with AI explanation support
kube-shield dashboard --ai-provider openai --ai-api-key sk-...
```

### AI-Powered Remediation

```bash
# Using OpenAI
kube-shield scan --ai-provider openai --ai-api-key sk-...

# Using environment variables
export KUBE_SHIELD_AI_PROVIDER=openai
export KUBE_SHIELD_AI_APIKEY=sk-...
kube-shield scan

# Using local Ollama
kube-shield scan --ai-provider ollama --ai-endpoint http://localhost:11434

# In the TUI dashboard, press 'e' on any finding for AI explanation
kube-shield dashboard --ai-provider openai --ai-api-key sk-...
```

## ⌨️ TUI Keybindings

| Key | Action |
|-----|--------|
| `Tab` / `Shift+Tab` | Switch between panels |
| `↑` / `k` | Navigate up |
| `↓` / `j` | Navigate down |
| `Enter` | Select / drill down into finding |
| `Esc` | Go back |
| `/` | Filter findings by name, namespace, severity, or check ID |
| `e` | AI explain (in finding detail view, requires AI provider) |
| `r` | Refresh scan |
| `?` | Toggle help |
| `q` / `Ctrl+C` | Quit |

## 📋 CLI Reference

### Global Flags

These flags apply to all commands and can also be set via config file or environment variables.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--config` | | string | `$HOME/.kube-shield.yaml` | Path to config file |
| `--kubeconfig` | | string | `$KUBECONFIG` or `~/.kube/config` | Path to kubeconfig |
| `--context` | | string | current context | Kubernetes context to use |
| `--namespace` | `-n` | string | all namespaces | Namespace to scan |
| `--output` | `-o` | string | `table` | Output format: `table`, `json`, `sarif` |
| `--verbose` | `-v` | bool | `false` | Enable verbose output |
| `--ai-provider` | | string | | AI provider: `openai`, `ollama` |
| `--ai-model` | | string | | Model name (e.g. `gpt-4`, `llama3`) |
| `--ai-api-key` | | string | | AI provider API key |
| `--ai-endpoint` | | string | | AI endpoint URL |

### `kube-shield scan`

Run security scanners against the cluster.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--scanners` | strings | all | Comma-separated scanners: `workload,cis,rbac,netpol,secrets` |
| `--severity` | string | `low` | Minimum severity: `critical`, `high`, `medium`, `low`, `info` |
| `--category` | strings | all | Filter by category: `workload,cis,rbac,netpol,secrets` |
| `--timeout` | duration | `5m` | Scan timeout |
| `--exit-code` | bool | `false` | Exit with code 1 if findings match severity threshold |

### `kube-shield dashboard`

Launch the interactive TUI dashboard.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--scanners` | strings | all | Comma-separated scanners to run |

### `kube-shield version`

Print the version, git commit, and build date.

## ⚙️ Configuration

kube-shield can be configured via CLI flags, environment variables, or a YAML config file.

**Precedence:** CLI flags > environment variables > config file > defaults.

### Config File

Place a `.kube-shield.yaml` in your project root or `$HOME/.kube-shield.yaml`:

```yaml
# Kubernetes context (empty = current context)
context: ""

# Namespace to scan (empty = all)
namespace: ""

# Output format: table, json, sarif
output: table

# Scanners to enable (empty = all)
scanners:
  - workload
  - rbac
  - netpol
  - secrets
  - cis

# Minimum severity: info, low, medium, high, critical
severity: low

# Scan timeout
timeout: 5m

# Exit with non-zero code when findings match threshold
exit-code: false

# AI-powered analysis
ai:
  provider: ""        # openai, ollama, or empty to disable
  model: ""           # e.g. gpt-4, llama3
  apikey: ""          # prefer KUBE_SHIELD_AI_APIKEY env var
  endpoint: ""        # custom endpoint URL
```

### Environment Variables

All config options can be set via environment variables with the `KUBE_SHIELD_` prefix:

| Variable | Config Key | Example |
|----------|-----------|---------|
| `KUBE_SHIELD_CONTEXT` | `context` | `staging-cluster` |
| `KUBE_SHIELD_NAMESPACE` | `namespace` | `production` |
| `KUBE_SHIELD_OUTPUT` | `output` | `json` |
| `KUBE_SHIELD_SEVERITY` | `severity` | `high` |
| `KUBE_SHIELD_AI_PROVIDER` | `ai.provider` | `openai` |
| `KUBE_SHIELD_AI_APIKEY` | `ai.apikey` | `sk-...` |
| `KUBE_SHIELD_AI_MODEL` | `ai.model` | `gpt-4` |
| `KUBE_SHIELD_AI_ENDPOINT` | `ai.endpoint` | `http://localhost:11434` |

## 🔬 Scanners

| Scanner | Checks | Severity Range | Description |
|---------|--------|---------------|-------------|
| **workload** | 12 | Critical → Info | Privileged containers, root access, host namespaces, capabilities, image tags, resource limits, probes |
| **cis** | 23 | Critical → Low | CIS Kubernetes Benchmark v1.12 — Sections 4.1 (RBAC), 4.2 (Pod Security), 4.3 (Network), 4.4 (Secrets), 4.5 (General) |
| **rbac** | 8 | Critical → Medium | Wildcard permissions, secret access, privilege escalation verbs, cluster-admin bindings, default SA usage |
| **netpol** | 5 | High → Medium | Missing network policies, no default-deny, allow-all rules, wide CIDR ranges |
| **secrets** | 6 | High → Info | Env var exposure, missing references, empty secrets, permissive volume modes, sensitive mount paths |

### Severity Levels

Findings are classified using five severity levels, from most to least critical:

| Level | Meaning | Examples |
|-------|---------|---------|
| **CRITICAL** | Direct cluster compromise possible | Privileged containers, cluster-admin bindings |
| **HIGH** | Significant security risk | Secret exposure, privilege escalation, missing network isolation |
| **MEDIUM** | Defense-in-depth gap | Non-root not enforced, secrets as env vars, wide CIDR ranges |
| **LOW** | Best practice not followed | Missing resource quotas, informational configuration gaps |
| **INFO** | Observation | Empty secrets, minor configuration notes |

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed, no findings at or above threshold (or `--exit-code` not set) |
| `1` | Findings detected at or above the `--severity` threshold (with `--exit-code`) |

## ☸️ Helm Deployment

Deploy kube-shield as a CronJob for periodic cluster scanning:

```bash
helm install kube-shield deploy/helm/ \
  --namespace kube-shield \
  --create-namespace \
  --set schedule="0 */6 * * *" \
  --set severity=medium
```

### Key Helm Values

| Value | Default | Description |
|-------|---------|-------------|
| `schedule` | `"0 */6 * * *"` | CronJob schedule |
| `scanners` | all 5 enabled | List of scanners |
| `severity` | `low` | Minimum severity |
| `output` | `json` | Output format |
| `image.tag` | appVersion | Container image tag |
| `serviceAccount.create` | `true` | Create ServiceAccount |
| `resources.limits.memory` | `256Mi` | Memory limit |
| `resources.limits.cpu` | `200m` | CPU limit |

See [`deploy/helm/values.yaml`](deploy/helm/values.yaml) for all options.

## 🔌 CI/CD Integration

### GitHub Actions

```yaml
- name: Scan cluster security
  run: |
    kube-shield scan --output sarif --severity high > results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### GitHub Actions (fail on critical)

```yaml
- name: Security gate
  run: kube-shield scan --exit-code --severity critical
```

### GitLab CI

```yaml
security-scan:
  script:
    - kube-shield scan --exit-code --severity critical
```

## 🏗️ Architecture

```
kube-shield
├── cmd/                    # Cobra CLI commands (scan, dashboard, version)
├── pkg/
│   ├── scanner/
│   │   ├── engine/         # Scanner interface, registry, parallel execution
│   │   ├── workload/       # Pod security misconfiguration checks
│   │   ├── cis/            # CIS Benchmark checks
│   │   ├── rbac/           # RBAC analysis and risk scoring
│   │   ├── netpol/         # Network policy validation
│   │   └── secrets/        # Secret exposure detection
│   ├── k8s/                # Multi-cluster Kubernetes client
│   ├── ai/                 # AI provider abstraction (OpenAI, Ollama)
│   ├── graph/              # Attack path analysis
│   ├── tui/                # Bubbletea interactive dashboard
│   ├── report/             # Output formatting (table, JSON, SARIF)
│   └── config/             # Configuration management
├── deploy/helm/            # Helm chart for in-cluster deployment
└── .github/workflows/      # CI/CD pipeline
```

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

```bash
git clone https://github.com/RamazanKara/kube-shield.git
cd kube-shield
make build
make test
make lint
```

## 📝 License

This project is licensed under the Apache License 2.0 — see the [LICENSE](LICENSE) file for details.

---

<p align="center">Built with ❤️ by <a href="https://github.com/RamazanKara">Ramazan Kara</a></p>
