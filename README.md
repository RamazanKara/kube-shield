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

<!-- Screenshot: <p align="center"><img src="docs/demo.gif" width="800"></p> -->

## ✨ Features

- **🔍 5 Built-in Scanners**
  - **Workload** — Privileged containers, root access, missing security contexts, dangerous capabilities, image tags, resource limits
  - **CIS Benchmark** — CIS Kubernetes Benchmark v1.12 checks via API (RBAC policies, pod security, network policies, secrets management)
  - **RBAC Analysis** — Deep effective permissions resolution, wildcard detection, cluster-admin bindings, privilege escalation paths
  - **Network Policy** — Namespace isolation gaps, missing default-deny rules, overly permissive policies, wide CIDR ranges
  - **Secrets** — Environment variable exposure, missing secret references, insecure secret management patterns

- **🖥️ Interactive TUI Dashboard**
  - Security score with A-F grade
  - Findings explorer with drill-down details
  - RBAC analysis panel
  - Network policy visualization
  - Attack path graph
  - Vim-style keyboard navigation

- **🤖 AI-Powered Remediation** (opt-in)
  - Context-aware YAML patch generation
  - Plain-English vulnerability explanations
  - Support for OpenAI and Ollama (local models)

- **📊 Multiple Output Formats**
  - Colored table (default)
  - JSON for scripting
  - SARIF for GitHub Code Scanning integration

- **🔧 Enterprise Ready**
  - Multi-cluster support
  - Namespace filtering
  - Configurable severity thresholds
  - CI/CD integration with exit codes
  - Helm chart for in-cluster deployment
  - kubectl plugin support

## 🚀 Quick Start

### Install

```bash
# Go install
go install github.com/RamazanKara/kube-shield@latest

# Homebrew (macOS/Linux)
brew install RamazanKara/tap/kube-shield

# Docker
docker run --rm -v ~/.kube:/home/kubeshield/.kube:ro ghcr.io/ramazankara/kube-shield scan

```

### Download Binary

Download the latest release from [GitHub Releases](https://github.com/RamazanKara/kube-shield/releases).

## 📖 Usage

### Scan your cluster

```bash
# Scan all namespaces with all scanners
kube-shield scan

# Scan a specific namespace
kube-shield scan -n production

# Run only RBAC and network policy checks
kube-shield scan --scanners rbac,netpol

# Show only high and critical findings
kube-shield scan --severity high

# Output as JSON
kube-shield scan -o json

# Output as SARIF for GitHub Code Scanning
kube-shield scan -o sarif > results.sarif

# Use a specific kubeconfig context
kube-shield scan --context staging-cluster

# Fail CI if findings exist (non-zero exit code)
kube-shield scan --exit-code --severity critical
```

### Launch the TUI Dashboard

```bash
# Interactive security dashboard
kube-shield dashboard

# Dashboard for a specific namespace
kube-shield dashboard -n production
```

### AI-Powered Remediation

```bash
# Using OpenAI (via flags)
kube-shield scan --ai-provider openai --ai-api-key sk-...

# Using environment variables
export KUBE_SHIELD_AI_PROVIDER=openai
export KUBE_SHIELD_AI_APIKEY=sk-...
kube-shield scan

# Using local Ollama
kube-shield scan --ai-provider ollama --ai-endpoint http://localhost:11434

# AI in the TUI dashboard (press 'e' on a finding for AI explanation)
kube-shield dashboard --ai-provider openai --ai-api-key sk-...
```

## 🔬 Scanners

| Scanner | Checks | Severity Range |
|---------|--------|---------------|
| **workload** | Privileged containers, root access, host namespaces, capabilities, image tags, resource limits, probes | Critical → Info |
| **cis** | CIS Kubernetes Benchmark v1.12 (Sections 4.1-4.5) | Critical → Low |
| **rbac** | Wildcard permissions, secret access, privilege escalation, cluster-admin bindings, default SA usage | Critical → Medium |
| **netpol** | Missing network policies, no default-deny, allow-all rules, wide CIDR ranges | High → Medium |
| **secrets** | Env var exposure, missing references, empty secrets, insecure patterns | High → Info |

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

## ☸️ Helm Deployment

Deploy kube-shield as a CronJob for periodic cluster scanning:

```bash
helm install kube-shield deploy/helm/ \
  --namespace kube-shield \
  --create-namespace \
  --set schedule="0 */6 * * *" \
  --set severity=medium
```

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

### GitLab CI

```yaml
security-scan:
  script:
    - kube-shield scan --exit-code --severity critical
```

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

Quick start:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Write tests for your changes
4. Ensure all tests pass (`make test`)
5. Ensure linting passes (`make lint`)
6. Commit your changes (`git commit -m 'feat: add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

### Development Setup

```bash
git clone https://github.com/RamazanKara/kube-shield.git
cd kube-shield
make build
make test
```

## 📝 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## ⭐ Star History

If you find kube-shield useful, please give it a star! It helps others discover the project.

---

<p align="center">Built with ❤️ by <a href="https://github.com/RamazanKara">Ramazan Kara</a></p>
