<h1 align="center">kube-shield</h1>
<p align="center"><strong>Kubernetes Security Posture Manager - k9s for security</strong></p>

<p align="center">
  <a href="https://github.com/RamazanKara/kube-shield/actions/workflows/ci.yml"><img src="https://github.com/RamazanKara/kube-shield/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/RamazanKara/kube-shield/actions/workflows/e2e.yml"><img src="https://github.com/RamazanKara/kube-shield/actions/workflows/e2e.yml/badge.svg" alt="E2E"></a>
  <a href="https://goreportcard.com/report/github.com/RamazanKara/kube-shield"><img src="https://goreportcard.com/badge/github.com/RamazanKara/kube-shield" alt="Go Report Card"></a>
  <a href="https://github.com/RamazanKara/kube-shield/releases"><img src="https://img.shields.io/github/v/release/RamazanKara/kube-shield" alt="Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License"></a>
  <a href="https://codecov.io/gh/RamazanKara/kube-shield"><img src="https://codecov.io/gh/RamazanKara/kube-shield/branch/main/graph/badge.svg" alt="Coverage"></a>
  <a href="https://ramazankara.github.io/kube-shield/"><img src="https://img.shields.io/badge/docs-mkdocs--material-blue" alt="Docs"></a>
</p>

---

`kube-shield` is a Kubernetes security posture scanner for quick local reviews, CI gates, and scheduled cluster checks. It reads Kubernetes API objects, highlights risky workload, CIS Kubernetes Benchmark v1.12, RBAC, network policy, and secret patterns, then turns them into actionable findings.

![kube-shield TUI dashboard demo](docs/assets/kube-shield-tui.gif)

Use it when you want a lightweight security pass that is easy to run, easy to read, and still friendly to automation.

📖 **[Full documentation](https://ramazankara.github.io/kube-shield/)** — installation, configuration, recipes, CI/CD integration, troubleshooting, and the complete scanner reference.

## Why kube-shield

- Finds common Kubernetes posture issues without installing a controller first.
- Groups checks into workload, CIS, RBAC, network policy, and secrets scanners.
- Shows results as a readable table, JSON for pipelines, SARIF for GitHub Code Scanning, or an interactive TUI.
- Supports severity thresholds and `--exit-code` so CI can fail only on the risks you care about.
- Includes structured remediation and optional AI explanations through OpenAI or local Ollama.
- Ships signed release archives, SBOMs, attestations, GHCR images, an OCI Helm chart, and a Homebrew cask.

## Scope

kube-shield checks Kubernetes API-visible configuration. It does not replace runtime threat detection, admission control, node hardening, cloud IAM review, or a full CIS audit of control-plane host files. It is meant to make the most common cluster posture problems visible fast.

## Install

Pick the install path that matches how you want to run scans.

### Homebrew

```bash
brew install --cask ramazankara/tap/kube-shield
```

### Go

```bash
go install github.com/RamazanKara/kube-shield/cmd/kube-shield@latest
```

### Docker

```bash
docker run --rm \
  -v ~/.kube:/home/kubeshield/.kube:ro \
  ghcr.io/ramazankara/kube-shield:v1.1.0 scan
```

### Binary Archives

Download Linux, macOS, and Windows archives from the [GitHub releases page](https://github.com/RamazanKara/kube-shield/releases). Each release includes checksums, SBOMs, and Sigstore signature bundles.

## Quick Start

Run a first scan against your current Kubernetes context:

```bash
kube-shield scan
```

Common next steps:

```bash
# Scan one namespace
kube-shield scan --namespace production

# Run selected scanners
kube-shield scan --scanners rbac,netpol

# Show only high and critical findings
kube-shield scan --severity high

# Emit SARIF for GitHub Code Scanning
kube-shield scan --output sarif > results.sarif

# Fail CI when critical findings exist
kube-shield scan --exit-code --severity critical

# Suppress an approved finding until an expiry date
kube-shield scan --suppressions suppressions.yaml --exit-code
```

Launch the dashboard:

```bash
kube-shield dashboard
kube-shield dashboard --namespace production
```

Use AI explanations:

```bash
kube-shield scan --ai-provider openai --ai-api-key "$OPENAI_API_KEY"
kube-shield scan --ai-provider ollama --ai-endpoint http://localhost:11434
```

In the TUI, press `e` on a finding detail view to request an AI explanation.

## CLI Reference

### Global Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--config` | | `$HOME/.kube-shield.yaml` | Config file path |
| `--kubeconfig` | | `$KUBECONFIG` or `~/.kube/config` | Kubeconfig path |
| `--context` | | current context | Kubernetes context |
| `--namespace` | `-n` | all namespaces | Namespace filter |
| `--output` | `-o` | `table` | `table`, `json`, or `sarif` |
| `--verbose` | `-v` | `false` | Verbose logs |
| `--ai-provider` | | disabled | `openai` or `ollama` |
| `--ai-model` | | provider default | Model name |
| `--ai-api-key` | | empty | AI provider API key |
| `--ai-endpoint` | | provider default | Custom AI endpoint |

### `kube-shield scan`

| Flag | Default | Description |
|------|---------|-------------|
| `--scanners` | all scanners | Comma-separated scanner list: `workload,cis,rbac,netpol,secrets` |
| `--severity` | `low` | Minimum severity: `critical`, `high`, `medium`, `low`, `info` |
| `--category` | all categories | Finding category filter |
| `--timeout` | `5m` | Scan timeout |
| `--exit-code` | `false` | Exit non-zero when matching findings are present |
| `--read-secret-data` | `false` | Enable checks that read Kubernetes Secret data, currently `SEC-010` |
| `--suppressions` | empty | YAML file of approved suppressions with required reason and expiry |

### `kube-shield rules`

| Command | Description |
|---------|-------------|
| `kube-shield rules list --output table\|json` | List built-in rule metadata |
| `kube-shield rules show CHECK_ID --output table\|json` | Show rationale, impact, data access, standards, and references for one rule |

### `kube-shield dashboard`

| Flag | Default | Description |
|------|---------|-------------|
| `--scanners` | all scanners | Comma-separated scanners to run |

### `kube-shield version`

Print build version, commit, and build date.

## Configuration

Configuration precedence is:

```text
CLI flags > environment variables > config file > defaults
```

Place `.kube-shield.yaml` in the project directory or home directory:

```yaml
context: ""
namespace: ""
output: table

scanners:
  - workload
  - cis
  - rbac
  - netpol
  - secrets

severity: low
timeout: 5m
exit-code: false
read-secret-data: false
suppressions: ""

ai:
  provider: ""   # openai, ollama, or empty
  model: ""
  apikey: ""     # prefer KUBE_SHIELD_AI_APIKEY
  endpoint: ""
```

Environment variables use the `KUBE_SHIELD_` prefix:

| Variable | Config Key | Example |
|----------|------------|---------|
| `KUBE_SHIELD_CONTEXT` | `context` | `staging-cluster` |
| `KUBE_SHIELD_NAMESPACE` | `namespace` | `production` |
| `KUBE_SHIELD_OUTPUT` | `output` | `json` |
| `KUBE_SHIELD_SCANNERS` | `scanners` | `rbac,secrets` |
| `KUBE_SHIELD_SEVERITY` | `severity` | `high` |
| `KUBE_SHIELD_TIMEOUT` | `timeout` | `10m` |
| `KUBE_SHIELD_EXIT_CODE` | `exit-code` | `true` |
| `KUBE_SHIELD_READ_SECRET_DATA` | `read-secret-data` | `true` |
| `KUBE_SHIELD_SUPPRESSIONS` | `suppressions` | `suppressions.yaml` |
| `KUBE_SHIELD_AI_PROVIDER` | `ai.provider` | `openai` |
| `KUBE_SHIELD_AI_APIKEY` | `ai.apikey` | `sk-...` |
| `KUBE_SHIELD_AI_MODEL` | `ai.model` | `gpt-4o-mini` |
| `KUBE_SHIELD_AI_ENDPOINT` | `ai.endpoint` | `http://localhost:11434` |

## Scanners

| Scanner | Checks | Severity Range | Focus |
|---------|--------|----------------|-------|
| `workload` | 17 | Critical to Info | Pod and container security posture |
| `cis` | 14 | Critical to Low | CIS Kubernetes Benchmark v1.12 API-accessible checks |
| `rbac` | 12 | Critical to Medium | Over-permissive roles and risky bindings |
| `netpol` | 6 | High to Medium | Missing isolation and permissive policies |
| `secrets` | 6 | High to Info | Secret exposure and reference hygiene |

See [docs/reference/scanners.md](docs/reference/scanners.md) for every check ID, severity, confidence, data-access level, standards mapping, and remediation category.

Secret checks use pod specs and metadata-only Secret inventory by default. kube-shield does not request or print Secret values unless `--read-secret-data` is set, which enables the opt-in `SEC-010` empty-secret check.

## Suppressions

Suppressions are fail-closed: malformed or expired entries stop the scan. Suppressed findings do not trigger `--exit-code`; JSON includes them under `suppressedFindings`, SARIF marks them as external suppressions, and summaries include `suppressedTotal`.

```yaml
suppressions:
  - id: accepted-risk-2026-001
    checkId: WL-010
    resource:
      kind: Pod
      namespace: production
      name: legacy-worker
    reason: Accepted temporarily while the workload is migrated.
    expires: 2026-12-31
```

## Helm

Install from the published OCI chart:

```bash
helm install kube-shield oci://ghcr.io/ramazankara/charts/kube-shield \
  --version 1.1.0 \
  --namespace kube-shield \
  --create-namespace
```

Run the local chart during development:

```bash
helm install kube-shield deploy/helm \
  --namespace kube-shield \
  --create-namespace \
  --set severity=medium
```

Common values:

| Value | Default | Description |
|-------|---------|-------------|
| `schedule` | `0 */6 * * *` | CronJob schedule |
| `scanners` | all 5 scanners | Scanner list |
| `severity` | `low` | Minimum severity |
| `output` | `json` | Report output format |
| `readSecretData` | `false` | Enable `--read-secret-data` for SEC-010 |
| `image.repository` | `ghcr.io/ramazankara/kube-shield` | Container repository |
| `image.tag` | chart appVersion | Container tag |
| `serviceAccount.create` | `true` | Create ServiceAccount |

See [deploy/helm/values.yaml](deploy/helm/values.yaml) for all chart values.

The chart grants `list` on core `secrets` so kube-shield can validate references with metadata-only requests. Kubernetes RBAC does not distinguish metadata-only Secret reads from full Secret reads, so kube-shield avoids requesting full Secret objects unless `readSecretData=true` is set for `SEC-010`.

## Release Verification

Install `gh` with attestation support and `cosign` before running verification commands.

```bash
gh release download v1.1.0 --repo RamazanKara/kube-shield \
  --pattern checksums.txt \
  --pattern checksums.txt.sigstore \
  --pattern kube-shield_1.1.0_linux_amd64.tar.gz

gh attestation verify kube-shield_1.1.0_linux_amd64.tar.gz \
  --repo RamazanKara/kube-shield

cosign verify-blob --bundle checksums.txt.sigstore \
  --certificate-identity-regexp 'https://github.com/RamazanKara/kube-shield/.github/workflows/release.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt

cosign verify ghcr.io/ramazankara/kube-shield:v1.1.0 \
  --certificate-identity-regexp 'https://github.com/RamazanKara/kube-shield/.github/workflows/release.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Install-channel smoke checks:

```bash
docker pull ghcr.io/ramazankara/kube-shield:v1.1.0
helm show chart oci://ghcr.io/ramazankara/charts/kube-shield --version 1.1.0
brew install --cask ramazankara/tap/kube-shield
```

## TUI Keybindings

| Key | Action |
|-----|--------|
| `Tab` / `Shift+Tab` | Switch panels |
| `Up` / `k` | Move up |
| `Down` / `j` | Move down |
| `Enter` | Open finding details |
| `Esc` | Back |
| `/` | Filter findings |
| `e` | AI explanation in detail view |
| `r` | Refresh scan |
| `?` | Toggle help |
| `q` / `Ctrl+C` | Quit |

## Shell Completion

kube-shield ships completion scripts for bash, zsh, fish, and PowerShell. Homebrew installs them automatically. For other install methods, generate the script for your shell:

```bash
# bash (current shell)
source <(kube-shield completion bash)

# zsh (persisted)
kube-shield completion zsh > "${fpath[1]}/_kube-shield"

# fish
kube-shield completion fish > ~/.config/fish/completions/kube-shield.fish

# PowerShell (persisted)
kube-shield completion powershell | Out-String | Add-Content $PROFILE
```

Run `kube-shield completion <shell> --help` for shell-specific setup notes.

## Documentation

- [Scanner reference](docs/reference/scanners.md)
- [Architecture](docs/design/architecture.md)
- [Threat model](docs/design/threat-model.md)
- [Development guide](docs/contributing/development.md)
- [Release process](RELEASE.md)
- [Repository operations checklist](docs/maintainers/repository-setup.md)
- [Security policy](SECURITY.md)
- [Support](SUPPORT.md)
- [Contributing](CONTRIBUTING.md)

## Contributing

Contributions are welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md):

```bash
git clone https://github.com/RamazanKara/kube-shield.git
cd kube-shield
make build
make test
make lint
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
