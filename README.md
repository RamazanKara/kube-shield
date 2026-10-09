<h1 align="center">kube-shield</h1>
<p align="center"><strong>Kubernetes Security Posture Manager - k9s for security</strong></p>

---

`kube-shield` is a Kubernetes security posture scanner for quick local reviews, CI gates, and scheduled cluster checks. It reads Kubernetes API objects, highlights risky workload, CIS Kubernetes Benchmark, RBAC, network policy, and secret patterns, then turns them into actionable findings.

![kube-shield TUI dashboard demo](docs/assets/kube-shield-tui.gif)

Use it when you want a lightweight security pass that is easy to run, easy to read, and still friendly to automation.

📖 **[Full documentation](https://ramazankara.github.io/kube-shield/)** — installation, configuration, recipes, CI/CD integration, troubleshooting, and the complete scanner reference.

## Why kube-shield

- Finds common Kubernetes posture issues without installing a controller first.
- Groups checks into workload, CIS, RBAC, network policy, and secrets scanners.
- Shows results as a readable table, JSON for pipelines, SARIF for GitHub Code Scanning, Markdown for reviews, or an interactive TUI.
- Supports severity thresholds and `--exit-code` so CI can fail only on the risks you care about.
- Includes structured remediation and optional AI explanations through OpenAI or local Ollama.
- Validates configuration offline with line-numbered diagnostics and completes flag values and rule IDs in your shell.
- Includes source builds, a local Helm chart, and local release binaries with SHA256 checksums.

## Scope

kube-shield checks Kubernetes API-visible configuration. It does not replace runtime threat detection, admission control, node hardening, cloud IAM review, or a full CIS audit of control-plane host files. It is meant to make the most common cluster posture problems visible fast.

## Install

Build this checkout with `make build`, then run `./bin/kube-shield version`. Go 1.26.9 is the pinned toolchain. On Windows, the binary is `bin/kube-shield.exe`; run `.\bin\kube-shield.exe version` from PowerShell.

The release-channel commands below require published artifacts. Homebrew, container execution, signatures, and attestations were not verified in this maintenance pass; check the selected release before installing.

Upgrading from v1.x? Review the [v2 migration notes](CHANGELOG.md#migrating-from-v1x) for renamed CIS IDs and suppression updates.

### Homebrew

```bash
brew install --cask ramazankara/tap/kube-shield
```

### Go

```bash
go install github.com/RamazanKara/kube-shield/v2/cmd/kube-shield@latest
```

### Docker

```bash
docker run --rm \
  -v "$HOME/.kube:/kube:ro" \
  ghcr.io/ramazankara/kube-shield:v2.0.0 scan --kubeconfig /kube/config
```

### Binary Archives

Download Linux, macOS, and Windows archives from the [GitHub releases page](https://github.com/RamazanKara/kube-shield/releases). Check the selected release for checksums, SBOMs, and Sigstore signature bundles.

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

# Save a report for an issue or review
kube-shield scan --output markdown > report.md

# Check a configuration file without cluster access
kube-shield config validate examples/.kube-shield.yaml

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
| `--config` | | `$HOME/.kube-shield.yaml`, then `./.kube-shield.yaml` | Config file path |
| `--kubeconfig` | | `$KUBECONFIG` or `~/.kube/config` | Kubeconfig path |
| `--context` | | current context | Kubernetes context |
| `--namespace` | `-n` | all namespaces | Namespace filter |
| `--output` | `-o` | `table` | `table`, `json`, `sarif`, or `markdown` |
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

### `kube-shield config validate FILE`

Validate one YAML file without cluster access or configuration overrides. Unknown keys, duplicate keys, wrong types, invalid enum values, and non-positive timeouts produce errors with line numbers. Normal scan configuration loading is unchanged. See [configuration validation](docs/reference/configuration.md#validate-a-file).

## Configuration

Configuration precedence is:

```text
CLI flags > environment variables > config file > defaults
```

Configuration is read from `.kube-shield.yaml` in the home directory first, then the current directory. `--config` selects an explicit file. Unreadable or malformed files stop the command:

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
| `cis` | 23 | Critical to Low | CIS Kubernetes Benchmark API-accessible checks |
| `rbac` | 12 | Critical to Medium | Over-permissive roles and risky bindings |
| `netpol` | 6 | High to Medium | Missing isolation and permissive policies |
| `secrets` | 6 | High to Info | Secret exposure and reference hygiene |

See [docs/reference/scanners.md](docs/reference/scanners.md) for every check ID, severity, confidence, data-access level, standards mapping, and remediation category.

The `cis` scanner covers the API-checkable subset of CIS Kubernetes Benchmark 2.0.x Policies recommendations. Its `CIS-5.*` check IDs align with Section 5 recommendation numbers, also carried in each rule's standards metadata and finding `cisRef` field. See the [scanner reference](docs/reference/scanners.md) for coverage and limitations.

Secret checks use pod specs and metadata-only Secret inventory by default. Secret values are never printed. `--read-secret-data` permits fetching Secret data for the opt-in `SEC-010` empty-secret check; use `--severity info` to include that finding.

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
  --version 2.0.0 \
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

For local release preparation, run `make release-local`. It writes a platform-named binary and `SHA256SUMS` to `dist/local/` without publishing. See [RELEASE.md](RELEASE.md) for Windows, macOS, and Linux build and verification commands. The single CI workflow runs checks only; release and documentation publishing are manual.

The commands below apply to existing published releases that include signatures and attestations from the former release workflow.

Install `gh` with attestation support and `cosign` before running verification commands.

```bash
gh release download v2.0.0 --repo RamazanKara/kube-shield \
  --pattern checksums.txt \
  --pattern checksums.txt.sigstore \
  --pattern kube-shield_2.0.0_linux_amd64.tar.gz

gh attestation verify kube-shield_2.0.0_linux_amd64.tar.gz \
  --repo RamazanKara/kube-shield

cosign verify-blob --bundle checksums.txt.sigstore \
  --certificate-identity-regexp 'https://github.com/RamazanKara/kube-shield/.github/workflows/release.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt

cosign verify ghcr.io/ramazankara/kube-shield:v2.0.0 \
  --certificate-identity-regexp 'https://github.com/RamazanKara/kube-shield/.github/workflows/release.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Install-channel smoke checks:

```bash
docker pull ghcr.io/ramazankara/kube-shield:v2.0.0
helm show chart oci://ghcr.io/ramazankara/charts/kube-shield --version 2.0.0
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

kube-shield ships completion scripts for bash, zsh, fish, and PowerShell. For other install methods, generate the script for your shell:

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

Completions include output formats, severity, AI providers, scanner/category lists (including values after a comma), and `rules show` check IDs with descriptions. Completion uses local metadata and does not contact Kubernetes.

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
