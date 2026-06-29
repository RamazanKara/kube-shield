# CLI reference

`kube-shield` provides `scan`, `dashboard`, `rules`, `version`, and `completion` commands. Run `kube-shield <command> --help` for inline help.

## Global flags

These apply to all commands.

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

## `kube-shield scan`

Reads Kubernetes API objects and reports findings.

| Flag | Default | Description |
|------|---------|-------------|
| `--scanners` | all scanners | Comma-separated list: `workload,cis,rbac,netpol,secrets` |
| `--severity` | `low` | Minimum severity: `critical`, `high`, `medium`, `low`, `info` |
| `--category` | all categories | Filter by category |
| `--timeout` | `5m` | Scan timeout |
| `--exit-code` | `false` | Exit non-zero when matching findings are present |
| `--read-secret-data` | `false` | Enable checks that read Kubernetes Secret data (currently `SEC-010`) |
| `--suppressions` | empty | YAML file of approved suppressions with required reason and expiry |

## `kube-shield dashboard`

Launches the interactive terminal UI.

| Flag | Default | Description |
|------|---------|-------------|
| `--scanners` | all scanners | Comma-separated scanners to run |

See [Output & display](../user-guide/output-and-display.md) for keybindings.

## `kube-shield rules`

Inspect the built-in rule catalog.

| Command | Description |
|---------|-------------|
| `kube-shield rules list --output table\|json` | List built-in rule metadata |
| `kube-shield rules show CHECK_ID --output table\|json` | Show rationale, impact, data access, standards, and references for one rule |

## `kube-shield version`

Prints the build version, commit, and build date (injected at build time).

## `kube-shield completion`

Generates a shell completion script for `bash`, `zsh`, `fish`, or `powershell`. See [Output & display](../user-guide/output-and-display.md#shell-completion).
