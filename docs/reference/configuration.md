# Configuration reference

kube-shield is configured by, in order of precedence:

```text
CLI flags > environment variables > config file > defaults
```

A value set by a higher-precedence source overrides lower ones. For example, `--severity high` overrides `KUBE_SHIELD_SEVERITY`, which overrides `severity:` in the config file.

## Config file

kube-shield looks for `.kube-shield.yaml` in your home directory and then the current directory. Override the path with `--config`. Missing explicit files and unreadable or malformed files cause an error.

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

A ready-to-copy version lives in [`examples/.kube-shield.yaml`](https://github.com/RamazanKara/kube-shield/blob/main/examples/.kube-shield.yaml).

## Validate a file

Check a file before a scan or in CI, without a kubeconfig or cluster:

```bash
kube-shield config validate examples/.kube-shield.yaml
```

Success prints `Configuration valid: FILE`. Failure exits non-zero with a file path, line number, and field diagnostic, for example:

```text
settings.yaml: line 2, column 10: severty: unknown configuration key
```

Validation checks unknown and duplicate keys (case-insensitively), YAML types, scanner/category names, output formats, severity, AI provider, and a positive duration such as `5m`. Use YAML booleans `true`/`false` and quote strings. Lists may use YAML sequences or comma-separated strings. Both `category` and `categories`, and `ai.apikey`/`ai.apiKey`, are recognized. YAML aliases and merge mappings are checked too, including their source values; multiple documents are rejected. Empty files use defaults.

Only the named file is checked: environment variables, `--config`, and flag overrides cannot hide mistakes. Diagnostics for type errors do not print values such as API keys. Validation does not contact Kubernetes or AI providers and does not open referenced kubeconfig or suppression files. The existing scan/dashboard loading behavior and precedence remain unchanged.

## Environment variables

Environment variables use the `KUBE_SHIELD_` prefix. Nested keys use `_` (for example `ai.provider` becomes `KUBE_SHIELD_AI_PROVIDER`).

| Variable | Config key | Example |
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

Prefer `KUBE_SHIELD_AI_APIKEY` over putting an API key in the config file or shell history.

## Keys

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `kubeconfig` | string | environment or home config | Kubernetes client configuration path |
| `context` | string | current context | Kubernetes context to scan |
| `namespace` | string | all namespaces | Restrict the scan to one namespace |
| `output` | string | `table` | `table`, `json`, `sarif`, or `markdown` |
| `verbose` | bool | `false` | Enable debug logs |
| `scanners` | list | all five | `workload`, `cis`, `rbac`, `netpol`, `secrets` |
| `categories` | list | all categories | Same names as scanners; `category` is also accepted and takes precedence when nonempty |
| `severity` | string | `low` | Minimum severity to report |
| `timeout` | duration | `5m` | Scan deadline |
| `exit-code` | bool | `false` | Exit non-zero on matching findings |
| `read-secret-data` | bool | `false` | Enable `SEC-010` (reads Secret data) |
| `suppressions` | string | empty | Path to a suppressions file |
| `ai.provider` | string | empty | `openai`, `ollama`, or empty |
| `ai.model` | string | provider default | Model name |
| `ai.apikey` | string | empty | API key (prefer the env var) |
| `ai.endpoint` | string | provider default | Custom provider endpoint |

See the [CLI reference](cli.md) for the equivalent flags and [Suppressions](../user-guide/suppressions.md) for the suppressions file format.
