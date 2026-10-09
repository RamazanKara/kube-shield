# Output & display

kube-shield can present results as a table, JSON, SARIF, Markdown, or an interactive dashboard.

## Output formats

Set the format with `--output` / `-o`:

| Format | Use it for |
|--------|------------|
| `table` (default) | Human-readable terminal review |
| `json` | Pipelines and custom tooling; serializes the full report including `suppressedFindings` |
| `sarif` | GitHub Code Scanning and other SARIF consumers; includes a `helpUri` to each rule |
| `markdown` | Issue descriptions, review notes, and CI summaries; includes remediation and suppression details |

```bash
kube-shield scan -o json | jq '.summary'
kube-shield scan -o sarif > results.sarif
kube-shield scan -o markdown > report.md
```

JSON severities are numeric: Info=0, Low=1, Medium=2, High=3, Critical=4. The `summary.bySeverity` keys use the same numbers as strings.

Markdown reports include the security score, severity counts, full resource names, descriptions, and remediation, with findings sorted by severity. Suppressed findings appear in a separate section with their approval ID, reason, and expiry. Markdown and HTML characters in report text are escaped so resource details cannot break tables or inject markup.

All scan formats use the same severity/category filters, suppressions, and `--exit-code` behavior. If a scanner fails, Markdown includes an incomplete-scan warning and labels the summary as covering completed scanners only; the command still exits non-zero after writing the partial report. Logs and optional AI explanations go to stderr, leaving stdout suitable for redirection.

## Interactive dashboard (TUI)

```bash
kube-shield dashboard
```

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

## Shell completion

kube-shield ships completion scripts for bash, zsh, fish, and PowerShell. For other install methods:

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

After loading the script, press Tab to complete values such as:

```text
kube-shield scan --output m           → markdown
kube-shield scan --scanners rbac,se   → rbac,secrets
kube-shield scan --severity h        → high
kube-shield rules show WL-01         → matching check IDs and titles
```

Scanner and category completion keeps the preceding comma-separated values and omits names already in that list. Dashboard scanners, AI providers, and the rule commands' output formats are also supported. These suggestions use only built-in metadata, without connecting to a cluster or reading configuration files.
