# Output & display

kube-shield can present results as a table, JSON, SARIF, or an interactive dashboard.

## Output formats

Set the format with `--output` / `-o`:

| Format | Use it for |
|--------|------------|
| `table` (default) | Human-readable terminal review |
| `json` | Pipelines and custom tooling; serializes the full report including `suppressedFindings` |
| `sarif` | GitHub Code Scanning and other SARIF consumers; includes a `helpUri` to each rule |

```bash
kube-shield scan -o json | jq '.summary'
kube-shield scan -o sarif > results.sarif
```

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

kube-shield ships completion scripts for bash, zsh, fish, and PowerShell. Homebrew installs them automatically. For other install methods:

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
