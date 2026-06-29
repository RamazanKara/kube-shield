# Quick start

kube-shield uses your current Kubernetes context (the same one `kubectl` uses), so a scan needs no setup beyond a working kubeconfig.

## Your first scan

```bash
kube-shield scan
```

This runs all five scanners across all namespaces and prints a table of findings with a posture score and letter grade.

## Common next steps

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

## Launch the dashboard

```bash
kube-shield dashboard
kube-shield dashboard --namespace production
```

The interactive TUI lets you browse, filter, and drill into findings. See [Output & display](../user-guide/output-and-display.md) for keybindings.

## AI explanations (optional)

```bash
kube-shield scan --ai-provider openai --ai-api-key "$OPENAI_API_KEY"
kube-shield scan --ai-provider ollama --ai-endpoint http://localhost:11434
```

In the TUI, press `e` on a finding's detail view to request an explanation. See [AI explanations](../user-guide/ai-explanations.md).

## Where to go next

- [Recipes](../guides/recipes.md) for real-world scenarios.
- [CI/CD integration](../guides/ci-cd.md) to gate pipelines.
- [Configuration reference](../reference/configuration.md) for every flag, env var, and config key.
- [Troubleshooting](../guides/troubleshooting.md) if a scan does not behave as expected.
