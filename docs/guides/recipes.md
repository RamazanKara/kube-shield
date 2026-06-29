# Recipes

Practical, copy-pasteable scenarios. All commands use your current Kubernetes context unless `--context` is given.

## Gate CI on critical findings

Fail a pipeline only when something critical appears, and accept known risks via a suppressions file:

```bash
kube-shield scan --exit-code --severity critical \
  --suppressions suppressions.yaml
```

See [CI/CD integration](ci-cd.md) for full pipeline examples.

## Audit a single namespace

```bash
kube-shield scan --namespace production --severity medium
```

Useful for team-owned namespaces where you want a focused review without cluster-wide noise.

## RBAC drift detection

Run only the RBAC scanner and compare JSON output over time:

```bash
kube-shield scan --scanners rbac --output json > rbac-$(kubectl config current-context).json
```

Diff successive runs (or check the file into a private audit repo) to catch new wildcard roles, secret-access grants, or `cluster-admin` bindings.

## Secret hygiene audit

```bash
kube-shield scan --scanners secrets --severity info
```

By default this uses metadata-only Secret inventory. Only add `--read-secret-data` if you explicitly want the opt-in `SEC-010` empty-secret check — see [Scanners](../user-guide/scanners.md#secret-handling).

## Scheduled cluster scans

Deploy the Helm chart to run kube-shield as a `CronJob` and emit JSON for your log pipeline:

```bash
helm install kube-shield oci://ghcr.io/ramazankara/charts/kube-shield \
  --namespace kube-shield --create-namespace \
  --set schedule="0 */6 * * *" --set output=json
```

## Post-process JSON with jq

```bash
# Count findings by severity
kube-shield scan -o json | jq '.summary.bySeverity'

# List every critical finding's resource and title
kube-shield scan -o json \
  | jq -r '.findings[] | select(.severity=="CRITICAL") | "\(.resource.namespace)/\(.resource.name): \(.title)"'
```

## Explain findings with AI

```bash
kube-shield scan --severity high \
  --ai-provider ollama --ai-endpoint http://localhost:11434
```

Keeps data local via Ollama. See [AI explanations](../user-guide/ai-explanations.md).
