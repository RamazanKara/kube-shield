# kube-shield Helm chart

Runs kube-shield as a scheduled in-cluster security scan via a Kubernetes `CronJob`. The chart creates a least-privilege `ServiceAccount` and `ClusterRole` so kube-shield can read API objects (and list `secrets` metadata) without elevated access.

## Install

From the published OCI registry:

```bash
helm install kube-shield oci://ghcr.io/ramazankara/charts/kube-shield \
  --version 1.1.0 \
  --namespace kube-shield \
  --create-namespace
```

From the local chart (development):

```bash
helm install kube-shield deploy/helm \
  --namespace kube-shield \
  --create-namespace \
  --set severity=medium
```

## Values

| Value | Default | Description |
|-------|---------|-------------|
| `schedule` | `0 */6 * * *` | CronJob schedule (cron format) |
| `scanners` | all five | Scanners to run: `workload`, `cis`, `rbac`, `netpol`, `secrets` |
| `severity` | `low` | Minimum severity to report (`critical`–`info`) |
| `output` | `json` | Report output format (`json`, `table`, `sarif`) |
| `readSecretData` | `false` | Enable `--read-secret-data` (required only for `SEC-010`) |
| `image.repository` | `ghcr.io/ramazankara/kube-shield` | Container image repository |
| `image.tag` | chart `appVersion` | Container image tag |
| `image.pullPolicy` | `IfNotPresent` | Image pull policy |
| `imagePullSecrets` | `[]` | Pull secrets for private registries |
| `serviceAccount.create` | `true` | Create a ServiceAccount |
| `serviceAccount.name` | `kube-shield` | ServiceAccount name |
| `resources` | 100m/128Mi requests, 200m/256Mi limits | Container resources |
| `nodeSelector` / `tolerations` / `affinity` | `{}` / `[]` / `{}` | Scheduling controls |

See [values.yaml](values.yaml) for the full list.

## RBAC and Secrets

The chart grants `list` on core `secrets` so kube-shield can validate Secret references with metadata-only requests. Kubernetes RBAC does not distinguish metadata-only Secret reads from full Secret reads, so kube-shield avoids requesting full Secret objects unless `readSecretData=true` is set for `SEC-010`. See the [threat model](../../docs/design/threat-model.md) for details.
