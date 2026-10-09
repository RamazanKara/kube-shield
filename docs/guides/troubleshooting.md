# Troubleshooting

Solutions to the most common issues. If something here doesn't cover your case, see [Support](https://github.com/RamazanKara/kube-shield/blob/main/SUPPORT.md).

## `kube-shield: command not found` after `go install`

`go install` places the binary in `$(go env GOPATH)/bin`. Make sure that directory is on your `PATH`:

```bash
export PATH="$(go env GOPATH)/bin:$PATH"
```

## "The connection to the server ... was refused" / "no configuration has been provided"

kube-shield resolves cluster credentials as follows:

1. `--kubeconfig` selects one file. Otherwise `$KUBECONFIG` is a path list (colon-separated on Unix, semicolon-separated on Windows), then `~/.kube/config`.
2. In-cluster credentials are used when no kubeconfig or context override is supplied.
3. `--context` selects the context; otherwise the current context is used.

Confirm `kubectl get nodes` works first. In containers, mount your kubeconfig read-only (`-v "$HOME/.kube:/kube:ro"`) and pass `--kubeconfig /kube/config`.

## "forbidden" or partial results

kube-shield needs **read** access to the objects it scans (pods, RBAC, network policies, namespaces, and Secret metadata). With insufficient permissions, the affected scanner fails and kube-shield returns a partial-results error while still reporting what it could read.

- For least-privilege access, deploy the [Helm chart](https://github.com/RamazanKara/kube-shield/blob/main/deploy/helm/README.md), which provisions a suitable read-only `ClusterRole`.
- To scan only what you can read, restrict with `--namespace` and/or `--scanners`.

## Scans are slow or time out

Large clusters take longer to enumerate. Options:

- Raise the deadline: `--timeout 10m`.
- Narrow the scope: `--namespace <ns>` or `--scanners rbac,netpol`.
- Filter noise with `--severity high` (this affects reporting, not scan time).

## A scan stops with a suppressions error

Suppressions are **fail-closed**. A scan aborts if a suppression entry is malformed, is missing a `reason`, or has a missing/expired `expires`. Fix or remove the offending entry. See [Suppressions](../user-guide/suppressions.md).

## `SEC-010` never fires

`SEC-010` reads Secret data and is opt-in. Enable it explicitly:

```bash
kube-shield scan --read-secret-data --severity info
```

All other secret checks run without it, using metadata only.

## AI explanations fail or hang

- Confirm the provider is reachable: for Ollama, that `--ai-endpoint` (default `http://localhost:11434`) is serving; for OpenAI, that the API key is valid.
- AI is optional — a provider error does not block the scan itself.
- Prefer `KUBE_SHIELD_AI_APIKEY` over `--ai-api-key` to keep the key out of shell history.

## Empty output / no findings

A clean namespace can legitimately produce no findings. To confirm the scan ran, lower the threshold (`--severity info`) or target a namespace you expect issues in. Use `-o json | jq '.summary'` to see counts.
