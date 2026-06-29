# FAQ

## Does kube-shield modify my cluster?

No. kube-shield is strictly read-only. It lists and reads API objects and never creates, updates, or deletes anything.

## Does it read my Secrets?

Not by default. Secret checks use pod specs and metadata-only Secret inventory. kube-shield only reads Secret *data* when you pass `--read-secret-data`, which enables the single opt-in check `SEC-010`. See the [threat model](../design/threat-model.md).

## Does the AI feature send my data anywhere?

Only if you enable it. AI is off by default. When enabled, finding metadata (not Secret values) is sent to the configured provider; with the `ollama` provider it stays on your own infrastructure. See [AI explanations](../user-guide/ai-explanations.md).

## What does kube-shield *not* do?

It checks API-visible configuration. It is **not** a runtime threat detector, admission controller, node/host hardening auditor, cloud IAM reviewer, CNI dataplane prover, or image/vulnerability scanner. It complements those tools. The [threat model](../design/threat-model.md) lists the full non-goals.

## How is the posture score calculated?

`score = 100 - (critical*10 + high*5 + medium*2 + low*0.5)`, clamped to zero; Info findings don't reduce it. Grades: A (90–100) down to F (0–59). Details in [Scanners](../user-guide/scanners.md#scoring).

## How do I handle a false positive?

Add an entry to a [suppressions file](../user-guide/suppressions.md) with a reason and an expiry. Suppressed findings are excluded from `--exit-code` gating but kept in JSON/SARIF output for auditability. If you believe a check is wrong in general, please [open an issue](https://github.com/RamazanKara/kube-shield/issues).

## What permissions does it need?

Read access to pods, RBAC objects, network policies, namespaces, and Secret metadata. The [Helm chart](https://github.com/RamazanKara/kube-shield/blob/main/deploy/helm/README.md) ships a least-privilege `ClusterRole`.

## How does kube-shield compare to kube-bench, Polaris, or kubesec?

kube-shield focuses on a fast, API-only posture pass across several domains (workload, CIS-API subset, RBAC, network policy, secrets) with one binary, multiple output formats, suppressions, and an optional TUI. Tools like kube-bench (node/control-plane CIS), Polaris (workload best practices/admission), and kubesec (manifest scoring) overlap in places and are complementary; run what fits your workflow.

## Can I use it as a Go library?

No. As of the `cmd/` + `internal/` layout, application packages live under `internal/` and are not importable. kube-shield is consumed as the `kube-shield` CLI (or container image / Helm chart).

## How do I run it in CI?

Use `--output sarif` for code-scanning dashboards and `--exit-code --severity <level>` to fail the job. See [CI/CD integration](ci-cd.md) for GitHub Actions, GitLab CI, and Jenkins examples.
