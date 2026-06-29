# Threat Model

kube-shield is a client-side Kubernetes posture scanner. It reads Kubernetes API objects, reports configuration risks, and exits. It does not install an admission controller, controller, webhook, or runtime sensor.

## Trust Boundaries

- The local CLI process runs with the privileges of the user and kubeconfig supplied to it.
- The Helm chart runs as a CronJob using the chart ServiceAccount and ClusterRole.
- Kubernetes API responses are treated as cluster-sensitive input and are never sent to third parties unless an AI provider is explicitly configured.
- Report outputs may contain resource names, namespaces, RBAC subjects, image names, and policy structure. Treat JSON and SARIF reports as cluster-sensitive artifacts.

## Kubernetes API Access

kube-shield requests read-only API access. The built-in scanners inspect pods, namespaces, services, service accounts, RBAC objects, NetworkPolicies, ResourceQuotas, LimitRanges, and Secret metadata.

The Helm chart grants `list` on core `secrets` so missing Secret references can be validated. Kubernetes RBAC does not distinguish metadata-only Secret reads from full Secret reads, so default secret checks use Kubernetes metadata-only requests for Secret inventory and pod specs for references. kube-shield does not request Secret data by default.

`SEC-010` detects empty Opaque Secrets and requires Secret data access. It is disabled by default and only runs when `--read-secret-data`, `read-secret-data: true`, or `readSecretData=true` in Helm is explicitly enabled.

## Secret Handling

- kube-shield must not print Secret values.
- Default scans must not deserialize Secret data.
- Tests and examples must use synthetic values only.
- Bug reports and support requests should include sanitized manifests and never include live credentials, kubeconfig tokens, customer data, or production Secret values.

## AI Provider Data Egress

AI explanations are disabled by default. When `--ai-provider` is configured, selected findings are sent to the configured provider. Finding data can include resource names, namespaces, image names, RBAC subjects, descriptions, and remediation text.

Use a local provider such as Ollama when findings cannot leave the environment. Do not enable an external AI provider for clusters where resource metadata is confidential unless that transfer is approved by policy.

## Suppressions

Suppressions are explicit risk acceptances. Each entry requires an ID, a `checkId` or `fingerprint`, a reason, and an expiry date. Expired or malformed suppressions fail closed so stale exceptions do not silently hide findings.

Suppressed findings are removed from exit-code decisions but remain present in JSON and SARIF output for auditability.

## Release Integrity

Releases are built by GitHub Actions from tags. Release archives, checksums, SBOMs, container images, and Helm charts are signed or attested through the release workflow. Verification instructions are documented in the README and release runbook.

Repository automation uses pinned GitHub Actions where practical, Dependabot updates, govulncheck, gosec, linting, race-enabled tests, coverage gating, E2E tests, and OpenSSF Scorecard.

## Non-Goals

kube-shield does not:

- Detect runtime attacks or malicious process behavior.
- Enforce admission policy.
- Replace cloud IAM review, node hardening, managed Kubernetes control-plane review, or a complete CIS audit.
- Prove NetworkPolicy enforcement by the active CNI dataplane.
- Validate container image vulnerabilities or provenance.
- Guarantee that compensating controls outside Kubernetes API objects are present.
