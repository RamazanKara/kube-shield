# kube-shield

**Kubernetes Security Posture Manager — k9s for security.**

kube-shield is a Kubernetes security posture scanner for quick local reviews, CI gates, and scheduled cluster checks. It reads Kubernetes API objects, highlights risky workload, CIS Kubernetes Benchmark v1.12, RBAC, network policy, and secret patterns, then turns them into actionable findings.

Use it when you want a lightweight security pass that is easy to run, easy to read, and still friendly to automation.

## Why kube-shield

- Finds common Kubernetes posture issues without installing a controller first.
- Groups checks into workload, CIS, RBAC, network policy, and secrets scanners.
- Shows results as a readable table, JSON for pipelines, SARIF for GitHub Code Scanning, or an interactive TUI.
- Supports severity thresholds and `--exit-code` so CI fails only on the risks you care about.
- Includes structured remediation and optional AI explanations through OpenAI or local Ollama.
- Ships signed release archives, SBOMs, attestations, GHCR images, an OCI Helm chart, and a Homebrew cask.

## Scope

kube-shield checks Kubernetes API-visible configuration. It does not replace runtime threat detection, admission control, node hardening, cloud IAM review, or a full CIS audit of control-plane host files. It makes the most common cluster posture problems visible fast. See the [threat model](design/threat-model.md) for the full trust boundaries and non-goals.

## Get started

- [Installation](getting-started/installation.md) — Homebrew, Go, Docker, or signed archives.
- [Quick start](getting-started/quickstart.md) — your first scan in under a minute.
- [Recipes](guides/recipes.md) — CI gates, namespace audits, RBAC drift, secret hygiene.
- [CI/CD integration](guides/ci-cd.md) — GitHub Actions, GitLab CI, Jenkins.

## Learn more

| Section | Contents |
|---------|----------|
| [User guide](user-guide/scanners.md) | Scanners, suppressions, output formats, TUI, AI |
| [Reference](reference/cli.md) | CLI, configuration, and the full scanner catalog |
| [Guides](guides/troubleshooting.md) | Troubleshooting, FAQ, recipes, CI/CD |
| [Design](design/architecture.md) | Architecture and threat model |
| [Contributing](contributing/development.md) | Development workflow and project guidelines |
