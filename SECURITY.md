# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

We take the security of kube-shield seriously. If you discover a security vulnerability, please report it responsibly.

**Please do NOT open a public GitHub issue for security vulnerabilities.**

### How to Report

1. Email: Send a detailed report to the project maintainers via GitHub's [private vulnerability reporting](https://github.com/RamazanKara/kube-shield/security/advisories/new).
2. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment**: Within 48 hours of your report.
- **Assessment**: We will investigate and determine the severity within 7 days.
- **Fix**: Critical vulnerabilities will be patched within 14 days.
- **Disclosure**: We will coordinate disclosure timing with you.

### Scope

The following are in scope:
- The kube-shield CLI binary
- The Helm chart and deployment manifests
- The Docker image
- AI provider integrations (API key handling, prompt injection)

### Out of Scope

- Vulnerabilities in upstream dependencies (report to the respective project)
- Issues requiring physical access to the machine
- Social engineering attacks

## Security Best Practices

When using kube-shield:

- **API Keys**: Use environment variables (`KUBE_SHIELD_AI_APIKEY`) instead of CLI flags for AI API keys
- **RBAC**: Deploy with minimal required permissions (the provided ClusterRole is read-only)
- **Network**: When using Ollama, ensure the endpoint is not publicly accessible
- **Image**: Always use signed, versioned container images from `ghcr.io/ramazankara/kube-shield`
