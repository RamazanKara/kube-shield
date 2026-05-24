# Security Policy

## Supported Versions

Security fixes are provided for the latest released version of kube-shield.

| Version | Supported |
| ------- | --------- |
| 1.x | Yes |
| 0.x | No |

## Reporting a Vulnerability

Do not open a public GitHub issue for a suspected vulnerability.

Use GitHub private vulnerability reporting when available:

<https://github.com/RamazanKara/kube-shield/security/advisories/new>

If that is unavailable, contact the maintainer through the GitHub profile at <https://github.com/RamazanKara> and request a private disclosure channel.

Please include:

- Affected version or commit.
- Clear reproduction steps.
- Impact and affected environments.
- Any known mitigations.

## Handling Expectations

Maintainers aim to:

- Acknowledge reports within 7 days.
- Confirm impact and affected versions.
- Coordinate a fix and release before public disclosure whenever possible.
- Credit reporters when they want public credit.

## Scope

In scope:

- Vulnerabilities in kube-shield code, release artifacts, containers, Helm chart, or CI release process.
- Findings that expose secrets, credentials, or cluster-sensitive data unexpectedly.
- Supply-chain issues in distributed artifacts.
- Bypass of documented release verification, signature, or attestation controls.

Out of scope:

- Findings already reported by kube-shield as cluster misconfigurations.
- Vulnerabilities in a user's Kubernetes cluster unrelated to kube-shield behavior.
- Denial-of-service testing against project infrastructure.
