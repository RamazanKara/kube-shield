# Suppressions

Suppressions let you accept a known finding for a bounded time without weakening the overall scan. They are **fail-closed**: a malformed entry or a missing/expired `expires` stops the scan rather than silently passing.

```bash
kube-shield scan --suppressions suppressions.yaml --exit-code
```

## Behavior

- Suppressed findings **do not** trigger `--exit-code`.
- JSON output includes them under `suppressedFindings`.
- SARIF marks them as external suppressions.
- Summaries include a `suppressedTotal` count.

This keeps an auditable trail: a suppressed finding is hidden from gating but never erased from the report.

## File format

Match a finding by `checkId` and/or `fingerprint`, optionally narrowed to a specific resource. Every entry requires a unique `id`, a `reason`, and an `expires` date.

```yaml
suppressions:
  - id: accepted-risk-2026-001
    checkId: WL-010
    resource:
      kind: Pod
      namespace: production
      name: legacy-worker
    reason: Accepted temporarily while the workload is migrated.
    expires: 2026-12-31
```

A ready-to-copy example with multiple entries lives in [`examples/suppressions.yaml`](https://github.com/RamazanKara/kube-shield/blob/main/examples/suppressions.yaml).

## Fields

| Field | Required | Description |
|-------|----------|-------------|
| `id` | yes | Unique identifier for the suppression (for audit) |
| `reason` | yes | Why the finding is accepted |
| `expires` | yes | Date (`YYYY-MM-DD`) or RFC 3339 timestamp after which the suppression is invalid |
| `checkId` | one of checkId/fingerprint | The rule to suppress, e.g. `WL-010` |
| `fingerprint` | one of checkId/fingerprint | A finding's stable fingerprint |
| `resource.kind` / `.name` / `.namespace` | no | Narrow the match to one resource |
