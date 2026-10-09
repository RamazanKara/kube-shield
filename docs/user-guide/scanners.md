# Scanners

kube-shield groups its checks into five scanners. Run a subset with `--scanners`, for example `kube-shield scan --scanners rbac,netpol`.

| Scanner | Checks | Severity range | Focus |
|---------|--------|----------------|-------|
| `workload` | 17 | Critical to Info | Pod and container security posture |
| `cis` | 23 | Critical to Low | CIS Kubernetes Benchmark API-accessible checks |
| `rbac` | 12 | Critical to Medium | Over-permissive roles and risky bindings |
| `netpol` | 6 | High to Medium | Missing isolation and permissive policies |
| `secrets` | 6 | High to Info | Secret exposure and reference hygiene |

For every check ID — with severity, confidence, data-access level, standards mapping (Pod Security Standards, CIS Kubernetes Benchmark), and remediation — see the generated [scanner reference](../reference/scanners.md).

The `cis` scanner covers the API-checkable subset of CIS Kubernetes Benchmark 2.0.x Policies recommendations. Its `CIS-5.*` check IDs align with Section 5 recommendation numbers, also carried in each rule's standards metadata and finding `cisRef` field. See the [scanner reference](../reference/scanners.md) for coverage and limitations, and the [v2 migration notes](https://github.com/RamazanKara/kube-shield/blob/main/CHANGELOG.md#migrating-from-v1x) when upgrading from v1.x.

## Scoring

Each scan produces a posture score and letter grade from the de-duplicated finding set:

```text
score = 100 - (critical*10 + high*5 + medium*2 + low*0.5)
```

Info findings do not reduce the score, and the score is clamped to zero. Grades: A (90–100), B (80–89), C (70–79), D (60–69), F (0–59). Known CIS/core overlaps are counted once for the summary; raw findings remain in JSON and SARIF output.

## Secret handling

Secret checks use pod specs and metadata-only Secret inventory by default. Secret values are never printed. `--read-secret-data` permits fetching Secret data for the opt-in `SEC-010` empty-secret check; use `--severity info` to include that finding. See the [threat model](../design/threat-model.md) for the full data-handling boundaries.
