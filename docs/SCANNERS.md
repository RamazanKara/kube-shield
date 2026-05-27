# Scanner Reference

This reference lists the built-in kube-shield scanner families and stable check IDs. Use it when you need to understand what a finding means, decide whether a severity is expected, or update docs after changing scanner behavior.

Scanner results are posture signals, not a full Kubernetes audit. kube-shield focuses on API-visible misconfigurations that can be checked consistently from a Kubernetes client.

| Scanner | Checks | Category | Severity Range |
|---------|--------|----------|----------------|
| `workload` | 17 | `workload` | Critical to Info |
| `cis` | 14 | `cis` | Critical to Low |
| `rbac` | 12 | `rbac` | Critical to Medium |
| `netpol` | 6 | `netpol` | High to Medium |
| `secrets` | 6 | `secrets` | High to Info |

## Severity Levels

| Level | Meaning |
|-------|---------|
| Critical | Direct compromise or full cluster-control path is plausible |
| High | Significant security weakness or strong escalation path |
| Medium | Defense-in-depth gap or risky configuration |
| Low | Best-practice deviation |
| Info | Operational observation |

Severity is assigned by expected blast radius and exploitability. If a finding depends heavily on local policy or compensating controls, prefer the lower severity and explain the risk clearly in remediation text.

## Workload Scanner (`workload`)

Checks pod and container security configuration.

Use these findings to identify workloads that could escape expected pod boundaries, run with elevated privileges, or miss basic runtime hardening.

| Check ID | Severity | Title |
|----------|----------|-------|
| WL-001 | High | Pod uses host PID namespace |
| WL-002 | High | Pod uses host IPC namespace |
| WL-003 | High | Pod uses host network |
| WL-004 | Medium | Default service account with automounted token |
| WL-010 | Critical | Privileged container |
| WL-011 | Medium | No security context defined |
| WL-012 | High | Container may run as root |
| WL-013 | Medium | Privilege escalation allowed |
| WL-014 | Low | Writable root filesystem |
| WL-020 | Critical | SYS_ADMIN capability |
| WL-021 | Medium | NET_RAW capability |
| WL-022 | Critical | ALL capabilities granted |
| WL-023 | High | NET_ADMIN capability |
| WL-030 | Medium | Image uses latest/no tag |
| WL-031 | Low | No resource limits |
| WL-032 | Info | No resource requests |
| WL-033 | Info | No liveness probe |

Completed and failed pods are skipped.

## CIS Kubernetes Benchmark Scanner (`cis`)

Checks API-accessible controls from CIS Kubernetes Benchmark v1.12.

These checks cover the parts of the benchmark kube-shield can evaluate through the Kubernetes API. Node filesystem, control-plane host, and managed-provider settings are outside this scanner's scope.

| Check ID | Severity | Title | CIS Section |
|----------|----------|-------|-------------|
| CIS-4.1.1 | Critical | cluster-admin role bound to ServiceAccount | 4.1 RBAC |
| CIS-4.1.2 | High | ClusterRole with secret access | 4.1 RBAC |
| CIS-4.1.5 | Medium | Default SA has role binding | 4.1 RBAC |
| CIS-4.1.6 | Medium | Default SA automounts token | 4.1 RBAC |
| CIS-4.2.1 | Critical | Privileged container | 4.2 Pod Security |
| CIS-4.2.2 | High | Pod uses hostPID | 4.2 Pod Security |
| CIS-4.2.3 | High | Pod uses hostIPC | 4.2 Pod Security |
| CIS-4.2.4 | High | Pod uses hostNetwork | 4.2 Pod Security |
| CIS-4.2.6 | High | Container may run as root | 4.2 Pod Security |
| CIS-4.2.9 | Medium | Container has added capabilities | 4.2 Pod Security |
| CIS-4.3.1 | High | No network policy in namespace | 4.3 Network |
| CIS-4.4.1 | Medium | Secret exposed as env var | 4.4 Secrets |
| CIS-4.5.1 | Low | No resource quotas in namespace | 4.5 Policies |
| CIS-4.5.2 | Low | No LimitRange in namespace | 4.5 Policies |

System namespaces are skipped for namespace-scoped CIS checks.

## RBAC Scanner (`rbac`)

Detects over-privileged roles, risky verbs, and risky bindings.

These findings are most useful when reviewing service accounts used by workloads, automation, and human operators.

| Check ID | Severity | Title |
|----------|----------|-------|
| RBAC-001 | Critical | Wildcard permissions on all resources |
| RBAC-002 | High | Wildcard verbs |
| RBAC-003 | High | Wildcard resources |
| RBAC-010 | High | Secret read access |
| RBAC-011 | Critical | Secret write access |
| RBAC-020 | Critical | Privilege escalation verbs |
| RBAC-021 | High | Pod exec/attach access |
| RBAC-022 | Critical | Node proxy access |
| RBAC-023 | High | PersistentVolume write access |
| RBAC-030 | Critical | cluster-admin bound to ServiceAccount |
| RBAC-031 | Critical | cluster-admin bound to unauthenticated users |
| RBAC-032 | Medium | Role bound to default ServiceAccount |

Kubernetes system roles and common CNI system roles are skipped to reduce noise.

## Network Policy Scanner (`netpol`)

Checks namespace isolation and overly permissive NetworkPolicies.

The scanner evaluates declared NetworkPolicy objects. It does not prove runtime dataplane enforcement by a specific CNI plugin.

| Check ID | Severity | Title |
|----------|----------|-------|
| NET-001 | High | No network policies in namespace |
| NET-002 | Medium | No default-deny ingress policy |
| NET-003 | Medium | No default-deny egress policy |
| NET-010 | High | Allow-all ingress rule |
| NET-011 | Medium | Allow-all egress rule |
| NET-020 | Medium | Wide CIDR range in network policy |

System namespaces are skipped. An empty `policyTypes` field is interpreted using Kubernetes NetworkPolicy defaults.

## Secrets Scanner (`secrets`)

Detects secret exposure and broken secret references.

The scanner reports risky references and mount patterns. It does not read or print secret values.

| Check ID | Severity | Title |
|----------|----------|-------|
| SEC-001 | Medium | Secret exposed as environment variable |
| SEC-002 | High | Missing secret reference |
| SEC-003 | Medium | Entire secret exposed as env vars (envFrom) |
| SEC-004 | Medium | Secret volume with permissive file mode |
| SEC-005 | High | Secret mounted at sensitive path |
| SEC-010 | Info | Empty secret |

Optional secret references are not reported as missing.

## Scoring

The score is calculated from the filtered finding set:

```text
score = 100 - (critical*10 + high*5 + medium*2 + low*0.5)
```

Info findings do not reduce the score. Scores are clamped at zero.

| Score | Grade |
|-------|-------|
| 90-100 | A |
| 80-89 | B |
| 70-79 | C |
| 60-69 | D |
| 0-59 | F |

## Documentation Maintenance

When adding, removing, or changing a check:

- Keep `CheckID` stable unless the behavior is intentionally replaced.
- Update this file.
- Update README scanner counts when counts change.
- Add or update unit tests and E2E fixtures.
- Include the behavior change in `CHANGELOG.md`.
- Keep titles short enough to scan in table, JSON, SARIF, and TUI output.
