# Scanner Reference

This document lists all security checks implemented by kube-shield.

## Workload Scanner (`workload`)

Checks pod and container security configurations.

| Check ID | Severity | Title |
|----------|----------|-------|
| WL-001 | High | Pod uses host PID namespace |
| WL-002 | High | Pod uses host IPC namespace |
| WL-003 | High | Pod uses host network |
| WL-004 | Medium | Default service account with automounted token |
| WL-010 | Critical | Privileged container |
| WL-011 | Medium | No security context defined |
| WL-012 | High | Container may run as root |
| WL-013 | High | Privilege escalation allowed |
| WL-014 | Medium | Writable root filesystem |
| WL-020 | Critical | SYS_ADMIN capability |
| WL-021 | Medium | NET_RAW capability |
| WL-022 | Critical | ALL capabilities granted |
| WL-023 | High | NET_ADMIN capability |
| WL-030 | Low | Image uses latest/no tag |
| WL-031 | Low | No resource limits |
| WL-032 | Low | No resource requests |
| WL-033 | Low | No liveness probe |

## CIS Kubernetes Benchmark Scanner (`cis`)

Checks based on CIS Kubernetes Benchmark v1.8.

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
| CIS-4.3.1 | Medium | No network policy in namespace | 4.3 Network |
| CIS-4.4.1 | Medium | Secret exposed as env var | 4.4 Secrets |
| CIS-4.5.1 | Low | No resource quotas in namespace | 4.5 Policies |
| CIS-4.5.2 | Low | No LimitRange in namespace | 4.5 Policies |

## RBAC Scanner (`rbac`)

Detects over-privileged roles and risky bindings.

| Check ID | Severity | Title |
|----------|----------|-------|
| RBAC-001 | Critical | Wildcard permissions on all resources |
| RBAC-002 | High | Wildcard verbs |
| RBAC-003 | High | Wildcard resources |
| RBAC-010 | High | Secret read access |
| RBAC-011 | Critical | Secret write access |
| RBAC-020 | Critical | Privilege escalation verbs (escalate/bind/impersonate) |
| RBAC-021 | High | Pod exec/attach access |
| RBAC-022 | High | Node proxy access |
| RBAC-023 | Medium | PersistentVolume write access |
| RBAC-030 | Critical | cluster-admin bound to ServiceAccount |
| RBAC-031 | Critical | cluster-admin bound to unauthenticated users |
| RBAC-032 | Medium | Role bound to default ServiceAccount |

## Network Policy Scanner (`netpol`)

Checks for missing or overly permissive network policies.

| Check ID | Severity | Title |
|----------|----------|-------|
| NET-001 | High | No network policies in namespace |
| NET-002 | Medium | No default-deny ingress policy |
| NET-003 | Medium | No default-deny egress policy |
| NET-010 | High | Allow-all ingress rule |
| NET-011 | High | Allow-all egress rule |
| NET-020 | Medium | Wide CIDR range in network policy |

## Secrets Scanner (`secrets`)

Detects insecure secret handling patterns.

| Check ID | Severity | Title |
|----------|----------|-------|
| SEC-001 | Medium | Secret exposed as environment variable |
| SEC-002 | Low | Missing secret reference |
| SEC-003 | Medium | Entire secret exposed as env vars (envFrom) |
| SEC-004 | High | Secret volume with permissive file mode |
| SEC-005 | High | Secret mounted at sensitive path |
| SEC-010 | Low | Empty secret |

## Severity Levels

| Level | Description |
|-------|-------------|
| Critical | Immediate exploitation risk, cluster compromise possible |
| High | Significant security weakness, escalation path exists |
| Medium | Security misconfiguration, defense-in-depth violation |
| Low | Best practice deviation, informational |
| Info | Observation, no direct risk |

## Scoring

The security score is calculated as:

```
score = 100 - (critical×10 + high×5 + medium×2 + low×0.5)
```

Grades: A (≥90), B (≥80), C (≥70), D (≥60), F (<60)
