package cis

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/RamazanKara/kube-shield/v2/internal/scanner/engine"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Scanner implements CIS Kubernetes Benchmark checks that can be performed via API.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string              { return "cis" }
func (s *Scanner) Category() engine.Category { return engine.CategoryCIS }
func (s *Scanner) Description() string {
	return "Runs CIS Kubernetes Benchmark checks accessible via the Kubernetes API"
}

func (s *Scanner) Scan(ctx context.Context, client kubernetes.Interface, namespace string) (*engine.ScanResult, error) {
	var findings []engine.Finding

	// Benchmark Policies section — these are the checks we can perform via API access

	// Benchmark 5.1 RBAC and Service Accounts
	f, err := checkRBACPolicies(ctx, client, namespace)
	if err != nil {
		return nil, err
	}
	findings = append(findings, f...)

	// Benchmark 5.2 Pod Security Standards
	f, err = checkPodSecurity(ctx, client, namespace)
	if err != nil {
		return nil, err
	}
	findings = append(findings, f...)

	// Benchmark 5.3 Network Policies and CNI
	f, err = checkNetworkPolicies(ctx, client, namespace)
	if err != nil {
		return nil, err
	}
	findings = append(findings, f...)

	// Benchmark 5.4 Secrets Management
	f, err = checkSecretsManagement(ctx, client, namespace)
	if err != nil {
		return nil, err
	}
	findings = append(findings, f...)

	f, err = checkAdmissionPolicies(ctx, client, namespace)
	if err != nil {
		return nil, err
	}
	findings = append(findings, f...)

	return &engine.ScanResult{
		Scanner:  s.Name(),
		Findings: findings,
	}, nil
}

// Benchmark 5.1 RBAC and Service Accounts
func checkRBACPolicies(ctx context.Context, client kubernetes.Interface, namespace string) ([]engine.Finding, error) {
	var findings []engine.Finding

	// CIS 5.1.1 - Ensure cluster-admin role is only used where required
	crbs, err := client.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	for i := range crbs.Items {
		crb := &crbs.Items[i]
		findings = append(findings, checkSystemMasters(crb.Subjects, engine.Resource{Kind: "ClusterRoleBinding", Name: crb.Name})...)
		if crb.RoleRef.Name == "cluster-admin" {
			for _, subj := range crb.Subjects {
				if subj.Kind == "ServiceAccount" {
					findings = append(findings, engine.Finding{
						ID:          fmt.Sprintf("CIS-5.1.1-%s-%s", crb.Name, subj.Name),
						CheckID:     "CIS-5.1.1",
						Title:       fmt.Sprintf("cluster-admin role bound to SA: %s/%s", subj.Namespace, subj.Name),
						Description: "CIS 5.1.1: Ensure that the cluster-admin role is only used where required. ServiceAccounts should not be bound to cluster-admin.",
						Severity:    engine.SeverityCritical,
						Category:    engine.CategoryCIS,
						Resource:    engine.Resource{Kind: "ClusterRoleBinding", Name: crb.Name},
						Remediation: "Create a specific ClusterRole/Role with minimum permissions and bind it instead of cluster-admin.",
						CISRef:      "5.1.1",
					})
				}
			}
		}
	}

	// CIS 5.1.2 - Minimize access to secrets
	clusterRoles, err := client.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	for i := range clusterRoles.Items {
		cr := &clusterRoles.Items[i]
		if isDefaultClusterRole(cr.Name) {
			continue
		}
		findings = append(findings, checkRolePermissions(cr.Rules, engine.Resource{Kind: "ClusterRole", Name: cr.Name})...)
		for _, rule := range cr.Rules {
			if hasResource(rule, "secrets") && hasVerb(rule, "get", "list", "watch") {
				findings = append(findings, engine.Finding{
					ID:          fmt.Sprintf("CIS-5.1.2-%s", cr.Name),
					CheckID:     "CIS-5.1.2",
					Title:       fmt.Sprintf("ClusterRole with secret access: %s", cr.Name),
					Description: "CIS 5.1.2: Minimize access to secrets. ClusterRole grants access to read secrets cluster-wide.",
					Severity:    engine.SeverityHigh,
					Category:    engine.CategoryCIS,
					Resource:    engine.Resource{Kind: "ClusterRole", Name: cr.Name},
					Remediation: "Restrict secret access to namespace-scoped Roles instead of ClusterRoles where possible.",
					CISRef:      "5.1.2",
				})
				break
			}
		}
	}

	roles, err := client.RbacV1().Roles(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for i := range roles.Items {
		r := &roles.Items[i]
		if isSystemNamespace(r.Namespace) || strings.HasPrefix(r.Name, "system:") {
			continue
		}
		findings = append(findings, checkRolePermissions(r.Rules, engine.Resource{Kind: "Role", Name: r.Name, Namespace: r.Namespace})...)
	}

	rbs, err := client.RbacV1().RoleBindings(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for i := range rbs.Items {
		rb := &rbs.Items[i]
		if !isSystemNamespace(rb.Namespace) {
			findings = append(findings, checkSystemMasters(rb.Subjects, engine.Resource{Kind: "RoleBinding", Name: rb.Name, Namespace: rb.Namespace})...)
		}
	}

	serviceAccounts, err := client.CoreV1().ServiceAccounts(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	for i := range serviceAccounts.Items {
		sa := &serviceAccounts.Items[i]
		if isSystemNamespace(sa.Namespace) {
			continue
		}
		// CIS 5.1.6 applies to every ServiceAccount, including dedicated accounts.
		if sa.AutomountServiceAccountToken == nil || *sa.AutomountServiceAccountToken {
			id := fmt.Sprintf("CIS-5.1.6-%s", sa.Namespace)
			if sa.Name != "default" {
				id += "/" + sa.Name
			}
			findings = append(findings, engine.Finding{
				ID:          id,
				CheckID:     "CIS-5.1.6",
				Title:       fmt.Sprintf("ServiceAccount automounts token: %s/%s", sa.Namespace, sa.Name),
				Description: "CIS 5.1.6: Ensure that Service Account Tokens are only mounted where necessary. This ServiceAccount enables token automounting by default.",
				Severity:    engine.SeverityMedium,
				Category:    engine.CategoryCIS,
				Resource:    engine.Resource{Kind: "ServiceAccount", Name: sa.Name, Namespace: sa.Namespace},
				Remediation: "Set automountServiceAccountToken: false on ServiceAccounts that do not need API access.",
				CISRef:      "5.1.6",
			})
		}
		if sa.Name != "default" {
			continue
		}
		for j := range rbs.Items {
			rb := &rbs.Items[j]
			if rb.Namespace != sa.Namespace {
				continue
			}
			for _, subj := range rb.Subjects {
				if subj.Kind == "ServiceAccount" && subj.Name == "default" &&
					(subj.Namespace == sa.Namespace || subj.Namespace == "" && rb.Namespace == sa.Namespace) {
					findings = append(findings, engine.Finding{
						ID:          fmt.Sprintf("CIS-5.1.5-%s-%s", sa.Namespace, rb.Name),
						CheckID:     "CIS-5.1.5",
						Title:       fmt.Sprintf("Default SA has role binding in %s", sa.Namespace),
						Description: "CIS 5.1.5: Ensure that default service accounts are not actively used. The default SA should not have additional roles bound to it.",
						Severity:    engine.SeverityMedium,
						Category:    engine.CategoryCIS,
						Resource:    engine.Resource{Kind: "ServiceAccount", Name: "default", Namespace: sa.Namespace},
						Remediation: "Create dedicated ServiceAccounts for workloads. Remove role bindings from the default SA.",
						CISRef:      "5.1.5",
					})
				}
			}
		}
	}

	return findings, nil
}

func checkRolePermissions(rules []rbacv1.PolicyRule, res engine.Resource) []engine.Finding {
	var createPods, approveCSR, accessWebhooks, createTokens bool
	for _, rule := range rules {
		coreGroup := slices.Contains(rule.APIGroups, "") || slices.Contains(rule.APIGroups, "*")
		createPods = createPods || coreGroup && hasResource(rule, "pods") && hasVerb(rule, "create")
		createTokens = createTokens || coreGroup && hasResource(rule, "serviceaccounts/token") && hasVerb(rule, "create")
		if res.Kind == "ClusterRole" {
			certGroup := slices.Contains(rule.APIGroups, "certificates.k8s.io") || slices.Contains(rule.APIGroups, "*")
			approveCSR = approveCSR || certGroup && hasResource(rule, "certificatesigningrequests/approval") && hasVerb(rule, "update", "patch")
			admissionGroup := slices.Contains(rule.APIGroups, "admissionregistration.k8s.io") || slices.Contains(rule.APIGroups, "*")
			accessWebhooks = accessWebhooks || admissionGroup && len(rule.Verbs) > 0 &&
				(hasResource(rule, "validatingwebhookconfigurations") || hasResource(rule, "mutatingwebhookconfigurations"))
		}
	}
	var findings []engine.Finding
	if createPods {
		findings = append(findings, engine.Finding{
			ID:          fmt.Sprintf("CIS-5.1.4-%s", res.String()),
			CheckID:     "CIS-5.1.4",
			Title:       fmt.Sprintf("Role can create pods: %s", res.Name),
			Description: "CIS 5.1.4: Minimize access to create pods. Pod creation can expose other workload identities and resources in the namespace.",
			Severity:    engine.SeverityHigh,
			Category:    engine.CategoryCIS,
			Resource:    res,
			Remediation: "Remove create access to pods where it is not required.",
			CISRef:      "5.1.4",
		})
	}
	if approveCSR {
		findings = append(findings, engine.Finding{
			ID:          fmt.Sprintf("CIS-5.1.11-%s", res.String()),
			CheckID:     "CIS-5.1.11",
			Title:       fmt.Sprintf("Role can approve certificate requests: %s", res.Name),
			Description: "CIS 5.1.11: Minimize access to the approval sub-resource of certificatesigningrequests objects.",
			Severity:    engine.SeverityHigh,
			Category:    engine.CategoryCIS,
			Resource:    res,
			Remediation: "Remove update and patch access to certificatesigningrequests/approval where it is not required.",
			CISRef:      "5.1.11",
		})
	}
	if accessWebhooks {
		findings = append(findings, engine.Finding{
			ID:          fmt.Sprintf("CIS-5.1.12-%s", res.String()),
			CheckID:     "CIS-5.1.12",
			Title:       fmt.Sprintf("Role has webhook configuration access: %s", res.Name),
			Description: "CIS 5.1.12: Minimize access to webhook configuration objects. Review access to admission webhook configuration.",
			Severity:    engine.SeverityHigh,
			Category:    engine.CategoryCIS,
			Resource:    res,
			Remediation: "Restrict access to validatingwebhookconfigurations and mutatingwebhookconfigurations to required administrators.",
			CISRef:      "5.1.12",
		})
	}
	if createTokens {
		findings = append(findings, engine.Finding{
			ID:          fmt.Sprintf("CIS-5.1.13-%s", res.String()),
			CheckID:     "CIS-5.1.13",
			Title:       fmt.Sprintf("Role can create ServiceAccount tokens: %s", res.Name),
			Description: "CIS 5.1.13: Minimize access to service account token creation. Token creation can expose other workload identities.",
			Severity:    engine.SeverityHigh,
			Category:    engine.CategoryCIS,
			Resource:    res,
			Remediation: "Remove create access to serviceaccounts/token where it is not required.",
			CISRef:      "5.1.13",
		})
	}
	return findings
}

func checkSystemMasters(subjects []rbacv1.Subject, res engine.Resource) []engine.Finding {
	for _, subject := range subjects {
		if subject.Kind == "Group" && subject.Name == "system:masters" {
			return []engine.Finding{{
				ID:          fmt.Sprintf("CIS-5.1.7-%s", res.String()),
				CheckID:     "CIS-5.1.7",
				Title:       fmt.Sprintf("Binding references system:masters: %s", res.Name),
				Description: "CIS 5.1.7: Avoid use of the system:masters group. This binding references the group; membership and client certificates cannot be audited through RBAC objects alone.",
				Severity:    engine.SeverityHigh,
				Category:    engine.CategoryCIS,
				Resource:    res,
				Remediation: "Review identities and credentials using system:masters and replace them with least-privilege groups. Removing this binding alone does not revoke the group's authorization bypass.",
				CISRef:      "5.1.7",
			}}
		}
	}
	return nil
}

// Benchmark 5.2 Pod Security Standards
func checkPodSecurity(ctx context.Context, client kubernetes.Interface, namespace string) ([]engine.Finding, error) {
	var findings []engine.Finding

	var pods *corev1.PodList
	var err error
	if namespace != "" {
		pods, err = client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	} else {
		pods, err = client.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	}
	if err != nil {
		return nil, err
	}

	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
			continue
		}
		if isSystemNamespace(pod.Namespace) {
			continue
		}

		res := engine.Resource{Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace}

		if pod.Spec.AutomountServiceAccountToken != nil && *pod.Spec.AutomountServiceAccountToken {
			findings = append(findings, engine.Finding{
				ID:          fmt.Sprintf("CIS-5.1.6-%s/%s/pod", pod.Namespace, pod.Name),
				CheckID:     "CIS-5.1.6",
				Title:       fmt.Sprintf("Pod explicitly automounts token: %s", pod.Name),
				Description: "CIS 5.1.6: Ensure that Service Account Tokens are only mounted where necessary. This pod enables token automounting, overriding the ServiceAccount setting.",
				Severity:    engine.SeverityMedium,
				Category:    engine.CategoryCIS,
				Resource:    res,
				Remediation: "Set spec.automountServiceAccountToken: false unless the pod needs API access.",
				CISRef:      "5.1.6",
			})
		}

		if pod.Namespace == "default" {
			findings = append(findings, engine.Finding{
				ID:          fmt.Sprintf("CIS-5.6.4-%s/%s", pod.Namespace, pod.Name),
				CheckID:     "CIS-5.6.4",
				Title:       fmt.Sprintf("Pod uses the default namespace: %s", pod.Name),
				Description: "CIS 5.6.4: The default namespace should not be used for workloads.",
				Severity:    engine.SeverityLow,
				Category:    engine.CategoryCIS,
				Resource:    res,
				Remediation: "Move the workload to a dedicated namespace with appropriate access and network policies.",
				CISRef:      "5.6.4",
			})
		}

		containers := append([]corev1.Container(nil), pod.Spec.Containers...)
		containers = append(containers, pod.Spec.InitContainers...)
		for _, c := range pod.Spec.EphemeralContainers {
			containers = append(containers, corev1.Container(c.EphemeralContainerCommon))
		}
		for _, c := range containers {
			// CIS 5.2.2 - Minimize admission of privileged containers
			if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
				findings = append(findings, engine.Finding{
					ID:          fmt.Sprintf("CIS-5.2.2-%s/%s/%s", pod.Namespace, pod.Name, c.Name),
					CheckID:     "CIS-5.2.2",
					Title:       fmt.Sprintf("Privileged container: %s/%s", pod.Name, c.Name),
					Description: "CIS 5.2.2: Minimize the admission of privileged containers.",
					Severity:    engine.SeverityCritical,
					Category:    engine.CategoryCIS,
					Resource:    res,
					Remediation: "Do not run containers in privileged mode. Use specific capabilities instead.",
					CISRef:      "5.2.2",
				})
			}

			windows := pod.Spec.OS != nil && pod.Spec.OS.Name == corev1.Windows
			var nonRoot *bool
			var runAsUser *int64
			var seccomp *corev1.SeccompProfile
			var hostProcess *bool
			if sc := pod.Spec.SecurityContext; sc != nil {
				nonRoot, runAsUser, seccomp = sc.RunAsNonRoot, sc.RunAsUser, sc.SeccompProfile
				if sc.WindowsOptions != nil {
					hostProcess = sc.WindowsOptions.HostProcess
				}
			}
			if sc := c.SecurityContext; sc != nil {
				if sc.RunAsNonRoot != nil {
					nonRoot = sc.RunAsNonRoot
				}
				if sc.RunAsUser != nil {
					runAsUser = sc.RunAsUser
				}
				if sc.SeccompProfile != nil {
					seccomp = sc.SeccompProfile
				}
				if sc.WindowsOptions != nil && sc.WindowsOptions.HostProcess != nil {
					hostProcess = sc.WindowsOptions.HostProcess
				}
			}

			// Container security settings take precedence over pod defaults.
			if !windows && (nonRoot == nil || !*nonRoot) && (runAsUser == nil || *runAsUser == 0) {
				findings = append(findings, engine.Finding{
					ID:          fmt.Sprintf("CIS-5.2.7-%s/%s/%s", pod.Namespace, pod.Name, c.Name),
					CheckID:     "CIS-5.2.7",
					Title:       fmt.Sprintf("Container may run as root: %s/%s", pod.Name, c.Name),
					Description: "CIS 5.2.7: Minimize the admission of root containers.",
					Severity:    engine.SeverityHigh,
					Category:    engine.CategoryCIS,
					Resource:    res,
					Remediation: "Set securityContext.runAsNonRoot: true and runAsUser to a non-zero value.",
					CISRef:      "5.2.7",
				})
			}

			dropsAll, addsCapabilities := false, false
			if c.SecurityContext != nil && c.SecurityContext.Capabilities != nil {
				dropsAll = slices.Contains(c.SecurityContext.Capabilities.Drop, corev1.Capability("ALL"))
				addsCapabilities = len(c.SecurityContext.Capabilities.Add) > 0
			}
			if !windows && (!dropsAll || addsCapabilities) {
				findings = append(findings, engine.Finding{
					ID:          fmt.Sprintf("CIS-5.2.9-%s/%s/%s", pod.Namespace, pod.Name, c.Name),
					CheckID:     "CIS-5.2.9",
					Title:       fmt.Sprintf("Container has capabilities assigned: %s/%s", pod.Name, c.Name),
					Description: "CIS 5.2.9: Minimize the admission of containers with capabilities assigned.",
					Severity:    engine.SeverityMedium,
					Category:    engine.CategoryCIS,
					Resource:    res,
					Remediation: "Remove added capabilities. Drop ALL capabilities and add only those strictly required.",
					CISRef:      "5.2.9",
				})
			}

			if hostProcess != nil && *hostProcess {
				findings = append(findings, engine.Finding{
					ID:          fmt.Sprintf("CIS-5.2.10-%s/%s/%s", pod.Namespace, pod.Name, c.Name),
					CheckID:     "CIS-5.2.10",
					Title:       fmt.Sprintf("Windows HostProcess container: %s/%s", pod.Name, c.Name),
					Description: "CIS 5.2.10: Minimize the admission of Windows HostProcess containers.",
					Severity:    engine.SeverityCritical,
					Category:    engine.CategoryCIS,
					Resource:    res,
					Remediation: "Set securityContext.windowsOptions.hostProcess to false at pod and container level.",
					CISRef:      "5.2.10",
				})
			}

			for _, port := range c.Ports {
				if port.HostPort == 0 {
					continue
				}
				findings = append(findings, engine.Finding{
					ID:          fmt.Sprintf("CIS-5.2.12-%s/%s/%s", pod.Namespace, pod.Name, c.Name),
					CheckID:     "CIS-5.2.12",
					Title:       fmt.Sprintf("Container uses host ports: %s/%s", pod.Name, c.Name),
					Description: "CIS 5.2.12: Minimize the admission of containers which use HostPorts.",
					Severity:    engine.SeverityHigh,
					Category:    engine.CategoryCIS,
					Resource:    res,
					Remediation: "Remove hostPort mappings and expose the workload through a Service.",
					CISRef:      "5.2.12",
				})
				break
			}

			if !windows && (seccomp == nil || seccomp.Type == corev1.SeccompProfileTypeUnconfined) {
				findings = append(findings, engine.Finding{
					ID:          fmt.Sprintf("CIS-5.6.2-%s/%s/%s", pod.Namespace, pod.Name, c.Name),
					CheckID:     "CIS-5.6.2",
					Title:       fmt.Sprintf("Container lacks a seccomp profile: %s/%s", pod.Name, c.Name),
					Description: "CIS 5.6.2: Ensure that the seccomp profile is set to RuntimeDefault or a reviewed Localhost profile. Node-level defaults cannot be verified from the pod spec.",
					Severity:    engine.SeverityMedium,
					Category:    engine.CategoryCIS,
					Resource:    res,
					Remediation: "Set securityContext.seccompProfile.type to RuntimeDefault at pod or container level.",
					CISRef:      "5.6.2",
				})
			}
		}

		for _, volume := range pod.Spec.Volumes {
			if volume.HostPath != nil {
				findings = append(findings, engine.Finding{
					ID:          fmt.Sprintf("CIS-5.2.11-%s/%s/%s", pod.Namespace, pod.Name, volume.Name),
					CheckID:     "CIS-5.2.11",
					Title:       fmt.Sprintf("Pod uses HostPath volume: %s/%s", pod.Name, volume.Name),
					Description: "CIS 5.2.11: Minimize the admission of HostPath volumes.",
					Severity:    engine.SeverityHigh,
					Category:    engine.CategoryCIS,
					Resource:    res,
					Remediation: "Replace hostPath volumes with storage that does not expose the node filesystem.",
					CISRef:      "5.2.11",
				})
			}
		}

		// CIS 5.2.3 - Minimize admission of containers with hostPID
		if pod.Spec.HostPID {
			findings = append(findings, engine.Finding{
				ID:          fmt.Sprintf("CIS-5.2.3-%s/%s", pod.Namespace, pod.Name),
				CheckID:     "CIS-5.2.3",
				Title:       fmt.Sprintf("Pod uses hostPID: %s", pod.Name),
				Description: "CIS 5.2.3: Minimize the admission of containers wishing to share the host process ID namespace.",
				Severity:    engine.SeverityHigh,
				Category:    engine.CategoryCIS,
				Resource:    res,
				Remediation: "Set spec.hostPID to false.",
				CISRef:      "5.2.3",
			})
		}

		// CIS 5.2.4 - Minimize admission of containers with hostIPC
		if pod.Spec.HostIPC {
			findings = append(findings, engine.Finding{
				ID:          fmt.Sprintf("CIS-5.2.4-%s/%s", pod.Namespace, pod.Name),
				CheckID:     "CIS-5.2.4",
				Title:       fmt.Sprintf("Pod uses hostIPC: %s", pod.Name),
				Description: "CIS 5.2.4: Minimize the admission of containers wishing to share the host IPC namespace.",
				Severity:    engine.SeverityHigh,
				Category:    engine.CategoryCIS,
				Resource:    res,
				Remediation: "Set spec.hostIPC to false.",
				CISRef:      "5.2.4",
			})
		}

		// CIS 5.2.5 - Minimize admission of containers with hostNetwork
		if pod.Spec.HostNetwork {
			findings = append(findings, engine.Finding{
				ID:          fmt.Sprintf("CIS-5.2.5-%s/%s", pod.Namespace, pod.Name),
				CheckID:     "CIS-5.2.5",
				Title:       fmt.Sprintf("Pod uses hostNetwork: %s", pod.Name),
				Description: "CIS 5.2.5: Minimize the admission of containers wishing to share the host network namespace.",
				Severity:    engine.SeverityHigh,
				Category:    engine.CategoryCIS,
				Resource:    res,
				Remediation: "Set spec.hostNetwork to false.",
				CISRef:      "5.2.5",
			})
		}
	}

	return findings, nil
}

// Benchmark 5.3 Network Policies and CNI
func checkNetworkPolicies(ctx context.Context, client kubernetes.Interface, namespace string) ([]engine.Finding, error) {
	var findings []engine.Finding

	namespaces, err := client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	for i := range namespaces.Items {
		ns := &namespaces.Items[i]
		if isSystemNamespace(ns.Name) {
			continue
		}
		if namespace != "" && ns.Name != namespace {
			continue
		}

		policies, err := client.NetworkingV1().NetworkPolicies(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		// CIS 5.3.2 - Ensure network policies are in place for every namespace
		if len(policies.Items) == 0 {
			findings = append(findings, engine.Finding{
				ID:          fmt.Sprintf("CIS-5.3.2-%s", ns.Name),
				CheckID:     "CIS-5.3.2",
				Title:       fmt.Sprintf("No network policy: %s", ns.Name),
				Description: "CIS 5.3.2: Ensure that all Namespaces have NetworkPolicies defined.",
				Severity:    engine.SeverityHigh,
				Category:    engine.CategoryCIS,
				Resource:    engine.Resource{Kind: "Namespace", Name: ns.Name},
				Remediation: "Create a default-deny NetworkPolicy for this namespace.",
				CISRef:      "5.3.2",
			})
		}
	}

	return findings, nil
}

// Benchmark 5.4 Secrets Management
func checkSecretsManagement(ctx context.Context, client kubernetes.Interface, namespace string) ([]engine.Finding, error) {
	var findings []engine.Finding

	var pods *corev1.PodList
	var err error
	if namespace != "" {
		pods, err = client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	} else {
		pods, err = client.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	}
	if err != nil {
		return nil, err
	}

	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
			continue
		}
		if isSystemNamespace(pod.Namespace) {
			continue
		}

		res := engine.Resource{Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace}

		// CIS 5.4.1 - Prefer using secrets as files over environment variables
		for _, c := range pod.Spec.Containers {
			for _, env := range c.Env {
				if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
					findings = append(findings, engine.Finding{
						ID:          fmt.Sprintf("CIS-5.4.1-%s/%s/%s/%s", pod.Namespace, pod.Name, c.Name, env.Name),
						CheckID:     "CIS-5.4.1",
						Title:       fmt.Sprintf("Secret as env var: %s in %s/%s", env.Name, pod.Name, c.Name),
						Description: "CIS 5.4.1: Prefer using Secrets as files over Secrets as environment variables.",
						Severity:    engine.SeverityMedium,
						Category:    engine.CategoryCIS,
						Resource:    res,
						Remediation: "Mount the secret as a volume instead of using valueFrom.secretKeyRef in env.",
						CISRef:      "5.4.1",
					})
				}
			}
		}
	}

	return findings, nil
}

func checkAdmissionPolicies(ctx context.Context, client kubernetes.Interface, namespace string) ([]engine.Finding, error) {
	var findings []engine.Finding

	namespaces, err := client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	for i := range namespaces.Items {
		ns := &namespaces.Items[i]
		if isSystemNamespace(ns.Name) {
			continue
		}
		if namespace != "" && ns.Name != namespace {
			continue
		}

		enforce := ns.Labels["pod-security.kubernetes.io/enforce"]
		if enforce == "baseline" || enforce == "restricted" {
			continue
		}
		findings = append(findings, engine.Finding{
			ID:          fmt.Sprintf("CIS-5.2.1-%s", ns.Name),
			CheckID:     "CIS-5.2.1",
			Title:       fmt.Sprintf("Namespace lacks Pod Security enforcement label: %s", ns.Name),
			Description: "CIS 5.2.1: Ensure that the cluster has at least one active policy control mechanism. This namespace has no baseline or restricted PSA enforcement label; cluster-wide defaults and external policy enforcement require separate verification.",
			Severity:    engine.SeverityMedium,
			Category:    engine.CategoryCIS,
			Resource:    engine.Resource{Kind: "Namespace", Name: ns.Name},
			Remediation: "Set pod-security.kubernetes.io/enforce to baseline or restricted for workload namespaces, or verify an equivalent active policy mechanism.",
			CISRef:      "5.2.1",
		})
	}

	return findings, nil
}

func hasResource(rule rbacv1.PolicyRule, resource string) bool {
	_, subresource, hasSubresource := strings.Cut(resource, "/")
	for _, r := range rule.Resources {
		if r == resource || r == "*" || hasSubresource && r == "*/"+subresource {
			return true
		}
	}
	return false
}

func hasVerb(rule rbacv1.PolicyRule, verbs ...string) bool {
	for _, v := range rule.Verbs {
		if v == "*" {
			return true
		}
		for _, target := range verbs {
			if v == target {
				return true
			}
		}
	}
	return false
}

func isDefaultClusterRole(name string) bool {
	defaults := map[string]bool{
		"system:controller:generic-garbage-collector": true,
		"system:controller:resourcequota-controller":  true,
		"system:controller:namespace-controller":      true,
		"admin":                                       true,
		"edit":                                        true,
		"view":                                        true,
		"cluster-admin":                               true,
	}
	return defaults[name] || len(name) > 7 && name[:7] == "system:"
}

func isSystemNamespace(name string) bool {
	return name == "kube-system" || name == "kube-public" || name == "kube-node-lease"
}
