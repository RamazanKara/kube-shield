package cis

import (
	"context"
	"fmt"

	"github.com/RamazanKara/kube-shield/pkg/scanner/engine"
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
	return "Runs CIS Kubernetes Benchmark v1.12 checks accessible via the Kubernetes API"
}

func (s *Scanner) Scan(ctx context.Context, client kubernetes.Interface, namespace string) (*engine.ScanResult, error) {
	var findings []engine.Finding

	// Section 4: Policies — these are the checks we can perform via API access

	// 4.1 RBAC and Service Accounts
	f, err := checkRBACPolicies(ctx, client)
	if err != nil {
		return nil, err
	}
	findings = append(findings, f...)

	// 4.2 Pod Security
	f, err = checkPodSecurity(ctx, client, namespace)
	if err != nil {
		return nil, err
	}
	findings = append(findings, f...)

	// 4.3 Network Policies
	f, err = checkNetworkPolicies(ctx, client, namespace)
	if err != nil {
		return nil, err
	}
	findings = append(findings, f...)

	// 4.4 Secrets Management
	f, err = checkSecretsManagement(ctx, client, namespace)
	if err != nil {
		return nil, err
	}
	findings = append(findings, f...)

	// 4.5 General Policies
	f, err = checkGeneralPolicies(ctx, client, namespace)
	if err != nil {
		return nil, err
	}
	findings = append(findings, f...)

	return &engine.ScanResult{
		Scanner:  s.Name(),
		Findings: findings,
	}, nil
}

// 4.1 RBAC and Service Accounts
func checkRBACPolicies(ctx context.Context, client kubernetes.Interface) ([]engine.Finding, error) {
	var findings []engine.Finding

	// CIS 4.1.1 - Ensure cluster-admin role is only used where required
	crbs, err := client.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	clusterAdminCount := 0
	for i := range crbs.Items {
		crb := &crbs.Items[i]
		if crb.RoleRef.Name == "cluster-admin" {
			clusterAdminCount++
			for _, subj := range crb.Subjects {
				if subj.Kind == "ServiceAccount" {
					findings = append(findings, engine.Finding{
						ID:          fmt.Sprintf("CIS-4.1.1-%s-%s", crb.Name, subj.Name),
						CheckID:     "CIS-4.1.1",
						Title:       fmt.Sprintf("cluster-admin role bound to SA: %s/%s", subj.Namespace, subj.Name),
						Description: "CIS 4.1.1: Ensure that the cluster-admin role is only used where required. ServiceAccounts should not be bound to cluster-admin.",
						Severity:    engine.SeverityCritical,
						Category:    engine.CategoryCIS,
						Resource:    engine.Resource{Kind: "ClusterRoleBinding", Name: crb.Name},
						Remediation: "Create a specific ClusterRole/Role with minimum permissions and bind it instead of cluster-admin.",
						CISRef:      "4.1.1",
					})
				}
			}
		}
	}

	// CIS 4.1.2 - Minimize access to secrets
	clusterRoles, err := client.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	for i := range clusterRoles.Items {
		cr := &clusterRoles.Items[i]
		if isDefaultClusterRole(cr.Name) {
			continue
		}
		for _, rule := range cr.Rules {
			if hasResource(rule, "secrets") && hasVerb(rule, "get", "list", "watch") {
				findings = append(findings, engine.Finding{
					ID:          fmt.Sprintf("CIS-4.1.2-%s", cr.Name),
					CheckID:     "CIS-4.1.2",
					Title:       fmt.Sprintf("ClusterRole with secret access: %s", cr.Name),
					Description: "CIS 4.1.2: Minimize access to secrets. ClusterRole grants access to read secrets cluster-wide.",
					Severity:    engine.SeverityHigh,
					Category:    engine.CategoryCIS,
					Resource:    engine.Resource{Kind: "ClusterRole", Name: cr.Name},
					Remediation: "Restrict secret access to namespace-scoped Roles instead of ClusterRoles where possible.",
					CISRef:      "4.1.2",
				})
				break
			}
		}
	}

	// CIS 4.1.5 - Ensure default service accounts are not actively used
	serviceAccounts, err := client.CoreV1().ServiceAccounts("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	for i := range serviceAccounts.Items {
		sa := &serviceAccounts.Items[i]
		if sa.Name != "default" {
			continue
		}
		// Check if default SA has any additional role bindings
		rbs, err := client.RbacV1().RoleBindings(sa.Namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}
		for j := range rbs.Items {
			rb := &rbs.Items[j]
			for _, subj := range rb.Subjects {
				if subj.Kind == "ServiceAccount" && subj.Name == "default" {
					findings = append(findings, engine.Finding{
						ID:          fmt.Sprintf("CIS-4.1.5-%s-%s", sa.Namespace, rb.Name),
						CheckID:     "CIS-4.1.5",
						Title:       fmt.Sprintf("Default SA has role binding in %s", sa.Namespace),
						Description: "CIS 4.1.5: Ensure that default service accounts are not actively used. The default SA should not have additional roles bound to it.",
						Severity:    engine.SeverityMedium,
						Category:    engine.CategoryCIS,
						Resource:    engine.Resource{Kind: "ServiceAccount", Name: "default", Namespace: sa.Namespace},
						Remediation: "Create dedicated ServiceAccounts for workloads. Remove role bindings from the default SA.",
						CISRef:      "4.1.5",
					})
				}
			}
		}

		// CIS 4.1.6 - Ensure SA tokens are not mounted automatically
		if sa.AutomountServiceAccountToken == nil || *sa.AutomountServiceAccountToken {
			findings = append(findings, engine.Finding{
				ID:          fmt.Sprintf("CIS-4.1.6-%s", sa.Namespace),
				CheckID:     "CIS-4.1.6",
				Title:       fmt.Sprintf("Default SA automounts token in %s", sa.Namespace),
				Description: "CIS 4.1.6: Ensure that Service Account Tokens are not automatically mounted. The default SA automounts tokens, giving pods API access.",
				Severity:    engine.SeverityMedium,
				Category:    engine.CategoryCIS,
				Resource:    engine.Resource{Kind: "ServiceAccount", Name: "default", Namespace: sa.Namespace},
				Remediation: "Set automountServiceAccountToken: false on the default ServiceAccount.",
				CISRef:      "4.1.6",
			})
		}
	}

	return findings, nil
}

// 4.2 Pod Security
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

		for _, c := range pod.Spec.Containers {
			// CIS 4.2.1 - Minimize admission of privileged containers
			if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
				findings = append(findings, engine.Finding{
					ID:          fmt.Sprintf("CIS-4.2.1-%s/%s/%s", pod.Namespace, pod.Name, c.Name),
					CheckID:     "CIS-4.2.1",
					Title:       fmt.Sprintf("Privileged container: %s/%s", pod.Name, c.Name),
					Description: "CIS 4.2.1: Minimize the admission of privileged containers.",
					Severity:    engine.SeverityCritical,
					Category:    engine.CategoryCIS,
					Resource:    res,
					Remediation: "Do not run containers in privileged mode. Use specific capabilities instead.",
					CISRef:      "4.2.1",
				})
			}

			// CIS 4.2.6 - Minimize admission of root containers
			if c.SecurityContext == nil || c.SecurityContext.RunAsNonRoot == nil || !*c.SecurityContext.RunAsNonRoot {
				if c.SecurityContext == nil || c.SecurityContext.RunAsUser == nil || *c.SecurityContext.RunAsUser == 0 {
					findings = append(findings, engine.Finding{
						ID:          fmt.Sprintf("CIS-4.2.6-%s/%s/%s", pod.Namespace, pod.Name, c.Name),
						CheckID:     "CIS-4.2.6",
						Title:       fmt.Sprintf("Container may run as root: %s/%s", pod.Name, c.Name),
						Description: "CIS 4.2.6: Minimize the admission of root containers.",
						Severity:    engine.SeverityHigh,
						Category:    engine.CategoryCIS,
						Resource:    res,
						Remediation: "Set securityContext.runAsNonRoot: true and runAsUser to a non-zero value.",
						CISRef:      "4.2.6",
					})
				}
			}

			// CIS 4.2.9 - Minimize admission of containers with added capabilities
			if c.SecurityContext != nil && c.SecurityContext.Capabilities != nil && len(c.SecurityContext.Capabilities.Add) > 0 {
				findings = append(findings, engine.Finding{
					ID:          fmt.Sprintf("CIS-4.2.9-%s/%s/%s", pod.Namespace, pod.Name, c.Name),
					CheckID:     "CIS-4.2.9",
					Title:       fmt.Sprintf("Container has added capabilities: %s/%s", pod.Name, c.Name),
					Description: "CIS 4.2.9: Minimize the admission of containers with added capabilities.",
					Severity:    engine.SeverityMedium,
					Category:    engine.CategoryCIS,
					Resource:    res,
					Remediation: "Remove added capabilities. Drop ALL capabilities and add only those strictly required.",
					CISRef:      "4.2.9",
				})
			}
		}

		// CIS 4.2.2 - Minimize admission of containers with hostPID
		if pod.Spec.HostPID {
			findings = append(findings, engine.Finding{
				ID:          fmt.Sprintf("CIS-4.2.2-%s/%s", pod.Namespace, pod.Name),
				CheckID:     "CIS-4.2.2",
				Title:       fmt.Sprintf("Pod uses hostPID: %s", pod.Name),
				Description: "CIS 4.2.2: Minimize the admission of containers wishing to share the host process ID namespace.",
				Severity:    engine.SeverityHigh,
				Category:    engine.CategoryCIS,
				Resource:    res,
				Remediation: "Set spec.hostPID to false.",
				CISRef:      "4.2.2",
			})
		}

		// CIS 4.2.3 - Minimize admission of containers with hostIPC
		if pod.Spec.HostIPC {
			findings = append(findings, engine.Finding{
				ID:          fmt.Sprintf("CIS-4.2.3-%s/%s", pod.Namespace, pod.Name),
				CheckID:     "CIS-4.2.3",
				Title:       fmt.Sprintf("Pod uses hostIPC: %s", pod.Name),
				Description: "CIS 4.2.3: Minimize the admission of containers wishing to share the host IPC namespace.",
				Severity:    engine.SeverityHigh,
				Category:    engine.CategoryCIS,
				Resource:    res,
				Remediation: "Set spec.hostIPC to false.",
				CISRef:      "4.2.3",
			})
		}

		// CIS 4.2.4 - Minimize admission of containers with hostNetwork
		if pod.Spec.HostNetwork {
			findings = append(findings, engine.Finding{
				ID:          fmt.Sprintf("CIS-4.2.4-%s/%s", pod.Namespace, pod.Name),
				CheckID:     "CIS-4.2.4",
				Title:       fmt.Sprintf("Pod uses hostNetwork: %s", pod.Name),
				Description: "CIS 4.2.4: Minimize the admission of containers wishing to share the host network namespace.",
				Severity:    engine.SeverityHigh,
				Category:    engine.CategoryCIS,
				Resource:    res,
				Remediation: "Set spec.hostNetwork to false.",
				CISRef:      "4.2.4",
			})
		}
	}

	return findings, nil
}

// 4.3 Network Policies
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

		// CIS 4.3.1 - Ensure network policies are in place for every namespace
		if len(policies.Items) == 0 {
			findings = append(findings, engine.Finding{
				ID:          fmt.Sprintf("CIS-4.3.1-%s", ns.Name),
				CheckID:     "CIS-4.3.1",
				Title:       fmt.Sprintf("No network policy: %s", ns.Name),
				Description: "CIS 4.3.1: Ensure that a NetworkPolicy is configured for every namespace.",
				Severity:    engine.SeverityHigh,
				Category:    engine.CategoryCIS,
				Resource:    engine.Resource{Kind: "Namespace", Name: ns.Name},
				Remediation: "Create a default-deny NetworkPolicy for this namespace.",
				CISRef:      "4.3.1",
			})
		}
	}

	return findings, nil
}

// 4.4 Secrets Management
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

		// CIS 4.4.1 - Prefer using secrets as files over environment variables
		for _, c := range pod.Spec.Containers {
			for _, env := range c.Env {
				if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
					findings = append(findings, engine.Finding{
						ID:          fmt.Sprintf("CIS-4.4.1-%s/%s/%s/%s", pod.Namespace, pod.Name, c.Name, env.Name),
						CheckID:     "CIS-4.4.1",
						Title:       fmt.Sprintf("Secret as env var: %s in %s/%s", env.Name, pod.Name, c.Name),
						Description: "CIS 4.4.1: Prefer using Secrets as files over Secrets as environment variables.",
						Severity:    engine.SeverityMedium,
						Category:    engine.CategoryCIS,
						Resource:    res,
						Remediation: "Mount the secret as a volume instead of using valueFrom.secretKeyRef in env.",
						CISRef:      "4.4.1",
					})
				}
			}
		}
	}

	return findings, nil
}

// 4.5 General Policies
func checkGeneralPolicies(ctx context.Context, client kubernetes.Interface, namespace string) ([]engine.Finding, error) {
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

		// CIS 4.5.1 - Ensure namespaces have resource quotas
		quotas, err := client.CoreV1().ResourceQuotas(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		if len(quotas.Items) == 0 {
			findings = append(findings, engine.Finding{
				ID:          fmt.Sprintf("CIS-4.5.1-%s", ns.Name),
				CheckID:     "CIS-4.5.1",
				Title:       fmt.Sprintf("No resource quotas: %s", ns.Name),
				Description: "CIS 4.5.1: Create administrative boundaries between resources using namespaces with resource quotas.",
				Severity:    engine.SeverityLow,
				Category:    engine.CategoryCIS,
				Resource:    engine.Resource{Kind: "Namespace", Name: ns.Name},
				Remediation: "Create a ResourceQuota for this namespace to limit resource consumption.",
				CISRef:      "4.5.1",
			})
		}

		// CIS 4.5.2 - Ensure LimitRange exists
		limitRanges, err := client.CoreV1().LimitRanges(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		if len(limitRanges.Items) == 0 {
			findings = append(findings, engine.Finding{
				ID:          fmt.Sprintf("CIS-4.5.2-%s", ns.Name),
				CheckID:     "CIS-4.5.2",
				Title:       fmt.Sprintf("No LimitRange: %s", ns.Name),
				Description: "CIS 4.5.2: Ensure LimitRange policies are set to constrain resource allocations.",
				Severity:    engine.SeverityLow,
				Category:    engine.CategoryCIS,
				Resource:    engine.Resource{Kind: "Namespace", Name: ns.Name},
				Remediation: "Create a LimitRange to set default resource limits for containers.",
				CISRef:      "4.5.2",
			})
		}
	}

	return findings, nil
}

func hasResource(rule rbacv1.PolicyRule, resource string) bool {
	for _, r := range rule.Resources {
		if r == resource || r == "*" {
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
