package rbac

import (
	"context"
	"fmt"
	"strings"

	"github.com/RamazanKara/kube-shield/pkg/scanner/engine"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Scanner checks for RBAC misconfigurations and risky permissions.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string              { return "rbac" }
func (s *Scanner) Category() engine.Category { return engine.CategoryRBAC }
func (s *Scanner) Description() string {
	return "Analyzes RBAC configurations for overly permissive roles, privilege escalation paths, and risky bindings"
}

func (s *Scanner) Scan(ctx context.Context, client kubernetes.Interface, namespace string) (*engine.ScanResult, error) {
	var findings []engine.Finding

	// Fetch all RBAC resources
	clusterRoles, err := client.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list ClusterRoles: %w", err)
	}

	clusterRoleBindings, err := client.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list ClusterRoleBindings: %w", err)
	}

	var roles *rbacv1.RoleList
	var roleBindings *rbacv1.RoleBindingList

	if namespace != "" {
		roles, err = client.RbacV1().Roles(namespace).List(ctx, metav1.ListOptions{})
	} else {
		roles, err = client.RbacV1().Roles("").List(ctx, metav1.ListOptions{})
	}
	if err != nil {
		return nil, fmt.Errorf("failed to list Roles: %w", err)
	}

	if namespace != "" {
		roleBindings, err = client.RbacV1().RoleBindings(namespace).List(ctx, metav1.ListOptions{})
	} else {
		roleBindings, err = client.RbacV1().RoleBindings("").List(ctx, metav1.ListOptions{})
	}
	if err != nil {
		return nil, fmt.Errorf("failed to list RoleBindings: %w", err)
	}

	// Check ClusterRoles
	for i := range clusterRoles.Items {
		cr := &clusterRoles.Items[i]
		if isSystemRole(cr.Name) {
			continue
		}
		res := engine.Resource{Kind: "ClusterRole", Name: cr.Name}
		findings = append(findings, checkRules(cr.Rules, res, cr.Name)...)
	}

	// Check Roles
	for i := range roles.Items {
		r := &roles.Items[i]
		if isSystemRole(r.Name) {
			continue
		}
		res := engine.Resource{Kind: "Role", Name: r.Name, Namespace: r.Namespace}
		findings = append(findings, checkRules(r.Rules, res, r.Name)...)
	}

	// Check ClusterRoleBindings
	for i := range clusterRoleBindings.Items {
		crb := &clusterRoleBindings.Items[i]
		if isSystemRole(crb.Name) {
			continue
		}
		findings = append(findings, checkBinding(crb.RoleRef, crb.Subjects, crb.Name, "")...)
	}

	// Check RoleBindings
	for i := range roleBindings.Items {
		rb := &roleBindings.Items[i]
		if isSystemRole(rb.Name) {
			continue
		}
		findings = append(findings, checkBinding(rb.RoleRef, rb.Subjects, rb.Name, rb.Namespace)...)
	}

	return &engine.ScanResult{
		Scanner:  s.Name(),
		Findings: findings,
	}, nil
}

func checkRules(rules []rbacv1.PolicyRule, res engine.Resource, roleName string) []engine.Finding {
	var findings []engine.Finding

	for _, rule := range rules {
		// Wildcard resources
		if containsStr(rule.Resources, "*") && containsStr(rule.Verbs, "*") {
			findings = append(findings, engine.Finding{
				ID:          fmt.Sprintf("RBAC-001-%s", res.String()),
				CheckID:     "RBAC-001",
				Title:       fmt.Sprintf("Wildcard permissions on all resources: %s", roleName),
				Description: "Role grants wildcard (*) verbs on wildcard (*) resources, effectively providing cluster-admin level access.",
				Severity:    engine.SeverityCritical,
				Category:    engine.CategoryRBAC,
				Resource:    res,
				Remediation: "Replace wildcards with specific resources and verbs needed by the workload.",
			})
		} else if containsStr(rule.Verbs, "*") {
			findings = append(findings, engine.Finding{
				ID:          fmt.Sprintf("RBAC-002-%s-%s", res.String(), strings.Join(rule.Resources, ",")),
				CheckID:     "RBAC-002",
				Title:       fmt.Sprintf("Wildcard verbs: %s on %s", roleName, strings.Join(rule.Resources, ", ")),
				Description: "Role grants all verbs (*) on specific resources. This is overly permissive.",
				Severity:    engine.SeverityHigh,
				Category:    engine.CategoryRBAC,
				Resource:    res,
				Remediation: "Replace verb wildcard with specific verbs (get, list, watch, etc.) needed by the workload.",
			})
		} else if containsStr(rule.Resources, "*") {
			findings = append(findings, engine.Finding{
				ID:          fmt.Sprintf("RBAC-003-%s-%s", res.String(), strings.Join(rule.Verbs, ",")),
				CheckID:     "RBAC-003",
				Title:       fmt.Sprintf("Wildcard resources: %s with %s", roleName, strings.Join(rule.Verbs, ", ")),
				Description: "Role grants specific verbs on all resources (*). This is overly permissive.",
				Severity:    engine.SeverityHigh,
				Category:    engine.CategoryRBAC,
				Resource:    res,
				Remediation: "Replace resource wildcard with specific resources needed by the workload.",
			})
		}

		// Secret access
		if containsStr(rule.Resources, "secrets") {
			if containsAny(rule.Verbs, "get", "list", "watch", "*") {
				findings = append(findings, engine.Finding{
					ID:          fmt.Sprintf("RBAC-010-%s", res.String()),
					CheckID:     "RBAC-010",
					Title:       fmt.Sprintf("Secret read access: %s", roleName),
					Description: "Role grants read access to secrets. This allows viewing all secrets in the scope.",
					Severity:    engine.SeverityHigh,
					Category:    engine.CategoryRBAC,
					Resource:    res,
					Remediation: "Restrict secret access to only the specific secrets needed. Consider using external secret management.",
				})
			}
			if containsAny(rule.Verbs, "create", "update", "patch", "delete", "*") {
				findings = append(findings, engine.Finding{
					ID:          fmt.Sprintf("RBAC-011-%s", res.String()),
					CheckID:     "RBAC-011",
					Title:       fmt.Sprintf("Secret write access: %s", roleName),
					Description: "Role grants write access to secrets. This allows creating or modifying secrets.",
					Severity:    engine.SeverityCritical,
					Category:    engine.CategoryRBAC,
					Resource:    res,
					Remediation: "Remove secret write permissions unless strictly required.",
				})
			}
		}

		// Privilege escalation verbs
		if containsAny(rule.Verbs, "bind", "escalate", "impersonate") {
			findings = append(findings, engine.Finding{
				ID:          fmt.Sprintf("RBAC-020-%s", res.String()),
				CheckID:     "RBAC-020",
				Title:       fmt.Sprintf("Privilege escalation verbs: %s", roleName),
				Description: "Role grants bind, escalate, or impersonate verbs which can be used for privilege escalation.",
				Severity:    engine.SeverityCritical,
				Category:    engine.CategoryRBAC,
				Resource:    res,
				Remediation: "Remove bind, escalate, and impersonate verbs. These should only be granted to cluster operators.",
			})
		}

		// Pod exec/attach (including pods/* wildcard)
		if containsStr(rule.Resources, "pods/exec") || containsStr(rule.Resources, "pods/attach") || containsStr(rule.Resources, "pods/*") {
			findings = append(findings, engine.Finding{
				ID:          fmt.Sprintf("RBAC-021-%s", res.String()),
				CheckID:     "RBAC-021",
				Title:       fmt.Sprintf("Pod exec/attach access: %s", roleName),
				Description: "Role allows exec/attach into pods, which can be used to run arbitrary commands inside containers.",
				Severity:    engine.SeverityHigh,
				Category:    engine.CategoryRBAC,
				Resource:    res,
				Remediation: "Restrict pod exec access to specific namespaces and service accounts that require debugging access.",
			})
		}

		// Node/proxy access
		if containsStr(rule.Resources, "nodes/proxy") {
			findings = append(findings, engine.Finding{
				ID:          fmt.Sprintf("RBAC-022-%s", res.String()),
				CheckID:     "RBAC-022",
				Title:       fmt.Sprintf("Node proxy access: %s", roleName),
				Description: "Role allows node/proxy access which can bypass RBAC and directly access kubelet API.",
				Severity:    engine.SeverityCritical,
				Category:    engine.CategoryRBAC,
				Resource:    res,
				Remediation: "Remove nodes/proxy access unless absolutely required.",
			})
		}

		// PersistentVolume access
		if containsStr(rule.Resources, "persistentvolumes") && containsAny(rule.Verbs, "create", "delete", "*") {
			findings = append(findings, engine.Finding{
				ID:          fmt.Sprintf("RBAC-023-%s", res.String()),
				CheckID:     "RBAC-023",
				Title:       fmt.Sprintf("PersistentVolume write access: %s", roleName),
				Description: "Role allows creating/deleting PersistentVolumes which could be used to mount host paths.",
				Severity:    engine.SeverityHigh,
				Category:    engine.CategoryRBAC,
				Resource:    res,
				Remediation: "Restrict PersistentVolume management to cluster administrators only.",
			})
		}
	}

	return findings
}

func checkBinding(roleRef rbacv1.RoleRef, subjects []rbacv1.Subject, bindingName, namespace string) []engine.Finding {
	var findings []engine.Finding

	res := engine.Resource{Kind: "ClusterRoleBinding", Name: bindingName}
	if namespace != "" {
		res = engine.Resource{Kind: "RoleBinding", Name: bindingName, Namespace: namespace}
	}

	// Check for cluster-admin binding
	if roleRef.Name == "cluster-admin" {
		for _, subj := range subjects {
			if subj.Kind == "ServiceAccount" {
				findings = append(findings, engine.Finding{
					ID:          fmt.Sprintf("RBAC-030-%s-%s", res.String(), subj.Name),
					CheckID:     "RBAC-030",
					Title:       fmt.Sprintf("cluster-admin bound to ServiceAccount: %s", subj.Name),
					Description: fmt.Sprintf("ServiceAccount %s/%s has cluster-admin access. If any pod using this SA is compromised, the entire cluster is compromised.", subj.Namespace, subj.Name),
					Severity:    engine.SeverityCritical,
					Category:    engine.CategoryRBAC,
					Resource:    res,
					Remediation: "Create a more restrictive role with only the permissions needed. Bind that role instead of cluster-admin.",
				})
			}
			if subj.Kind == "Group" && subj.Name == "system:unauthenticated" {
				findings = append(findings, engine.Finding{
					ID:          fmt.Sprintf("RBAC-031-%s", res.String()),
					CheckID:     "RBAC-031",
					Title:       fmt.Sprintf("cluster-admin bound to unauthenticated users: %s", bindingName),
					Description: "Unauthenticated users have cluster-admin access. This is a critical security vulnerability.",
					Severity:    engine.SeverityCritical,
					Category:    engine.CategoryRBAC,
					Resource:    res,
					Remediation: "Remove this binding immediately. Unauthenticated users should never have cluster-admin access.",
				})
			}
		}
	}

	// Check for bindings to default service account
	for _, subj := range subjects {
		if subj.Kind == "ServiceAccount" && subj.Name == "default" {
			findings = append(findings, engine.Finding{
				ID:          fmt.Sprintf("RBAC-032-%s-%s", res.String(), subj.Namespace),
				CheckID:     "RBAC-032",
				Title:       fmt.Sprintf("Role bound to default ServiceAccount in %s", subj.Namespace),
				Description: "The default ServiceAccount is used by all pods that don't specify a SA. Binding roles to it gives those permissions to all unspecified pods.",
				Severity:    engine.SeverityMedium,
				Category:    engine.CategoryRBAC,
				Resource:    res,
				Remediation: "Create dedicated ServiceAccounts for workloads and bind roles to those instead.",
			})
		}
	}

	return findings
}

func isSystemRole(name string) bool {
	return strings.HasPrefix(name, "system:") || strings.HasPrefix(name, "kubeadm:") ||
		strings.HasPrefix(name, "calico") || strings.HasPrefix(name, "cilium")
}

func containsStr(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

func containsAny(slice []string, vals ...string) bool {
	for _, v := range slice {
		for _, val := range vals {
			if v == val {
				return true
			}
		}
	}
	return false
}
