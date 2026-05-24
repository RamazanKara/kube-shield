package netpol

import (
	"context"
	"fmt"

	"github.com/RamazanKara/kube-shield/pkg/scanner/engine"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Scanner checks for network policy misconfigurations and gaps.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string              { return "netpol" }
func (s *Scanner) Category() engine.Category { return engine.CategoryNetpol }
func (s *Scanner) Description() string {
	return "Validates network policies for gaps, overly permissive rules, and missing namespace isolation"
}

func (s *Scanner) Scan(ctx context.Context, client kubernetes.Interface, namespace string) (*engine.ScanResult, error) {
	var findings []engine.Finding

	// Get all namespaces
	namespaces, err := client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list namespaces: %w", err)
	}

	// Get all network policies
	var policies *networkingv1.NetworkPolicyList
	if namespace != "" {
		policies, err = client.NetworkingV1().NetworkPolicies(namespace).List(ctx, metav1.ListOptions{})
	} else {
		policies, err = client.NetworkingV1().NetworkPolicies("").List(ctx, metav1.ListOptions{})
	}
	if err != nil {
		return nil, fmt.Errorf("failed to list network policies: %w", err)
	}

	// Build per-namespace policy map
	nsPolicies := make(map[string][]networkingv1.NetworkPolicy)
	for i := range policies.Items {
		p := &policies.Items[i]
		nsPolicies[p.Namespace] = append(nsPolicies[p.Namespace], *p)
	}

	// Check each namespace for network policy coverage
	for i := range namespaces.Items {
		ns := &namespaces.Items[i]

		// Skip system namespaces
		if isSystemNamespace(ns.Name) {
			continue
		}

		if namespace != "" && ns.Name != namespace {
			continue
		}

		res := engine.Resource{Kind: "Namespace", Name: ns.Name}

		pols, hasPolicies := nsPolicies[ns.Name]
		if !hasPolicies || len(pols) == 0 {
			findings = append(findings, engine.Finding{
				ID:          fmt.Sprintf("NET-001-%s", ns.Name),
				CheckID:     "NET-001",
				Title:       fmt.Sprintf("No network policies in namespace: %s", ns.Name),
				Description: "Namespace has no network policies defined. All pods can communicate freely with any other pod in the cluster.",
				Severity:    engine.SeverityHigh,
				Category:    engine.CategoryNetpol,
				Resource:    res,
				Remediation: "Create a default-deny NetworkPolicy and allow only necessary traffic. Example:\n\napiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: default-deny-all\nspec:\n  podSelector: {}\n  policyTypes:\n  - Ingress\n  - Egress",
			})
			continue
		}

		// Check for default deny
		hasDefaultDenyIngress := false
		hasDefaultDenyEgress := false
		for _, pol := range pols {
			if isDefaultDeny(pol, networkingv1.PolicyTypeIngress) {
				hasDefaultDenyIngress = true
			}
			if isDefaultDeny(pol, networkingv1.PolicyTypeEgress) {
				hasDefaultDenyEgress = true
			}
		}

		if !hasDefaultDenyIngress {
			findings = append(findings, engine.Finding{
				ID:          fmt.Sprintf("NET-002-%s", ns.Name),
				CheckID:     "NET-002",
				Title:       fmt.Sprintf("No default-deny ingress policy: %s", ns.Name),
				Description: "Namespace has network policies but no default-deny ingress rule. Pods without matching policies accept all incoming traffic.",
				Severity:    engine.SeverityMedium,
				Category:    engine.CategoryNetpol,
				Resource:    res,
				Remediation: "Add a default-deny ingress NetworkPolicy with an empty podSelector.",
			})
		}

		if !hasDefaultDenyEgress {
			findings = append(findings, engine.Finding{
				ID:          fmt.Sprintf("NET-003-%s", ns.Name),
				CheckID:     "NET-003",
				Title:       fmt.Sprintf("No default-deny egress policy: %s", ns.Name),
				Description: "Namespace has no default-deny egress rule. Pods can send traffic to any destination including external networks.",
				Severity:    engine.SeverityMedium,
				Category:    engine.CategoryNetpol,
				Resource:    res,
				Remediation: "Add a default-deny egress NetworkPolicy, then explicitly allow required outbound traffic.",
			})
		}

		// Check individual policies for overly permissive rules
		for _, pol := range pols {
			findings = append(findings, checkPolicy(pol)...)
		}
	}

	return &engine.ScanResult{
		Scanner:  s.Name(),
		Findings: findings,
	}, nil
}

func checkPolicy(pol networkingv1.NetworkPolicy) []engine.Finding {
	var findings []engine.Finding
	res := engine.Resource{Kind: "NetworkPolicy", Name: pol.Name, Namespace: pol.Namespace}

	// Check for allow-all ingress
	for _, ingress := range pol.Spec.Ingress {
		if len(ingress.From) == 0 && len(ingress.Ports) == 0 {
			findings = append(findings, engine.Finding{
				ID:          fmt.Sprintf("NET-010-%s/%s", pol.Namespace, pol.Name),
				CheckID:     "NET-010",
				Title:       fmt.Sprintf("Allow-all ingress rule: %s", pol.Name),
				Description: "Network policy has an ingress rule that allows traffic from all sources on all ports.",
				Severity:    engine.SeverityHigh,
				Category:    engine.CategoryNetpol,
				Resource:    res,
				Remediation: "Restrict ingress sources using podSelector, namespaceSelector, or ipBlock.",
			})
		}
	}

	// Check for allow-all egress
	for _, egress := range pol.Spec.Egress {
		if len(egress.To) == 0 && len(egress.Ports) == 0 {
			findings = append(findings, engine.Finding{
				ID:          fmt.Sprintf("NET-011-%s/%s", pol.Namespace, pol.Name),
				CheckID:     "NET-011",
				Title:       fmt.Sprintf("Allow-all egress rule: %s", pol.Name),
				Description: "Network policy has an egress rule that allows traffic to all destinations on all ports.",
				Severity:    engine.SeverityMedium,
				Category:    engine.CategoryNetpol,
				Resource:    res,
				Remediation: "Restrict egress destinations using podSelector, namespaceSelector, or ipBlock.",
			})
		}
	}

	// Check for wide CIDR ranges
	for _, ingress := range pol.Spec.Ingress {
		for _, from := range ingress.From {
			if from.IPBlock != nil && isWideCIDR(from.IPBlock.CIDR) {
				findings = append(findings, engine.Finding{
					ID:          fmt.Sprintf("NET-020-%s/%s-%s", pol.Namespace, pol.Name, from.IPBlock.CIDR),
					CheckID:     "NET-020",
					Title:       fmt.Sprintf("Wide CIDR range in ingress: %s", pol.Name),
					Description: fmt.Sprintf("Network policy allows ingress from a very wide CIDR range: %s", from.IPBlock.CIDR),
					Severity:    engine.SeverityMedium,
					Category:    engine.CategoryNetpol,
					Resource:    res,
					Remediation: "Narrow the CIDR range to only include necessary source IP ranges.",
				})
			}
		}
	}

	return findings
}

func isDefaultDeny(pol networkingv1.NetworkPolicy, policyType networkingv1.PolicyType) bool {
	// A default deny has an empty podSelector and the specified policyType with no rules
	if len(pol.Spec.PodSelector.MatchLabels) > 0 || len(pol.Spec.PodSelector.MatchExpressions) > 0 {
		return false
	}

	if !hasEffectivePolicyType(pol, policyType) {
		return false
	}

	switch policyType {
	case networkingv1.PolicyTypeIngress:
		return len(pol.Spec.Ingress) == 0
	case networkingv1.PolicyTypeEgress:
		return len(pol.Spec.Egress) == 0
	}

	return false
}

func hasEffectivePolicyType(pol networkingv1.NetworkPolicy, policyType networkingv1.PolicyType) bool {
	if len(pol.Spec.PolicyTypes) == 0 {
		if policyType == networkingv1.PolicyTypeIngress {
			return true
		}
		return len(pol.Spec.Egress) > 0
	}

	for _, pt := range pol.Spec.PolicyTypes {
		if pt == policyType {
			return true
		}
	}
	return false
}

func isWideCIDR(cidr string) bool {
	return cidr == "0.0.0.0/0" || cidr == "::/0" || cidr == "10.0.0.0/8" || cidr == "172.16.0.0/12" || cidr == "192.168.0.0/16"
}

func isSystemNamespace(name string) bool {
	return name == "kube-system" || name == "kube-public" || name == "kube-node-lease"
}
