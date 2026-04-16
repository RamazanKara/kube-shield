package netpol

import (
	"context"
	"testing"

	"github.com/RamazanKara/kube-shield/pkg/scanner/engine"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestScan_NoNetworkPolicies(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "production"}},
	)

	s := New()
	result, err := s.Scan(context.Background(), client, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range result.Findings {
		if f.CheckID == "NET-001" && f.Resource.Name == "production" {
			found = true
			if f.Severity != engine.SeverityHigh {
				t.Errorf("expected HIGH severity, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected NET-001 finding for namespace without network policies")
	}
}

func TestScan_NoDefaultDenyIngress(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "app"}},
		&networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "allow-web", Namespace: "app"},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"role": "web"},
				},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
				Ingress: []networkingv1.NetworkPolicyIngressRule{
					{From: []networkingv1.NetworkPolicyPeer{{
						PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"role": "api"}},
					}}},
				},
			},
		},
	)

	s := New()
	result, err := s.Scan(context.Background(), client, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	foundIngress := false
	foundEgress := false
	for _, f := range result.Findings {
		if f.CheckID == "NET-002" {
			foundIngress = true
		}
		if f.CheckID == "NET-003" {
			foundEgress = true
		}
	}
	if !foundIngress {
		t.Error("expected NET-002 (no default-deny ingress)")
	}
	if !foundEgress {
		t.Error("expected NET-003 (no default-deny egress)")
	}
}

func TestScan_DefaultDenyPresent(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "secure"}},
		&networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "default-deny", Namespace: "secure"},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{},
				PolicyTypes: []networkingv1.PolicyType{
					networkingv1.PolicyTypeIngress,
					networkingv1.PolicyTypeEgress,
				},
			},
		},
	)

	s := New()
	result, err := s.Scan(context.Background(), client, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range result.Findings {
		if f.CheckID == "NET-001" || f.CheckID == "NET-002" || f.CheckID == "NET-003" {
			if f.Resource.Name == "secure" {
				t.Errorf("should not find %s for namespace with default-deny policy", f.CheckID)
			}
		}
	}
}

func TestScan_AllowAllIngress(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "open"}},
		&networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "allow-all", Namespace: "open"},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
				Ingress:     []networkingv1.NetworkPolicyIngressRule{{}},
			},
		},
	)

	s := New()
	result, err := s.Scan(context.Background(), client, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range result.Findings {
		if f.CheckID == "NET-010" {
			found = true
		}
	}
	if !found {
		t.Error("expected NET-010 (allow-all ingress)")
	}
}

func TestScan_WideCIDR(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "wide"}},
		&networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "wide-cidr", Namespace: "wide"},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
				Ingress: []networkingv1.NetworkPolicyIngressRule{{
					From: []networkingv1.NetworkPolicyPeer{{
						IPBlock: &networkingv1.IPBlock{CIDR: "0.0.0.0/0"},
					}},
				}},
			},
		},
	)

	s := New()
	result, err := s.Scan(context.Background(), client, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range result.Findings {
		if f.CheckID == "NET-020" {
			found = true
		}
	}
	if !found {
		t.Error("expected NET-020 (wide CIDR)")
	}
}

func TestScan_SystemNamespaceSkipped(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}},
	)

	s := New()
	result, err := s.Scan(context.Background(), client, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range result.Findings {
		if f.Resource.Name == "kube-system" {
			t.Error("should not scan kube-system namespace")
		}
	}
}

func TestScan_NamespaceFilter(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "app1"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "app2"}},
	)

	s := New()
	result, err := s.Scan(context.Background(), client, "app1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range result.Findings {
		if f.Resource.Name == "app2" {
			t.Error("should not scan app2 when filtering to app1")
		}
	}
}
