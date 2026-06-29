package rbac

import (
	"context"
	"testing"

	"github.com/RamazanKara/kube-shield/internal/scanner/engine"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestScan_WildcardPermissions(t *testing.T) {
	client := fake.NewSimpleClientset(
		&rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{Name: "overly-permissive"},
			Rules: []rbacv1.PolicyRule{{
				APIGroups: []string{"*"},
				Resources: []string{"*"},
				Verbs:     []string{"*"},
			}},
		},
	)

	s := New()
	result, err := s.Scan(context.Background(), client, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range result.Findings {
		if f.CheckID == "RBAC-001" {
			found = true
			if f.Severity != engine.SeverityCritical {
				t.Errorf("expected CRITICAL severity, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected to find RBAC-001 (wildcard permissions)")
	}
}

func TestScan_SecretAccess(t *testing.T) {
	client := fake.NewSimpleClientset(
		&rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{Name: "secret-reader"},
			Rules: []rbacv1.PolicyRule{{
				APIGroups: []string{""},
				Resources: []string{"secrets"},
				Verbs:     []string{"get", "list"},
			}},
		},
	)

	s := New()
	result, err := s.Scan(context.Background(), client, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range result.Findings {
		if f.CheckID == "RBAC-010" {
			found = true
		}
	}
	if !found {
		t.Error("expected to find RBAC-010 (secret read access)")
	}
}

func TestScan_ClusterAdminBinding(t *testing.T) {
	client := fake.NewSimpleClientset(
		&rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "bad-binding"},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "ClusterRole",
				Name:     "cluster-admin",
			},
			Subjects: []rbacv1.Subject{{
				Kind:      "ServiceAccount",
				Name:      "my-app",
				Namespace: "default",
			}},
		},
	)

	s := New()
	result, err := s.Scan(context.Background(), client, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range result.Findings {
		if f.CheckID == "RBAC-030" {
			found = true
			if f.Severity != engine.SeverityCritical {
				t.Errorf("expected CRITICAL severity, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected to find RBAC-030 (cluster-admin binding to SA)")
	}
}

func TestScan_PrivilegeEscalationVerbs(t *testing.T) {
	client := fake.NewSimpleClientset(
		&rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{Name: "escalator"},
			Rules: []rbacv1.PolicyRule{{
				APIGroups: []string{"rbac.authorization.k8s.io"},
				Resources: []string{"clusterroles"},
				Verbs:     []string{"bind", "escalate"},
			}},
		},
	)

	s := New()
	result, err := s.Scan(context.Background(), client, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range result.Findings {
		if f.CheckID == "RBAC-020" {
			found = true
		}
	}
	if !found {
		t.Error("expected to find RBAC-020 (privilege escalation verbs)")
	}
}

func TestScan_SystemRolesSkipped(t *testing.T) {
	client := fake.NewSimpleClientset(
		&rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{Name: "system:controller:foo"},
			Rules: []rbacv1.PolicyRule{{
				APIGroups: []string{"*"},
				Resources: []string{"*"},
				Verbs:     []string{"*"},
			}},
		},
	)

	s := New()
	result, err := s.Scan(context.Background(), client, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range result.Findings {
		t.Errorf("unexpected finding for system role: %s", f.Title)
	}
}
