package cis

import (
	"context"
	"testing"

	"github.com/RamazanKara/kube-shield/pkg/scanner/engine"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func boolPtr(b bool) *bool    { return &b }
func int64Ptr(i int64) *int64 { return &i }

func TestScan_ClusterAdminBinding(t *testing.T) {
	client := fake.NewSimpleClientset(
		&rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "admin-binding"},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "ClusterRole",
				Name:     "cluster-admin",
			},
			Subjects: []rbacv1.Subject{{
				Kind:      "ServiceAccount",
				Name:      "deploy-bot",
				Namespace: "ci",
			}},
		},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ci"}},
		&corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "ci"},
		},
	)

	s := New()
	result, err := s.Scan(context.Background(), client, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range result.Findings {
		if f.CheckID == "CIS-4.1.1" {
			found = true
			if f.Severity != engine.SeverityCritical {
				t.Errorf("expected CRITICAL severity, got %s", f.Severity)
			}
			if f.CISRef != "4.1.1" {
				t.Errorf("expected CISRef 4.1.1, got %s", f.CISRef)
			}
		}
	}
	if !found {
		t.Error("expected CIS-4.1.1 (cluster-admin bound to SA)")
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
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
		&corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "default"},
		},
	)

	s := New()
	result, err := s.Scan(context.Background(), client, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range result.Findings {
		if f.CheckID == "CIS-4.1.2" {
			found = true
			if f.Severity != engine.SeverityHigh {
				t.Errorf("expected HIGH severity, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected CIS-4.1.2 (secret access)")
	}
}

func TestScan_DefaultSAAutomountToken(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "app"}},
		&corev1.ServiceAccount{
			ObjectMeta:                   metav1.ObjectMeta{Name: "default", Namespace: "app"},
			AutomountServiceAccountToken: nil, // defaults to true
		},
	)

	s := New()
	result, err := s.Scan(context.Background(), client, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range result.Findings {
		if f.CheckID == "CIS-4.1.6" && f.Resource.Namespace == "app" {
			found = true
			if f.Severity != engine.SeverityMedium {
				t.Errorf("expected MEDIUM severity, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected CIS-4.1.6 (default SA automounts token)")
	}
}

func TestScan_PrivilegedPod(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "app"}},
		&corev1.ServiceAccount{
			ObjectMeta:                   metav1.ObjectMeta{Name: "default", Namespace: "app"},
			AutomountServiceAccountToken: boolPtr(false),
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "priv-pod", Namespace: "app"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name:  "app",
					Image: "nginx:1.25",
					SecurityContext: &corev1.SecurityContext{
						Privileged: boolPtr(true),
					},
				}},
			},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		},
	)

	s := New()
	result, err := s.Scan(context.Background(), client, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range result.Findings {
		if f.CheckID == "CIS-4.2.1" {
			found = true
			if f.Severity != engine.SeverityCritical {
				t.Errorf("expected CRITICAL severity, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected CIS-4.2.1 (privileged container)")
	}
}

func TestScan_HostPIDIPC(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "app"}},
		&corev1.ServiceAccount{
			ObjectMeta:                   metav1.ObjectMeta{Name: "default", Namespace: "app"},
			AutomountServiceAccountToken: boolPtr(false),
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "host-pod", Namespace: "app"},
			Spec: corev1.PodSpec{
				HostPID: true,
				HostIPC: true,
				Containers: []corev1.Container{{
					Name:  "app",
					Image: "nginx:1.25",
					SecurityContext: &corev1.SecurityContext{
						RunAsNonRoot: boolPtr(true),
						RunAsUser:    int64Ptr(1000),
					},
				}},
			},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		},
	)

	s := New()
	result, err := s.Scan(context.Background(), client, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	checks := map[string]bool{"CIS-4.2.2": false, "CIS-4.2.3": false}
	for _, f := range result.Findings {
		if _, ok := checks[f.CheckID]; ok {
			checks[f.CheckID] = true
		}
	}
	for check, found := range checks {
		if !found {
			t.Errorf("expected %s finding", check)
		}
	}
}

func TestScan_NoNetworkPolicy(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "unprotected"}},
		&corev1.ServiceAccount{
			ObjectMeta:                   metav1.ObjectMeta{Name: "default", Namespace: "unprotected"},
			AutomountServiceAccountToken: boolPtr(false),
		},
	)

	s := New()
	result, err := s.Scan(context.Background(), client, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range result.Findings {
		if f.CheckID == "CIS-4.3.1" && f.Resource.Name == "unprotected" {
			found = true
		}
	}
	if !found {
		t.Error("expected CIS-4.3.1 (no network policy)")
	}
}

func TestScan_NoResourceQuotas(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "dev"}},
		&corev1.ServiceAccount{
			ObjectMeta:                   metav1.ObjectMeta{Name: "default", Namespace: "dev"},
			AutomountServiceAccountToken: boolPtr(false),
		},
	)

	s := New()
	result, err := s.Scan(context.Background(), client, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	foundQuota := false
	foundLimit := false
	for _, f := range result.Findings {
		if f.CheckID == "CIS-4.5.1" && f.Resource.Name == "dev" {
			foundQuota = true
		}
		if f.CheckID == "CIS-4.5.2" && f.Resource.Name == "dev" {
			foundLimit = true
		}
	}
	if !foundQuota {
		t.Error("expected CIS-4.5.1 (no resource quotas)")
	}
	if !foundLimit {
		t.Error("expected CIS-4.5.2 (no limit range)")
	}
}

func TestScan_SystemNamespaceSkipped(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "kube-proxy", Namespace: "kube-system"},
			Spec: corev1.PodSpec{
				HostNetwork: true,
				Containers: []corev1.Container{{
					Name:  "proxy",
					Image: "kube-proxy:1.28",
					SecurityContext: &corev1.SecurityContext{
						Privileged: boolPtr(true),
					},
				}},
			},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		},
	)

	s := New()
	result, err := s.Scan(context.Background(), client, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range result.Findings {
		if f.Resource.Namespace == "kube-system" || f.Resource.Name == "kube-system" {
			t.Errorf("should not scan kube-system, found: %s - %s", f.CheckID, f.Title)
		}
	}
}
