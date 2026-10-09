package rbac

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/RamazanKara/kube-shield/v2/internal/scanner/engine"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func TestScanRolePermissions(t *testing.T) {
	for _, tt := range []struct {
		name, resource string
		verbs          []string
		want           string
	}{
		{"read pods", "pods", []string{"get", "list"}, ""},
		{"wildcard verbs", "pods", []string{"*"}, "RBAC-002"},
		{"wildcard resources", "*", []string{"get"}, "RBAC-003"},
		{"write secrets", "secrets", []string{"patch"}, "RBAC-011"},
		{"read and write secrets", "secrets", []string{"get", "update"}, "RBAC-010,RBAC-011"},
		{"exec", "pods/exec", []string{"create"}, "RBAC-021"},
		{"node proxy", "nodes/proxy", []string{"get"}, "RBAC-022"},
		{"read volumes", "persistentvolumes", []string{"get"}, ""},
		{"create volumes", "persistentvolumes", []string{"create"}, "RBAC-023"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			client := fake.NewSimpleClientset(&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "team"}, Rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{tt.resource}, Verbs: tt.verbs}}})
			result, err := New().Scan(context.Background(), client, "team")
			if err != nil {
				t.Fatal(err)
			}
			var ids []string
			for _, f := range result.Findings {
				ids = append(ids, f.CheckID)
				if f.Resource != (engine.Resource{Kind: "Role", Name: "app", Namespace: "team"}) {
					t.Fatalf("wrong resource: %#v", f.Resource)
				}
			}
			slices.Sort(ids)
			if got := strings.Join(ids, ","); got != tt.want {
				t.Errorf("checks = %q, want %q", got, tt.want)
			}
			other, err := New().Scan(context.Background(), client, "other")
			if err != nil || len(other.Findings) != 0 {
				t.Fatalf("namespace filter failed: %#v, %v", other, err)
			}
		})
	}
}

func TestScanBindingRoleKind(t *testing.T) {
	for _, tt := range []struct{ name, roleKind, subjectKind, subjectName, want string }{
		{"cluster role service account", "ClusterRole", "ServiceAccount", "app", "RBAC-030"},
		{"namespaced role with same name", "Role", "ServiceAccount", "app", ""},
		{"unauthenticated cluster role", "ClusterRole", "Group", "system:unauthenticated", "RBAC-031"},
		{"unauthenticated namespaced role", "Role", "Group", "system:unauthenticated", ""},
		{"default service account", "Role", "ServiceAccount", "default", "RBAC-032"},
		{"user named default", "Role", "User", "default", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			client := fake.NewSimpleClientset(&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "binding", Namespace: "team"}, RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: tt.roleKind, Name: "cluster-admin"}, Subjects: []rbacv1.Subject{{Kind: tt.subjectKind, Name: tt.subjectName, Namespace: "team"}}})
			result, err := New().Scan(context.Background(), client, "team")
			if err != nil {
				t.Fatal(err)
			}
			if tt.want == "" {
				if len(result.Findings) != 0 {
					t.Fatalf("unexpected findings: %#v", result.Findings)
				}
				return
			}
			if len(result.Findings) != 1 || result.Findings[0].CheckID != tt.want || result.Findings[0].Resource.Kind != "RoleBinding" {
				t.Fatalf("unexpected findings: %#v", result.Findings)
			}
		})
	}
}

func TestScanListErrors(t *testing.T) {
	for _, resource := range []string{"clusterroles", "clusterrolebindings", "roles", "rolebindings"} {
		t.Run(resource, func(t *testing.T) {
			denied := errors.New("forbidden")
			client := fake.NewSimpleClientset()
			client.PrependReactor("list", resource, func(ktesting.Action) (bool, runtime.Object, error) { return true, nil, denied })
			result, err := New().Scan(context.Background(), client, "team")
			if !errors.Is(err, denied) || result != nil {
				t.Fatalf("failure must propagate, got %#v, %v", result, err)
			}
		})
	}
}
