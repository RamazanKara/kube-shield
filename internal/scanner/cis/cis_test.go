package cis

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/RamazanKara/kube-shield/internal/scanner/engine"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
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
		if f.CheckID == "CIS-5.1.1" {
			found = true
			if f.Severity != engine.SeverityCritical {
				t.Errorf("expected CRITICAL severity, got %s", f.Severity)
			}
			if f.CISRef != "5.1.1" {
				t.Errorf("expected CISRef 5.1.1, got %s", f.CISRef)
			}
		}
	}
	if !found {
		t.Error("expected CIS-5.1.1 (cluster-admin bound to SA)")
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
		if f.CheckID == "CIS-5.1.2" {
			found = true
			if f.Severity != engine.SeverityHigh {
				t.Errorf("expected HIGH severity, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected CIS-5.1.2 (secret access)")
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
		if f.CheckID == "CIS-5.1.6" && f.Resource.Namespace == "app" {
			found = true
			if f.Severity != engine.SeverityMedium {
				t.Errorf("expected MEDIUM severity, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected CIS-5.1.6 (default SA automounts token)")
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
		if f.CheckID == "CIS-5.2.2" {
			found = true
			if f.Severity != engine.SeverityCritical {
				t.Errorf("expected CRITICAL severity, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected CIS-5.2.2 (privileged container)")
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

	checks := map[string]bool{"CIS-5.2.3": false, "CIS-5.2.4": false}
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
		if f.CheckID == "CIS-5.3.2" && f.Resource.Name == "unprotected" {
			found = true
		}
	}
	if !found {
		t.Error("expected CIS-5.3.2 (no network policy)")
	}
}

func TestScan_ResourcePoliciesAreNotCISChecks(t *testing.T) {
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

	for _, f := range result.Findings {
		if f.CheckID == "CIS-4.5.1" || f.CheckID == "CIS-4.5.2" || f.CISRef == "5.6.1" {
			t.Errorf("resource policies must not emit CIS findings: %#v", f)
		}
	}
	for _, action := range client.Actions() {
		if action.GetResource().Resource == "resourcequotas" || action.GetResource().Resource == "limitranges" {
			t.Errorf("CIS scanner should not query %s", action.GetResource().Resource)
		}
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

func TestScan_PodPolicies(t *testing.T) {
	runtimeDefault := &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}
	unconfined := &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeUnconfined}
	tests := []struct {
		name   string
		change func(*corev1.Pod)
		want   []string
	}{
		{name: "secure pod"},
		{name: "default namespace", change: func(p *corev1.Pod) { p.Namespace = "default" }, want: []string{"CIS-5.6.4"}},
		{name: "pod token override", change: func(p *corev1.Pod) { p.Spec.AutomountServiceAccountToken = boolPtr(true) }, want: []string{"CIS-5.1.6"}},
		{name: "token disabled", change: func(p *corev1.Pod) { p.Spec.AutomountServiceAccountToken = boolPtr(false) }},
		{name: "host path", change: func(p *corev1.Pod) {
			p.Spec.Volumes = []corev1.Volume{{Name: "host", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/log"}}}}
		}, want: []string{"CIS-5.2.11"}},
		{name: "empty dir", change: func(p *corev1.Pod) {
			p.Spec.Volumes = []corev1.Volume{{Name: "data", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}}
		}},
		{name: "host ports deduplicated", change: func(p *corev1.Pod) {
			p.Spec.Containers[0].Ports = []corev1.ContainerPort{{HostPort: 8080}, {HostPort: 8443}}
		}, want: []string{"CIS-5.2.12"}},
		{name: "container port", change: func(p *corev1.Pod) {
			p.Spec.Containers[0].Ports = []corev1.ContainerPort{{ContainerPort: 8080}}
		}},
		{name: "host process inherited", change: func(p *corev1.Pod) {
			p.Spec.SecurityContext.WindowsOptions = &corev1.WindowsSecurityContextOptions{HostProcess: boolPtr(true)}
		}, want: []string{"CIS-5.2.10"}},
		{name: "host process container", change: func(p *corev1.Pod) {
			p.Spec.Containers[0].SecurityContext.WindowsOptions = &corev1.WindowsSecurityContextOptions{HostProcess: boolPtr(true)}
		}, want: []string{"CIS-5.2.10"}},
		{name: "host process false overrides pod", change: func(p *corev1.Pod) {
			p.Spec.SecurityContext.WindowsOptions = &corev1.WindowsSecurityContextOptions{HostProcess: boolPtr(true)}
			p.Spec.Containers[0].SecurityContext.WindowsOptions = &corev1.WindowsSecurityContextOptions{HostProcess: boolPtr(false)}
		}},
		{name: "seccomp missing", change: func(p *corev1.Pod) { p.Spec.SecurityContext.SeccompProfile = nil }, want: []string{"CIS-5.6.2"}},
		{name: "seccomp unconfined overrides pod", change: func(p *corev1.Pod) {
			p.Spec.Containers[0].SecurityContext.SeccompProfile = unconfined
		}, want: []string{"CIS-5.6.2"}},
		{name: "seccomp container overrides unconfined", change: func(p *corev1.Pod) {
			p.Spec.SecurityContext.SeccompProfile = unconfined
			p.Spec.Containers[0].SecurityContext.SeccompProfile = runtimeDefault
		}},
		{name: "seccomp localhost", change: func(p *corev1.Pod) {
			profile := "profiles/app.json"
			p.Spec.Containers[0].SecurityContext.SeccompProfile = &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeLocalhost, LocalhostProfile: &profile}
		}},
		{name: "default capabilities", change: func(p *corev1.Pod) { p.Spec.Containers[0].SecurityContext.Capabilities = nil }, want: []string{"CIS-5.2.9"}},
		{name: "added capabilities after drop all", change: func(p *corev1.Pod) {
			p.Spec.Containers[0].SecurityContext.Capabilities.Add = []corev1.Capability{"NET_BIND_SERVICE"}
		}, want: []string{"CIS-5.2.9"}},
		{name: "missing security context", change: func(p *corev1.Pod) {
			p.Spec.SecurityContext = nil
			p.Spec.Containers[0].SecurityContext = nil
		}, want: []string{"CIS-5.2.7", "CIS-5.2.9", "CIS-5.6.2"}},
		{name: "root override", change: func(p *corev1.Pod) {
			p.Spec.Containers[0].SecurityContext.RunAsNonRoot = boolPtr(false)
			p.Spec.Containers[0].SecurityContext.RunAsUser = int64Ptr(0)
		}, want: []string{"CIS-5.2.7"}},
		{name: "nonzero uid", change: func(p *corev1.Pod) {
			p.Spec.Containers[0].SecurityContext.RunAsNonRoot = boolPtr(false)
			p.Spec.Containers[0].SecurityContext.RunAsUser = int64Ptr(1000)
		}},
		{name: "windows skips linux checks", change: func(p *corev1.Pod) {
			p.Spec.OS = &corev1.PodOS{Name: corev1.Windows}
			p.Spec.SecurityContext = nil
			p.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{WindowsOptions: &corev1.WindowsSecurityContextOptions{HostProcess: boolPtr(true)}}
		}, want: []string{"CIS-5.2.10"}},
		{name: "init container", change: func(p *corev1.Pod) {
			c := *p.Spec.Containers[0].DeepCopy()
			c.Name = "init"
			c.Ports = []corev1.ContainerPort{{HostPort: 8080}}
			p.Spec.InitContainers = []corev1.Container{c}
		}, want: []string{"CIS-5.2.12"}},
		{name: "ephemeral container", change: func(p *corev1.Pod) {
			c := *p.Spec.Containers[0].DeepCopy()
			c.Name = "debug"
			c.SecurityContext.SeccompProfile = unconfined
			p.Spec.EphemeralContainers = []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon(c)}}
		}, want: []string{"CIS-5.6.2"}},
		{name: "completed pod", change: func(p *corev1.Pod) { p.Namespace = "default"; p.Status.Phase = corev1.PodSucceeded }},
		{name: "failed pod", change: func(p *corev1.Pod) { p.Namespace = "default"; p.Status.Phase = corev1.PodFailed }},
		{name: "system namespace", change: func(p *corev1.Pod) { p.Namespace = "kube-system"; p.Spec.HostPID = true }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "team"},
				Spec: corev1.PodSpec{
					SecurityContext: &corev1.PodSecurityContext{RunAsNonRoot: boolPtr(true), SeccompProfile: runtimeDefault},
					Containers:      []corev1.Container{{Name: "web", SecurityContext: &corev1.SecurityContext{Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}}}},
				},
			}
			if tt.change != nil {
				tt.change(pod)
			}
			findings, err := checkPodSecurity(context.Background(), fake.NewSimpleClientset(pod), "")
			if err != nil {
				t.Fatal(err)
			}
			assertCheckIDs(t, findings, tt.want)
		})
	}
}

func TestScan_AdmissionPolicies(t *testing.T) {
	tests := []struct {
		name   string
		labels map[string]string
		want   bool
	}{
		{name: "missing", want: true},
		{name: "privileged", labels: map[string]string{"pod-security.kubernetes.io/enforce": "privileged"}, want: true},
		{name: "audit only", labels: map[string]string{"pod-security.kubernetes.io/audit": "restricted"}, want: true},
		{name: "warn only", labels: map[string]string{"pod-security.kubernetes.io/warn": "restricted"}, want: true},
		{name: "invalid", labels: map[string]string{"pod-security.kubernetes.io/enforce": "invalid"}, want: true},
		{name: "baseline", labels: map[string]string{"pod-security.kubernetes.io/enforce": "baseline"}},
		{name: "restricted", labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fake.NewSimpleClientset(
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team", Labels: tt.labels}},
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "other"}},
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}},
			)
			findings, err := checkAdmissionPolicies(context.Background(), client, "team")
			if err != nil {
				t.Fatal(err)
			}
			var want []string
			if tt.want {
				want = []string{"CIS-5.2.1"}
			}
			assertCheckIDs(t, findings, want)
		})
	}
}

func TestScan_RBACPermissions(t *testing.T) {
	tests := []struct {
		name     string
		rules    []rbacv1.PolicyRule
		want     []string
		wantRole []string
	}{
		{name: "pod creation", rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"create"}}}, want: []string{"CIS-5.1.4"}, wantRole: []string{"CIS-5.1.4"}},
		{name: "pod read", rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list"}}}},
		{name: "wrong API group", rules: []rbacv1.PolicyRule{{APIGroups: []string{"example.com"}, Resources: []string{"pods", "serviceaccounts/token", "certificatesigningrequests/approval", "mutatingwebhookconfigurations"}, Verbs: []string{"*"}}}},
		{name: "CSR update", rules: []rbacv1.PolicyRule{{APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"certificatesigningrequests/approval"}, Verbs: []string{"update"}}}, want: []string{"CIS-5.1.11"}},
		{name: "CSR patch wildcard subresource", rules: []rbacv1.PolicyRule{{APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"*/approval"}, Verbs: []string{"patch"}}}, want: []string{"CIS-5.1.11"}},
		{name: "CSR read", rules: []rbacv1.PolicyRule{{APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"certificatesigningrequests/approval"}, Verbs: []string{"get"}}}},
		{name: "CSR parent does not grant approval", rules: []rbacv1.PolicyRule{{APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"certificatesigningrequests"}, Verbs: []string{"update"}}}},
		{name: "mutating webhook", rules: []rbacv1.PolicyRule{{APIGroups: []string{"admissionregistration.k8s.io"}, Resources: []string{"mutatingwebhookconfigurations"}, Verbs: []string{"patch"}}}, want: []string{"CIS-5.1.12"}},
		{name: "validating webhook read", rules: []rbacv1.PolicyRule{{APIGroups: []string{"admissionregistration.k8s.io"}, Resources: []string{"validatingwebhookconfigurations"}, Verbs: []string{"get"}}}, want: []string{"CIS-5.1.12"}},
		{name: "no webhook verbs", rules: []rbacv1.PolicyRule{{APIGroups: []string{"admissionregistration.k8s.io"}, Resources: []string{"validatingwebhookconfigurations"}}}},
		{name: "token creation", rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"serviceaccounts/token"}, Verbs: []string{"create"}}}, want: []string{"CIS-5.1.13"}, wantRole: []string{"CIS-5.1.13"}},
		{name: "token read", rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"serviceaccounts/token"}, Verbs: []string{"get"}}}},
		{name: "service account parent", rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"serviceaccounts"}, Verbs: []string{"create"}}}},
		{name: "resource wildcard", rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"*"}, Verbs: []string{"create"}}}, want: []string{"CIS-5.1.4", "CIS-5.1.13"}, wantRole: []string{"CIS-5.1.4", "CIS-5.1.13"}},
		{name: "group and verb wildcards", rules: []rbacv1.PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"pods", "serviceaccounts/token", "certificatesigningrequests/approval", "validatingwebhookconfigurations"}, Verbs: []string{"*"}}}, want: []string{"CIS-5.1.4", "CIS-5.1.11", "CIS-5.1.12", "CIS-5.1.13"}, wantRole: []string{"CIS-5.1.4", "CIS-5.1.13"}},
		{name: "separate rules cannot combine permissions", rules: []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
			{APIGroups: []string{"example.com"}, Resources: []string{"pods"}, Verbs: []string{"create"}},
		}},
		{name: "duplicate rules", rules: []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"create"}},
			{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"create"}},
		}, want: []string{"CIS-5.1.4"}, wantRole: []string{"CIS-5.1.4"}},
	}
	for _, tt := range tests {
		for _, kind := range []string{"Role", "ClusterRole"} {
			t.Run(tt.name+"/"+kind, func(t *testing.T) {
				var obj runtime.Object = &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "custom"}, Rules: tt.rules}
				want := tt.want
				if kind == "Role" {
					obj = &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "custom", Namespace: "team"}, Rules: tt.rules}
					want = tt.wantRole
				}
				result, err := New().Scan(context.Background(), fake.NewSimpleClientset(obj), "team")
				if err != nil {
					t.Fatal(err)
				}
				assertCheckIDs(t, result.Findings, want)
			})
		}
	}
}

func TestScan_RBACScopeAndSystemRoles(t *testing.T) {
	rules := []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"create"}}}
	client := fake.NewSimpleClientset(
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "custom", Namespace: "other"}, Rules: rules},
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "system:controller", Namespace: "team"}, Rules: rules},
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "custom", Namespace: "kube-system"}, Rules: rules},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "system:controller"}, Rules: rules},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "cluster-admin"}, Rules: rules},
	)
	result, err := New().Scan(context.Background(), client, "team")
	if err != nil {
		t.Fatal(err)
	}
	assertCheckIDs(t, result.Findings, nil)
}

func TestScan_SystemMasters(t *testing.T) {
	for _, kind := range []string{"Group", "User", "ServiceAccount"} {
		for _, name := range []string{"system:masters", "operators"} {
			t.Run(kind+"/"+name, func(t *testing.T) {
				subjects := []rbacv1.Subject{{Kind: kind, Name: name}, {Kind: kind, Name: name}}
				client := fake.NewSimpleClientset(
					&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "cluster"}, Subjects: subjects},
					&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "local", Namespace: "team"}, Subjects: subjects},
				)
				result, err := New().Scan(context.Background(), client, "team")
				if err != nil {
					t.Fatal(err)
				}
				var want []string
				if kind == "Group" && name == "system:masters" {
					want = []string{"CIS-5.1.7", "CIS-5.1.7"}
				}
				assertCheckIDs(t, result.Findings, want)
			})
		}
	}
}

func TestScan_ServiceAccountTokens(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "team"}, AutomountServiceAccountToken: boolPtr(false)},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "implicit", Namespace: "team"}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "explicit", Namespace: "team"}, AutomountServiceAccountToken: boolPtr(true)},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "disabled", Namespace: "team"}, AutomountServiceAccountToken: boolPtr(false)},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "other"}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "kube-system"}},
	)
	result, err := New().Scan(context.Background(), client, "team")
	if err != nil {
		t.Fatal(err)
	}
	assertCheckIDs(t, result.Findings, []string{"CIS-5.1.6", "CIS-5.1.6"})
	for _, f := range result.Findings {
		if f.Resource.Namespace != "team" || f.Resource.Name != "implicit" && f.Resource.Name != "explicit" {
			t.Errorf("unexpected token finding: %#v", f)
		}
	}
}

func TestScan_DefaultServiceAccountBinding(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "team"}, AutomountServiceAccountToken: boolPtr(false)},
		&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "bound", Namespace: "team"}, Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Name: "default", Namespace: "team"}}},
		&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "other", Namespace: "team"}, Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Name: "default", Namespace: "other"}}},
	)
	result, err := New().Scan(context.Background(), client, "team")
	if err != nil {
		t.Fatal(err)
	}
	assertCheckIDs(t, result.Findings, []string{"CIS-5.1.5"})
}

func TestScan_ListErrors(t *testing.T) {
	for _, resource := range []string{"clusterrolebindings", "clusterroles", "roles", "rolebindings", "serviceaccounts", "pods", "namespaces"} {
		t.Run(resource, func(t *testing.T) {
			client := fake.NewSimpleClientset()
			denied := errors.New("list denied")
			client.PrependReactor("list", resource, func(clienttesting.Action) (bool, runtime.Object, error) {
				return true, nil, denied
			})
			if _, err := New().Scan(context.Background(), client, ""); !errors.Is(err, denied) {
				t.Errorf("Scan error = %v, want %v", err, denied)
			}
		})
	}
}

func assertCheckIDs(t *testing.T, findings []engine.Finding, want []string) {
	t.Helper()
	var got []string
	seen := make(map[string]bool)
	for _, f := range findings {
		got = append(got, f.CheckID)
		if f.CheckID != "CIS-"+f.CISRef || !strings.HasPrefix(f.ID, f.CheckID+"-") {
			t.Errorf("inconsistent CIS identifiers: %#v", f)
		}
		if seen[f.ID] {
			t.Errorf("duplicate finding ID: %s", f.ID)
		}
		seen[f.ID] = true
		if _, ok := engine.RuleByID(f.CheckID); !ok {
			t.Errorf("missing catalog entry: %s", f.CheckID)
		}
	}
	sort.Strings(got)
	want = append([]string(nil), want...)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("check IDs = %v, want %v", got, want)
	}
}
