package workload

import (
	"context"
	"testing"

	"github.com/RamazanKara/kube-shield/pkg/scanner/engine"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func boolPtr(b bool) *bool    { return &b }
func int64Ptr(i int64) *int64 { return &i }

func TestScan_PrivilegedContainer(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
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
	})

	s := New()
	result, err := s.Scan(context.Background(), client, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range result.Findings {
		if f.CheckID == "WL-010" {
			found = true
			if f.Severity != engine.SeverityCritical {
				t.Errorf("expected CRITICAL severity, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected to find WL-010 (privileged container)")
	}
}

func TestScan_HostNamespaces(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "host-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			HostPID:     true,
			HostIPC:     true,
			HostNetwork: true,
			Containers: []corev1.Container{{
				Name:  "app",
				Image: "nginx:1.25",
				SecurityContext: &corev1.SecurityContext{
					RunAsNonRoot:             boolPtr(true),
					ReadOnlyRootFilesystem:   boolPtr(true),
					AllowPrivilegeEscalation: boolPtr(false),
				},
				Resources: corev1.ResourceRequirements{
					Limits: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("100m"),
						corev1.ResourceMemory: resource.MustParse("128Mi"),
					},
					Requests: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("50m"),
						corev1.ResourceMemory: resource.MustParse("64Mi"),
					},
				},
				LivenessProbe: &corev1.Probe{
					ProbeHandler: corev1.ProbeHandler{
						HTTPGet: &corev1.HTTPGetAction{Path: "/healthz"},
					},
				},
			}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	})

	s := New()
	result, err := s.Scan(context.Background(), client, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	checks := map[string]bool{"WL-001": false, "WL-002": false, "WL-003": false}
	for _, f := range result.Findings {
		if _, ok := checks[f.CheckID]; ok {
			checks[f.CheckID] = true
		}
	}

	for check, found := range checks {
		if !found {
			t.Errorf("expected to find %s", check)
		}
	}
}

func TestScan_NoSecurityContext(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "insecure-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "app",
				Image: "nginx",
			}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	})

	s := New()
	result, err := s.Scan(context.Background(), client, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	checks := map[string]bool{
		"WL-011": false, // No security context
		"WL-030": false, // Latest/no tag
		"WL-031": false, // No resource limits
		"WL-033": false, // No liveness probe
	}
	for _, f := range result.Findings {
		if _, ok := checks[f.CheckID]; ok {
			checks[f.CheckID] = true
		}
	}

	for check, found := range checks {
		if !found {
			t.Errorf("expected to find %s", check)
		}
	}
}

func TestScan_DangerousCapabilities(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "cap-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "app",
				Image: "myapp:v1.0",
				SecurityContext: &corev1.SecurityContext{
					RunAsNonRoot:             boolPtr(true),
					AllowPrivilegeEscalation: boolPtr(false),
					ReadOnlyRootFilesystem:   boolPtr(true),
					Capabilities: &corev1.Capabilities{
						Add: []corev1.Capability{"SYS_ADMIN", "NET_RAW"},
					},
				},
				Resources: corev1.ResourceRequirements{
					Limits: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("100m"),
						corev1.ResourceMemory: resource.MustParse("128Mi"),
					},
					Requests: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("50m"),
						corev1.ResourceMemory: resource.MustParse("64Mi"),
					},
				},
				LivenessProbe: &corev1.Probe{
					ProbeHandler: corev1.ProbeHandler{
						HTTPGet: &corev1.HTTPGetAction{Path: "/healthz"},
					},
				},
			}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	})

	s := New()
	result, err := s.Scan(context.Background(), client, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	checks := map[string]bool{"WL-020": false, "WL-021": false}
	for _, f := range result.Findings {
		if _, ok := checks[f.CheckID]; ok {
			checks[f.CheckID] = true
		}
	}

	for check, found := range checks {
		if !found {
			t.Errorf("expected to find %s (dangerous capability)", check)
		}
	}
}

func TestScan_SecurePod(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "secure-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			AutomountServiceAccountToken: boolPtr(false),
			ServiceAccountName:           "dedicated-sa",
			Containers: []corev1.Container{{
				Name:  "app",
				Image: "myapp:v1.2.3",
				SecurityContext: &corev1.SecurityContext{
					RunAsNonRoot:             boolPtr(true),
					RunAsUser:                int64Ptr(1000),
					ReadOnlyRootFilesystem:   boolPtr(true),
					AllowPrivilegeEscalation: boolPtr(false),
					Capabilities: &corev1.Capabilities{
						Drop: []corev1.Capability{"ALL"},
					},
				},
				Resources: corev1.ResourceRequirements{
					Limits: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("100m"),
						corev1.ResourceMemory: resource.MustParse("128Mi"),
					},
					Requests: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("50m"),
						corev1.ResourceMemory: resource.MustParse("64Mi"),
					},
				},
				LivenessProbe: &corev1.Probe{
					ProbeHandler: corev1.ProbeHandler{
						HTTPGet: &corev1.HTTPGetAction{Path: "/healthz"},
					},
				},
			}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	})

	s := New()
	result, err := s.Scan(context.Background(), client, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Findings) != 0 {
		for _, f := range result.Findings {
			t.Errorf("unexpected finding on secure pod: %s - %s", f.CheckID, f.Title)
		}
	}
}

func TestScan_NamespaceFilter(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "pod-prod", Namespace: "production"},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "nginx"}}},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "pod-dev", Namespace: "development"},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "nginx"}}},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		},
	)

	s := New()
	result, err := s.Scan(context.Background(), client, "production")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range result.Findings {
		if f.Resource.Namespace != "production" {
			t.Errorf("expected all findings in production namespace, got %s", f.Resource.Namespace)
		}
	}
}

func TestImageTagChecks(t *testing.T) {
	tests := []struct {
		image    string
		hasTag   bool
		isLatest bool
	}{
		{"nginx", false, true},
		{"nginx:latest", true, true},
		{"nginx:1.25", true, false},
		{"myregistry.io/app:v1.0", true, false},
		{"myregistry.io/app", false, true},
		{"myregistry.io/app:latest", true, true},
	}

	for _, tt := range tests {
		if containsTag(tt.image) != tt.hasTag {
			t.Errorf("containsTag(%q) = %v, want %v", tt.image, !tt.hasTag, tt.hasTag)
		}
		if hasLatestTag(tt.image) != tt.isLatest {
			t.Errorf("hasLatestTag(%q) = %v, want %v", tt.image, !tt.isLatest, tt.isLatest)
		}
	}
}
