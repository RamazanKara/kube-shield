package secrets

import (
	"context"
	"testing"

	"github.com/RamazanKara/kube-shield/pkg/scanner/engine"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func boolPtr(b bool) *bool { return &b }

func TestScan_SecretAsEnvVar(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name:  "web",
					Image: "nginx:1.25",
					Env: []corev1.EnvVar{{
						Name: "DB_PASSWORD",
						ValueFrom: &corev1.EnvVarSource{
							SecretKeyRef: &corev1.SecretKeySelector{
								LocalObjectReference: corev1.LocalObjectReference{Name: "db-creds"},
								Key:                  "password",
							},
						},
					}},
				}},
			},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "db-creds", Namespace: "default"},
			Data:       map[string][]byte{"password": []byte("s3cret")},
		},
	)

	s := New()
	result, err := s.Scan(context.Background(), client, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range result.Findings {
		if f.CheckID == "SEC-001" {
			found = true
			if f.Severity != engine.SeverityMedium {
				t.Errorf("expected MEDIUM severity, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected SEC-001 (secret as env var)")
	}
}

func TestScan_MissingSecretReference(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name:  "web",
					Image: "nginx:1.25",
					Env: []corev1.EnvVar{{
						Name: "API_KEY",
						ValueFrom: &corev1.EnvVarSource{
							SecretKeyRef: &corev1.SecretKeySelector{
								LocalObjectReference: corev1.LocalObjectReference{Name: "missing-secret"},
								Key:                  "key",
							},
						},
					}},
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
		if f.CheckID == "SEC-002" {
			found = true
			if f.Severity != engine.SeverityHigh {
				t.Errorf("expected HIGH severity, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected SEC-002 (missing secret)")
	}
}

func TestScan_EnvFrom(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name:  "web",
					Image: "nginx:1.25",
					EnvFrom: []corev1.EnvFromSource{{
						SecretRef: &corev1.SecretEnvSource{
							LocalObjectReference: corev1.LocalObjectReference{Name: "all-secrets"},
						},
					}},
				}},
			},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "all-secrets", Namespace: "default"},
			Data:       map[string][]byte{"key1": []byte("val1"), "key2": []byte("val2")},
		},
	)

	s := New()
	result, err := s.Scan(context.Background(), client, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range result.Findings {
		if f.CheckID == "SEC-003" {
			found = true
		}
	}
	if !found {
		t.Error("expected SEC-003 (envFrom secret)")
	}
}

func TestScan_MissingEnvFromSecretReference(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name:  "web",
					Image: "nginx:1.25",
					EnvFrom: []corev1.EnvFromSource{{
						SecretRef: &corev1.SecretEnvSource{
							LocalObjectReference: corev1.LocalObjectReference{Name: "missing-envfrom-secret"},
						},
					}},
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
		if f.CheckID == "SEC-002" {
			found = true
		}
	}
	if !found {
		t.Error("expected SEC-002 (missing envFrom secret)")
	}
}

func TestScan_SecretVolumePermissiveMode(t *testing.T) {
	mode := int32(0o644)
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name:  "web",
					Image: "nginx:1.25",
					VolumeMounts: []corev1.VolumeMount{{
						Name:      "secret-vol",
						MountPath: "/etc/secrets",
					}},
				}},
				Volumes: []corev1.Volume{{
					Name: "secret-vol",
					VolumeSource: corev1.VolumeSource{
						Secret: &corev1.SecretVolumeSource{
							SecretName:  "my-secret",
							DefaultMode: &mode,
						},
					},
				}},
			},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "my-secret", Namespace: "default"},
			Data:       map[string][]byte{"token": []byte("abc123")},
		},
	)

	s := New()
	result, err := s.Scan(context.Background(), client, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range result.Findings {
		if f.CheckID == "SEC-004" {
			found = true
			if f.Severity != engine.SeverityMedium {
				t.Errorf("expected MEDIUM severity, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected SEC-004 (permissive volume mode)")
	}
}

func TestScan_SecretVolumeDefaultModeIsPermissive(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name:  "web",
					Image: "nginx:1.25",
					VolumeMounts: []corev1.VolumeMount{{
						Name:      "secret-vol",
						MountPath: "/etc/secrets",
					}},
				}},
				Volumes: []corev1.Volume{{
					Name: "secret-vol",
					VolumeSource: corev1.VolumeSource{
						Secret: &corev1.SecretVolumeSource{
							SecretName: "my-secret",
						},
					},
				}},
			},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "my-secret", Namespace: "default"},
			Data:       map[string][]byte{"token": []byte("abc123")},
		},
	)

	s := New()
	result, err := s.Scan(context.Background(), client, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range result.Findings {
		if f.CheckID == "SEC-004" {
			found = true
		}
	}
	if !found {
		t.Error("expected SEC-004 for default secret volume file mode")
	}
}

func TestScan_MissingSecretVolumeReference(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"},
			Spec: corev1.PodSpec{
				Volumes: []corev1.Volume{{
					Name: "secret-vol",
					VolumeSource: corev1.VolumeSource{
						Secret: &corev1.SecretVolumeSource{
							SecretName: "missing-volume-secret",
						},
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
		if f.CheckID == "SEC-002" {
			found = true
		}
	}
	if !found {
		t.Error("expected SEC-002 (missing secret volume)")
	}
}

func TestScan_SecretMountedAtSensitivePath(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name:  "web",
					Image: "nginx:1.25",
					VolumeMounts: []corev1.VolumeMount{{
						Name:      "secret-vol",
						MountPath: "/etc",
					}},
				}},
				Volumes: []corev1.Volume{{
					Name: "secret-vol",
					VolumeSource: corev1.VolumeSource{
						Secret: &corev1.SecretVolumeSource{
							SecretName: "my-secret",
						},
					},
				}},
			},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "my-secret", Namespace: "default"},
			Data:       map[string][]byte{"token": []byte("abc123")},
		},
	)

	s := New()
	result, err := s.Scan(context.Background(), client, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range result.Findings {
		if f.CheckID == "SEC-005" {
			found = true
			if f.Severity != engine.SeverityHigh {
				t.Errorf("expected HIGH severity, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected SEC-005 (secret at sensitive path)")
	}
}

func TestScan_EmptySecret(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "empty-secret", Namespace: "default"},
			Type:       corev1.SecretTypeOpaque,
		},
	)

	s := New()
	result, err := s.Scan(context.Background(), client, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range result.Findings {
		if f.CheckID == "SEC-010" {
			found = true
			if f.Severity != engine.SeverityInfo {
				t.Errorf("expected INFO severity, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected SEC-010 (empty secret)")
	}
}

func TestScan_SecurePod_NoFindings(t *testing.T) {
	mode := int32(0o400)
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "secure-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name:  "web",
					Image: "nginx:1.25",
					VolumeMounts: []corev1.VolumeMount{{
						Name:      "secret-vol",
						MountPath: "/var/run/secrets/app",
					}},
				}},
				Volumes: []corev1.Volume{{
					Name: "secret-vol",
					VolumeSource: corev1.VolumeSource{
						Secret: &corev1.SecretVolumeSource{
							SecretName:  "my-secret",
							DefaultMode: &mode,
						},
					},
				}},
			},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "my-secret", Namespace: "default"},
			Data:       map[string][]byte{"token": []byte("abc123")},
		},
	)

	s := New()
	result, err := s.Scan(context.Background(), client, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings for secure pod, got %d", len(result.Findings))
		for _, f := range result.Findings {
			t.Logf("  unexpected: %s - %s", f.CheckID, f.Title)
		}
	}
}

func TestScan_OptionalMissingSecret(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name:  "web",
					Image: "nginx:1.25",
					Env: []corev1.EnvVar{{
						Name: "MAYBE_KEY",
						ValueFrom: &corev1.EnvVarSource{
							SecretKeyRef: &corev1.SecretKeySelector{
								LocalObjectReference: corev1.LocalObjectReference{Name: "optional-secret"},
								Key:                  "key",
								Optional:             boolPtr(true),
							},
						},
					}},
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
		if f.CheckID == "SEC-002" {
			t.Error("should not report missing optional secret")
		}
	}
}
