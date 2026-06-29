package scanner_test

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"testing"

	cisscanner "github.com/RamazanKara/kube-shield/internal/scanner/cis"
	"github.com/RamazanKara/kube-shield/internal/scanner/engine"
	netpolscanner "github.com/RamazanKara/kube-shield/internal/scanner/netpol"
	rbacscanner "github.com/RamazanKara/kube-shield/internal/scanner/rbac"
	secretsscanner "github.com/RamazanKara/kube-shield/internal/scanner/secrets"
	workloadscanner "github.com/RamazanKara/kube-shield/internal/scanner/workload"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"
	metadatafake "k8s.io/client-go/metadata/fake"
)

func TestScannerGoldenFindingsAndFingerprints(t *testing.T) {
	privileged := true
	allowPrivilegeEscalation := false
	readOnlyRootFilesystem := true
	runAsNonRoot := true
	runAsUser := int64(1000)
	automountToken := false

	tests := []struct {
		name     string
		run      func(t *testing.T) []engine.Finding
		expected []string
	}{
		{
			name: "workload positive fixture",
			run: func(t *testing.T) []engine.Finding {
				client := fake.NewSimpleClientset(&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{Name: "golden-workload", Namespace: "golden"},
					Spec: corev1.PodSpec{
						ServiceAccountName:           "golden-sa",
						AutomountServiceAccountToken: &automountToken,
						Containers: []corev1.Container{{
							Name:  "app",
							Image: "registry.example.com/app:v1.2.3",
							SecurityContext: &corev1.SecurityContext{
								Privileged:               &privileged,
								RunAsNonRoot:             &runAsNonRoot,
								RunAsUser:                &runAsUser,
								AllowPrivilegeEscalation: &allowPrivilegeEscalation,
								ReadOnlyRootFilesystem:   &readOnlyRootFilesystem,
								Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
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
							LivenessProbe: httpProbe(),
						}},
					},
					Status: corev1.PodStatus{Phase: corev1.PodRunning},
				})
				result, err := workloadscanner.New().Scan(context.Background(), client, "golden")
				if err != nil {
					t.Fatalf("workload scan: %v", err)
				}
				return result.Findings
			},
			expected: []string{"WL-010|golden/Pod/golden-workload|ks-5b45c08c290128df183d"},
		},
		{
			name: "workload negative fixture",
			run: func(t *testing.T) []engine.Finding {
				client := fake.NewSimpleClientset(securePod("secure-workload"))
				result, err := workloadscanner.New().Scan(context.Background(), client, "golden")
				if err != nil {
					t.Fatalf("workload scan: %v", err)
				}
				return result.Findings
			},
			expected: []string{},
		},
		{
			name: "cis positive fixture",
			run: func(t *testing.T) []engine.Finding {
				client := fake.NewSimpleClientset(&rbacv1.ClusterRoleBinding{
					ObjectMeta: metav1.ObjectMeta{Name: "golden-admin"},
					RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "cluster-admin"},
					Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "golden-sa", Namespace: "golden"}},
				})
				result, err := cisscanner.New().Scan(context.Background(), client, "golden")
				if err != nil {
					t.Fatalf("cis scan: %v", err)
				}
				return result.Findings
			},
			expected: []string{"CIS-4.1.1|ClusterRoleBinding/golden-admin|ks-e241fbea9c9332b2f3c6"},
		},
		{
			name: "cis negative fixture",
			run: func(t *testing.T) []engine.Finding {
				result, err := cisscanner.New().Scan(context.Background(), fake.NewSimpleClientset(), "golden")
				if err != nil {
					t.Fatalf("cis scan: %v", err)
				}
				return result.Findings
			},
			expected: []string{},
		},
		{
			name: "rbac positive fixture",
			run: func(t *testing.T) []engine.Finding {
				client := fake.NewSimpleClientset(&rbacv1.ClusterRole{
					ObjectMeta: metav1.ObjectMeta{Name: "golden-wildcard"},
					Rules: []rbacv1.PolicyRule{{
						APIGroups: []string{"*"},
						Resources: []string{"*"},
						Verbs:     []string{"*"},
					}},
				})
				result, err := rbacscanner.New().Scan(context.Background(), client, "")
				if err != nil {
					t.Fatalf("rbac scan: %v", err)
				}
				return result.Findings
			},
			expected: []string{"RBAC-001|ClusterRole/golden-wildcard|ks-a80767a5bc7a4f91d45d"},
		},
		{
			name: "rbac negative fixture",
			run: func(t *testing.T) []engine.Finding {
				result, err := rbacscanner.New().Scan(context.Background(), fake.NewSimpleClientset(), "")
				if err != nil {
					t.Fatalf("rbac scan: %v", err)
				}
				return result.Findings
			},
			expected: []string{},
		},
		{
			name: "netpol positive fixture",
			run: func(t *testing.T) []engine.Finding {
				client := fake.NewSimpleClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "golden"}})
				result, err := netpolscanner.New().Scan(context.Background(), client, "golden")
				if err != nil {
					t.Fatalf("netpol scan: %v", err)
				}
				return result.Findings
			},
			expected: []string{"NET-001|Namespace/golden|ks-04e7293e238021cecb19"},
		},
		{
			name: "netpol negative fixture",
			run: func(t *testing.T) []engine.Finding {
				client := fake.NewSimpleClientset(
					&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "golden"}},
					&networkingv1.NetworkPolicy{
						ObjectMeta: metav1.ObjectMeta{Name: "default-deny", Namespace: "golden"},
						Spec: networkingv1.NetworkPolicySpec{
							PodSelector: metav1.LabelSelector{},
							PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
						},
					},
				)
				result, err := netpolscanner.New().Scan(context.Background(), client, "golden")
				if err != nil {
					t.Fatalf("netpol scan: %v", err)
				}
				return result.Findings
			},
			expected: []string{},
		},
		{
			name: "secrets positive fixture",
			run: func(t *testing.T) []engine.Finding {
				client := fake.NewSimpleClientset(&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{Name: "golden-secrets", Namespace: "golden"},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{
							Name: "app",
							Env: []corev1.EnvVar{{
								Name: "TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{Name: "app-token"},
										Key:                  "token",
									},
								},
							}},
						}},
					},
					Status: corev1.PodStatus{Phase: corev1.PodRunning},
				})
				result, err := secretsscanner.New().ScanWithContext(context.Background(), engine.ScanContext{
					Client:         client,
					MetadataClient: secretMetadataClient(t, "golden", "app-token"),
					Namespace:      "golden",
				})
				if err != nil {
					t.Fatalf("secrets scan: %v", err)
				}
				return result.Findings
			},
			expected: []string{"SEC-001|golden/Pod/golden-secrets|ks-fd515e44dc79bbe45115"},
		},
		{
			name: "secrets negative fixture",
			run: func(t *testing.T) []engine.Finding {
				client := fake.NewSimpleClientset(securePod("secure-secrets"))
				result, err := secretsscanner.New().ScanWithContext(context.Background(), engine.ScanContext{
					Client:         client,
					MetadataClient: secretMetadataClient(t),
					Namespace:      "golden",
				})
				if err != nil {
					t.Fatalf("secrets scan: %v", err)
				}
				return result.Findings
			},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := goldenFindingLines(tt.run(t))
			if !reflect.DeepEqual(got, tt.expected) {
				t.Fatalf("golden findings mismatch\nwant: %#v\n got: %#v", tt.expected, got)
			}
		})
	}
}

func goldenFindingLines(findings []engine.Finding) []string {
	enriched := engine.EnrichFindings(findings)
	lines := make([]string, 0, len(enriched))
	for _, finding := range enriched {
		lines = append(lines, fmt.Sprintf("%s|%s|%s", finding.CheckID, finding.Resource.String(), finding.Fingerprint))
	}
	sort.Strings(lines)
	return lines
}

func securePod(name string) *corev1.Pod {
	allowPrivilegeEscalation := false
	readOnlyRootFilesystem := true
	runAsNonRoot := true
	runAsUser := int64(1000)
	automountToken := false
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "golden"},
		Spec: corev1.PodSpec{
			ServiceAccountName:           "golden-sa",
			AutomountServiceAccountToken: &automountToken,
			Containers: []corev1.Container{{
				Name:  "app",
				Image: "registry.example.com/app:v1.2.3",
				SecurityContext: &corev1.SecurityContext{
					RunAsNonRoot:             &runAsNonRoot,
					RunAsUser:                &runAsUser,
					AllowPrivilegeEscalation: &allowPrivilegeEscalation,
					ReadOnlyRootFilesystem:   &readOnlyRootFilesystem,
					Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
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
				LivenessProbe: httpProbe(),
			}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

func httpProbe() *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{
				Path: "/healthz",
				Port: intstr.FromInt(8080),
			},
		},
	}
}

func secretMetadataClient(t *testing.T, secrets ...string) *metadatafake.FakeMetadataClient {
	t.Helper()
	scheme := runtime.NewScheme()
	scheme.AddKnownTypeWithName(schema.GroupVersionKind{Version: "v1", Kind: "Secret"}, &metav1.PartialObjectMetadata{})
	scheme.AddKnownTypeWithName(schema.GroupVersionKind{Version: "v1", Kind: "SecretList"}, &metav1.PartialObjectMetadataList{})

	objects := make([]runtime.Object, 0, len(secrets))
	for _, name := range secrets {
		objects = append(objects, &metav1.PartialObjectMetadata{
			TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "golden"},
		})
	}
	return metadatafake.NewSimpleMetadataClient(scheme, objects...)
}
