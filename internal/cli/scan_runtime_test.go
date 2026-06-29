package cli

import (
	"context"
	"testing"

	"github.com/RamazanKara/kube-shield/internal/config"
	"github.com/RamazanKara/kube-shield/internal/k8s"
	"github.com/RamazanKara/kube-shield/internal/scanner/engine"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

type runtimeScanner struct {
	name     string
	category engine.Category
}

func (s runtimeScanner) Name() string              { return s.name }
func (s runtimeScanner) Category() engine.Category { return s.category }
func (s runtimeScanner) Description() string       { return "runtime test scanner" }
func (s runtimeScanner) Scan(ctx context.Context, client kubernetes.Interface, namespace string) (*engine.ScanResult, error) {
	return &engine.ScanResult{
		Scanner: s.name,
		Findings: []engine.Finding{{
			ID:       s.name + "-finding",
			CheckID:  s.name + "-check",
			Severity: engine.SeverityHigh,
			Category: s.category,
		}},
	}, nil
}

func TestScanRuntimeRunAll(t *testing.T) {
	runtime := testScanRuntime(nil)

	report, err := runtime.run(context.Background())
	if err != nil {
		t.Fatalf("run returned error: %v", err)
	}
	if report.Summary.Total != 2 {
		t.Fatalf("expected both scanners to run, got %d findings", report.Summary.Total)
	}
}

func TestScanRuntimeRunSelectedScanners(t *testing.T) {
	runtime := testScanRuntime([]string{"rbac"})

	report, err := runtime.run(context.Background())
	if err != nil {
		t.Fatalf("run returned error: %v", err)
	}
	if report.Summary.Total != 1 {
		t.Fatalf("expected one selected scanner finding, got %d", report.Summary.Total)
	}
	if report.Findings[0].Category != engine.CategoryRBAC {
		t.Fatalf("expected RBAC finding, got %s", report.Findings[0].Category)
	}
}

func testScanRuntime(scanners []string) *scanRuntime {
	registry := engine.NewRegistry()
	registry.Register(runtimeScanner{name: "workload", category: engine.CategoryWorkload})
	registry.Register(runtimeScanner{name: "rbac", category: engine.CategoryRBAC})
	return &scanRuntime{
		cfg: &config.Config{
			Scanners: scanners,
		},
		k8sClient: &k8s.Client{Clientset: fake.NewSimpleClientset()},
		engine:    engine.NewEngine(registry, 2),
	}
}
