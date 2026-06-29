//go:build e2e

package e2e

import (
	"context"
	"testing"
	"time"

	"github.com/RamazanKara/kube-shield/internal/k8s"
	"github.com/RamazanKara/kube-shield/internal/scanner/cis"
	"github.com/RamazanKara/kube-shield/internal/scanner/engine"
	"github.com/RamazanKara/kube-shield/internal/scanner/netpol"
	"github.com/RamazanKara/kube-shield/internal/scanner/rbac"
	"github.com/RamazanKara/kube-shield/internal/scanner/secrets"
	"github.com/RamazanKara/kube-shield/internal/scanner/workload"
)

func TestFullScan(t *testing.T) {
	client, err := k8s.NewClient(kubeconfig, "")
	if err != nil {
		t.Fatalf("failed to create k8s client: %v", err)
	}

	registry := engine.NewRegistry()
	registry.Register(workload.New())
	registry.Register(cis.New())
	registry.Register(rbac.New())
	registry.Register(netpol.New())
	registry.Register(secrets.New())

	eng := engine.NewEngine(registry, 5)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	report, err := eng.RunAllWithContext(ctx, engine.ScanContext{
		Client:         client.Clientset,
		MetadataClient: client.MetadataClient,
		Namespace:      namespace,
	})
	if err != nil {
		t.Fatalf("full scan failed: %v", err)
	}

	// Verify findings exist from multiple categories
	categoriesFound := make(map[engine.Category]int)
	for _, f := range report.Findings {
		categoriesFound[f.Category]++
	}

	expectedCategories := []engine.Category{
		engine.CategoryWorkload,
		engine.CategoryCIS,
		engine.CategorySecrets,
	}

	for _, cat := range expectedCategories {
		if count, ok := categoriesFound[cat]; !ok || count == 0 {
			t.Errorf("expected findings in category %s, but found none", cat)
		}
	}

	// Verify score is below 100 (vulnerable fixtures should trigger findings)
	if report.Summary.Score >= 100 {
		t.Errorf("expected score < 100 for vulnerable cluster, got %.0f", report.Summary.Score)
	}

	// Verify grade reflects issues
	if report.Summary.Grade == "A" {
		t.Error("expected grade worse than A for vulnerable cluster")
	}

	// Verify total findings is reasonable
	if report.Summary.Total < 10 {
		t.Errorf("expected at least 10 total findings, got %d", report.Summary.Total)
	}

	t.Logf("full scan: %d findings, score=%.0f, grade=%s", report.Summary.Total, report.Summary.Score, report.Summary.Grade)
	for cat, count := range categoriesFound {
		t.Logf("  %s: %d findings", cat, count)
	}
}

func TestFullScan_SeverityFiltering(t *testing.T) {
	client, err := k8s.NewClient(kubeconfig, "")
	if err != nil {
		t.Fatalf("failed to create k8s client: %v", err)
	}

	registry := engine.NewRegistry()
	registry.Register(workload.New())
	registry.Register(cis.New())
	registry.Register(rbac.New())
	registry.Register(netpol.New())
	registry.Register(secrets.New())

	eng := engine.NewEngine(registry, 5)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	report, err := eng.RunAllWithContext(ctx, engine.ScanContext{
		Client:         client.Clientset,
		MetadataClient: client.MetadataClient,
		Namespace:      namespace,
	})
	if err != nil {
		t.Fatalf("full scan failed: %v", err)
	}

	// Filter to critical only
	critical := engine.FilterFindings(report.Findings, engine.SeverityCritical, nil, "")
	if len(critical) == 0 {
		t.Error("expected at least one CRITICAL finding")
	}

	// All filtered findings should be critical
	for _, f := range critical {
		if f.Severity != engine.SeverityCritical {
			t.Errorf("expected only CRITICAL findings after filter, got %s", f.Severity)
		}
	}

	// Filter to high+
	highPlus := engine.FilterFindings(report.Findings, engine.SeverityHigh, nil, "")
	if len(highPlus) <= len(critical) {
		t.Error("expected more findings at HIGH+ than CRITICAL only")
	}

	t.Logf("severity filtering: %d critical, %d high+, %d total", len(critical), len(highPlus), len(report.Findings))
}

func TestFullScan_CategoryFiltering(t *testing.T) {
	client, err := k8s.NewClient(kubeconfig, "")
	if err != nil {
		t.Fatalf("failed to create k8s client: %v", err)
	}

	registry := engine.NewRegistry()
	registry.Register(workload.New())
	registry.Register(cis.New())
	registry.Register(rbac.New())
	registry.Register(netpol.New())
	registry.Register(secrets.New())

	eng := engine.NewEngine(registry, 5)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	report, err := eng.RunAllWithContext(ctx, engine.ScanContext{
		Client:         client.Clientset,
		MetadataClient: client.MetadataClient,
		Namespace:      namespace,
	})
	if err != nil {
		t.Fatalf("full scan failed: %v", err)
	}

	// Filter to workload only
	workloadOnly := engine.FilterFindings(report.Findings, engine.SeverityInfo, []engine.Category{engine.CategoryWorkload}, "")
	for _, f := range workloadOnly {
		if f.Category != engine.CategoryWorkload {
			t.Errorf("expected only workload category after filter, got %s", f.Category)
		}
	}

	// Filter to RBAC + secrets
	multi := engine.FilterFindings(report.Findings, engine.SeverityInfo, []engine.Category{engine.CategoryRBAC, engine.CategorySecrets}, "")
	for _, f := range multi {
		if f.Category != engine.CategoryRBAC && f.Category != engine.CategorySecrets {
			t.Errorf("expected only rbac/secrets categories after filter, got %s", f.Category)
		}
	}
}
