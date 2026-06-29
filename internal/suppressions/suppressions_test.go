package suppressions

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/RamazanKara/kube-shield/internal/scanner/engine"
)

func TestApplyReportSuppressesByCheckIDAndResource(t *testing.T) {
	finding := engine.EnrichFinding(engine.Finding{
		ID:       "finding-1",
		CheckID:  "WL-010",
		Title:    "Privileged container: app",
		Severity: engine.SeverityCritical,
		Category: engine.CategoryWorkload,
		Resource: engine.Resource{Kind: "Pod", Name: "app", Namespace: "default"},
	})
	report := &engine.Report{
		Findings: []engine.Finding{finding},
		Summary:  engine.SummarizeFindings([]engine.Finding{finding}),
	}

	ApplyReport(report, []Suppression{{
		ID:      "accepted-risk-1",
		CheckID: "WL-010",
		Resource: ResourceMatch{
			Kind:      "Pod",
			Name:      "app",
			Namespace: "default",
		},
		Reason:  "temporary exception for migration",
		Expires: "2099-01-01",
	}})

	if report.Summary.Total != 0 {
		t.Fatalf("expected active findings to be empty, got %d", report.Summary.Total)
	}
	if report.Summary.SuppressedTotal != 1 || len(report.SuppressedFindings) != 1 {
		t.Fatalf("expected one suppressed finding, got summary=%d len=%d", report.Summary.SuppressedTotal, len(report.SuppressedFindings))
	}
	if report.SuppressedFindings[0].Suppression == nil || report.SuppressedFindings[0].Suppression.ID != "accepted-risk-1" {
		t.Fatalf("expected suppression metadata on suppressed finding: %#v", report.SuppressedFindings[0].Suppression)
	}
}

func TestApplyFindingsSuppressesByFingerprint(t *testing.T) {
	finding := engine.EnrichFinding(engine.Finding{
		CheckID:  "RBAC-010",
		Title:    "Secret read access: support",
		Severity: engine.SeverityHigh,
		Category: engine.CategoryRBAC,
		Resource: engine.Resource{Kind: "Role", Name: "support", Namespace: "default"},
	})

	active, suppressed := ApplyFindings([]engine.Finding{finding}, []Suppression{{
		ID:          "fingerprint-1",
		Fingerprint: finding.Fingerprint,
		Reason:      "reviewed controller permission",
		Expires:     "2099-01-01",
	}})

	if len(active) != 0 || len(suppressed) != 1 {
		t.Fatalf("expected fingerprint suppression, active=%d suppressed=%d", len(active), len(suppressed))
	}
}

func TestLoadFileRejectsExpiredSuppression(t *testing.T) {
	path := filepath.Join(t.TempDir(), "suppressions.yaml")
	data := []byte(`suppressions:
  - id: expired
    checkId: WL-010
    reason: old exception
    expires: 2020-01-01
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write test suppressions: %v", err)
	}

	_, err := LoadFile(path, time.Date(2026, 6, 27, 12, 0, 0, 0, time.UTC))
	if err == nil {
		t.Fatal("expected expired suppression to fail closed")
	}
}

func TestLoadFileRejectsMalformedSuppression(t *testing.T) {
	path := filepath.Join(t.TempDir(), "suppressions.yaml")
	data := []byte(`suppressions:
  - id: missing-reason
    checkId: WL-010
    expires: 2099-01-01
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write test suppressions: %v", err)
	}

	_, err := LoadFile(path, time.Date(2026, 6, 27, 12, 0, 0, 0, time.UTC))
	if err == nil {
		t.Fatal("expected malformed suppression to fail closed")
	}
}

func TestLoadFileAcceptsTopLevelList(t *testing.T) {
	path := filepath.Join(t.TempDir(), "suppressions.yaml")
	data := []byte(`- id: active
  fingerprint: ks-abc
  reason: approved exception
  expires: 2099-01-01
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write test suppressions: %v", err)
	}

	suppressions, err := LoadFile(path, time.Date(2026, 6, 27, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("expected active suppression to load: %v", err)
	}
	if len(suppressions) != 1 || suppressions[0].ID != "active" {
		t.Fatalf("unexpected suppressions: %#v", suppressions)
	}
}
