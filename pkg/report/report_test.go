package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/RamazanKara/kube-shield/pkg/scanner/engine"
	"github.com/RamazanKara/kube-shield/pkg/version"
)

func sampleReport() *engine.Report {
	return &engine.Report{
		Findings: []engine.Finding{
			{
				ID:          "WL-010-default/test-pod/app",
				CheckID:     "WL-010",
				Title:       "Privileged container: test-pod/app",
				Description: "Container runs in privileged mode.",
				Severity:    engine.SeverityCritical,
				Category:    engine.CategoryWorkload,
				Resource:    engine.Resource{Kind: "Pod", Name: "test-pod", Namespace: "default"},
				Remediation: "Do not run containers in privileged mode.",
			},
			{
				ID:          "RBAC-001-admin-role",
				CheckID:     "RBAC-001",
				Title:       "Wildcard permissions: admin-role",
				Description: "ClusterRole has wildcard resource access.",
				Severity:    engine.SeverityHigh,
				Category:    engine.CategoryRBAC,
				Resource:    engine.Resource{Kind: "ClusterRole", Name: "admin-role"},
				Remediation: "Replace wildcard with specific resources.",
			},
			{
				ID:          "NET-001-production",
				CheckID:     "NET-001",
				Title:       "No network policies in namespace: production",
				Description: "Namespace has no network policies defined.",
				Severity:    engine.SeverityHigh,
				Category:    engine.CategoryNetpol,
				Resource:    engine.Resource{Kind: "Namespace", Name: "production"},
				Remediation: "Create a default-deny NetworkPolicy.",
			},
			{
				ID:          "SEC-001-default/app/web/DB_PASS",
				CheckID:     "SEC-001",
				Title:       "Secret exposed as env var: DB_PASS in web",
				Description: "Secret key exposed as environment variable.",
				Severity:    engine.SeverityMedium,
				Category:    engine.CategorySecrets,
				Resource:    engine.Resource{Kind: "Pod", Name: "app", Namespace: "default"},
				Remediation: "Mount secrets as files.",
			},
			{
				ID:          "CIS-4.5.1-staging",
				CheckID:     "CIS-4.5.1",
				Title:       "No resource quotas: staging",
				Description: "Namespace has no resource quotas.",
				Severity:    engine.SeverityLow,
				Category:    engine.CategoryCIS,
				Resource:    engine.Resource{Kind: "Namespace", Name: "staging"},
				Remediation: "Create a ResourceQuota.",
				CISRef:      "4.5.1",
			},
		},
		Summary: engine.Summary{
			Score: 62,
			Grade: "D",
			Total: 5,
			BySeverity: map[engine.Severity]int{
				engine.SeverityCritical: 1,
				engine.SeverityHigh:     2,
				engine.SeverityMedium:   1,
				engine.SeverityLow:      1,
				engine.SeverityInfo:     0,
			},
			ByCategory: map[engine.Category]int{
				engine.CategoryWorkload: 1,
				engine.CategoryRBAC:     1,
				engine.CategoryNetpol:   1,
				engine.CategorySecrets:  1,
				engine.CategoryCIS:      1,
			},
		},
	}
}

func TestTableWriter(t *testing.T) {
	var buf bytes.Buffer
	report := sampleReport()

	err := TableWriter(&buf, report)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()

	// Check header
	if !strings.Contains(output, "SEVERITY") {
		t.Error("table output should contain SEVERITY header")
	}
	if !strings.Contains(output, "CHECK") {
		t.Error("table output should contain CHECK header")
	}

	// Check findings present
	if !strings.Contains(output, "WL-010") {
		t.Error("table output should contain WL-010 check")
	}
	if !strings.Contains(output, "RBAC-001") {
		t.Error("table output should contain RBAC-001 check")
	}

	// Check summary
	if !strings.Contains(output, "Security Score") {
		t.Error("table output should contain Security Score")
	}
	if !strings.Contains(output, "Total Findings: 5") {
		t.Error("table output should contain total findings count")
	}
}

func TestTableWriter_Empty(t *testing.T) {
	var buf bytes.Buffer
	report := &engine.Report{}

	err := TableWriter(&buf, report)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(buf.String(), "No security findings") {
		t.Error("empty report should show no findings message")
	}
}

func TestJSONWriter(t *testing.T) {
	var buf bytes.Buffer
	report := sampleReport()

	err := JSONWriter(&buf, report)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify it's valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("JSON output is not valid: %v", err)
	}

	// Check for key fields
	findings, ok := parsed["findings"].([]interface{})
	if !ok {
		t.Fatal("JSON should contain findings array")
	}
	if len(findings) != 5 {
		t.Errorf("expected 5 findings, got %d", len(findings))
	}

	summary, ok := parsed["summary"].(map[string]interface{})
	if !ok {
		t.Fatal("JSON should contain summary object")
	}
	if grade, ok := summary["grade"].(string); !ok || grade != "D" {
		t.Errorf("expected grade D, got %v", summary["grade"])
	}
}

func TestSARIFWriter(t *testing.T) {
	var buf bytes.Buffer
	report := sampleReport()

	err := SARIFWriter(&buf, report)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify it's valid JSON
	var sarif map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &sarif); err != nil {
		t.Fatalf("SARIF output is not valid JSON: %v", err)
	}

	// Check SARIF version
	if version, ok := sarif["version"].(string); !ok || version != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %v", sarif["version"])
	}

	// Check runs
	runs, ok := sarif["runs"].([]interface{})
	if !ok || len(runs) != 1 {
		t.Fatal("SARIF should contain exactly 1 run")
	}

	run := runs[0].(map[string]interface{})

	// Check tool
	tool := run["tool"].(map[string]interface{})
	driver := tool["driver"].(map[string]interface{})
	if name, ok := driver["name"].(string); !ok || name != "kube-shield" {
		t.Errorf("expected tool name kube-shield, got %v", driver["name"])
	}
	if got, ok := driver["version"].(string); !ok || got != version.Version {
		t.Errorf("expected tool version %q, got %v", version.Version, driver["version"])
	}

	// Check rules
	rules, ok := driver["rules"].([]interface{})
	if !ok || len(rules) == 0 {
		t.Error("SARIF should contain rules")
	}

	// Check results
	results, ok := run["results"].([]interface{})
	if !ok || len(results) != 5 {
		t.Errorf("expected 5 results, got %d", len(results))
	}

	// Verify first result has expected fields
	result := results[0].(map[string]interface{})
	if _, ok := result["ruleId"].(string); !ok {
		t.Error("result should have ruleId")
	}
	if _, ok := result["level"].(string); !ok {
		t.Error("result should have level")
	}
	if _, ok := result["message"]; !ok {
		t.Error("result should have message")
	}
	if _, ok := result["locations"]; !ok {
		t.Error("result should have locations")
	}
}

func TestSARIFWriter_UsesExistingScannerReference(t *testing.T) {
	var buf bytes.Buffer

	if err := SARIFWriter(&buf, sampleReport()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var sarif map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &sarif); err != nil {
		t.Fatalf("SARIF output is not valid JSON: %v", err)
	}

	runs := sarif["runs"].([]interface{})
	run := runs[0].(map[string]interface{})
	tool := run["tool"].(map[string]interface{})
	driver := tool["driver"].(map[string]interface{})
	rules := driver["rules"].([]interface{})
	rule := rules[0].(map[string]interface{})

	if got := rule["helpUri"]; got != "https://github.com/RamazanKara/kube-shield/blob/main/docs/SCANNERS.md" {
		t.Fatalf("unexpected helpUri: %v", got)
	}
}

func TestSARIFWriter_LevelMapping(t *testing.T) {
	tests := []struct {
		severity engine.Severity
		expected string
	}{
		{engine.SeverityCritical, "error"},
		{engine.SeverityHigh, "error"},
		{engine.SeverityMedium, "warning"},
		{engine.SeverityLow, "note"},
		{engine.SeverityInfo, "note"},
	}

	for _, tt := range tests {
		actual := sarifLevel(tt.severity)
		if actual != tt.expected {
			t.Errorf("sarifLevel(%s) = %s, want %s", tt.severity, actual, tt.expected)
		}
	}
}
