package engine

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestRulesHaveRequiredCredibilityMetadata(t *testing.T) {
	seen := make(map[string]struct{})
	for _, rule := range Rules() {
		if rule.CheckID == "" {
			t.Fatal("rule has empty check ID")
		}
		if _, ok := seen[rule.CheckID]; ok {
			t.Fatalf("duplicate rule %s", rule.CheckID)
		}
		seen[rule.CheckID] = struct{}{}
		if rule.Scanner == "" || rule.Category == "" || rule.Title == "" {
			t.Fatalf("rule %s missing identity metadata: %#v", rule.CheckID, rule)
		}
		if rule.Confidence == "" || rule.Rationale == "" || rule.Impact == "" || rule.Remediation == "" {
			t.Fatalf("rule %s missing credibility metadata: %#v", rule.CheckID, rule)
		}
		if rule.DataAccess == "" {
			t.Fatalf("rule %s missing data access classification", rule.CheckID)
		}
		if len(rule.References) == 0 {
			t.Fatalf("rule %s must include at least one reference", rule.CheckID)
		}
		if rule.CheckID == "SEC-010" && rule.DefaultEnabled {
			t.Fatal("SEC-010 reads secret data and must not be enabled by default")
		}
	}
}

func TestCISPolicyCatalog(t *testing.T) {
	controls := []string{
		"5.1.1", "5.1.2", "5.1.4", "5.1.5", "5.1.6", "5.1.7", "5.1.11", "5.1.12", "5.1.13",
		"5.2.1", "5.2.2", "5.2.3", "5.2.4", "5.2.5", "5.2.7", "5.2.9", "5.2.10", "5.2.11", "5.2.12",
		"5.3.2", "5.4.1", "5.6.2", "5.6.4",
	}
	rules := RulesByScanner("cis")
	if len(rules) != len(controls) {
		t.Fatalf("CIS catalog has %d rules, want %d", len(rules), len(controls))
	}
	for _, control := range controls {
		rule, ok := RuleByID("CIS-" + control)
		if !ok {
			t.Errorf("missing CIS control %s", control)
			continue
		}
		if len(rule.Standards) != 1 || rule.Standards[0] != (StandardMapping{Name: "CIS Kubernetes Benchmark", Control: control}) {
			t.Errorf("incorrect standard mapping for %s: %v", rule.CheckID, rule.Standards)
		}
	}
	for _, rule := range Rules() {
		if strings.HasPrefix(rule.CheckID, "CIS-4.") {
			t.Errorf("legacy CIS ID remains in catalog: %s", rule.CheckID)
		}
	}
}

func TestScannerEmittedCheckIDsExistInRuleCatalog(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not resolve test file path")
	}
	scannerRoot := filepath.Clean(filepath.Join(filepath.Dir(file), ".."))
	checkIDs := collectProductionCheckIDs(t, scannerRoot)
	if len(checkIDs) == 0 {
		t.Fatal("expected to find emitted check IDs in scanner source")
	}

	for checkID := range checkIDs {
		if _, ok := RuleByID(checkID); !ok {
			t.Fatalf("scanner emits %s but rule catalog has no metadata", checkID)
		}
	}
}

func collectProductionCheckIDs(t *testing.T, root string) map[string]struct{} {
	t.Helper()
	re := regexp.MustCompile(`CheckID:\s+"([^"]+)"`)
	checkIDs := make(map[string]struct{})
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".go" || filepath.Base(path) == "rules.go" || filepath.Base(path) == "rules_test.go" {
			return nil
		}
		if len(path) >= len("_test.go") && path[len(path)-len("_test.go"):] == "_test.go" {
			return nil
		}
		data, err := os.ReadFile(path) // #nosec G304,G122 -- test walks fixed repository scanner source paths.
		if err != nil {
			return err
		}
		for _, match := range re.FindAllSubmatch(data, -1) {
			checkIDs[string(match[1])] = struct{}{}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk scanner source: %v", err)
	}
	return checkIDs
}
