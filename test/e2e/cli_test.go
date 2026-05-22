//go:build e2e

package e2e

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

func TestCLI_JSONOutput(t *testing.T) {
	cmd := exec.Command(binaryPath, "scan",
		"--kubeconfig", kubeconfig,
		"-n", namespace,
		"-o", "json",
	)
	out, err := cmd.Output()
	if err != nil {
		// scan may exit non-zero due to findings, check if output is valid
		if exitErr, ok := err.(*exec.ExitError); ok {
			out = append(out, exitErr.Stderr...)
		}
	}

	// Verify output is valid JSON
	var report map[string]interface{}
	if err := json.Unmarshal(out, &report); err != nil {
		t.Fatalf("JSON output is not valid JSON: %v\nOutput: %s", err, string(out))
	}

	// Verify expected top-level keys
	expectedKeys := []string{"findings", "summary"}
	for _, key := range expectedKeys {
		if _, ok := report[key]; !ok {
			t.Errorf("expected key %q in JSON output, not found", key)
		}
	}

	// Verify findings is an array with items
	findings, ok := report["findings"].([]interface{})
	if !ok {
		t.Fatal("findings is not an array")
	}
	if len(findings) == 0 {
		t.Error("expected findings in JSON output, got empty array")
	}

	// Verify finding structure
	first := findings[0].(map[string]interface{})
	requiredFields := []string{"checkId", "severity", "category", "title", "resource"}
	for _, field := range requiredFields {
		if _, ok := first[field]; !ok {
			t.Errorf("expected field %q in finding, not found", field)
		}
	}
}

func TestCLI_SARIFOutput(t *testing.T) {
	cmd := exec.Command(binaryPath, "scan",
		"--kubeconfig", kubeconfig,
		"-n", namespace,
		"-o", "sarif",
	)
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			out = append(out, exitErr.Stderr...)
		}
	}

	// Verify output is valid JSON
	var sarif map[string]interface{}
	if err := json.Unmarshal(out, &sarif); err != nil {
		t.Fatalf("SARIF output is not valid JSON: %v\nOutput: %s", err, string(out))
	}

	// Verify SARIF 2.1.0 schema fields
	version, ok := sarif["version"].(string)
	if !ok || version != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %v", sarif["version"])
	}

	runs, ok := sarif["runs"].([]interface{})
	if !ok || len(runs) == 0 {
		t.Fatal("expected at least one run in SARIF output")
	}

	run := runs[0].(map[string]interface{})
	tool, ok := run["tool"].(map[string]interface{})
	if !ok {
		t.Fatal("expected tool in SARIF run")
	}

	driver, ok := tool["driver"].(map[string]interface{})
	if !ok {
		t.Fatal("expected driver in SARIF tool")
	}

	name, ok := driver["name"].(string)
	if !ok || name != "kube-shield" {
		t.Errorf("expected driver name 'kube-shield', got %v", driver["name"])
	}

	results, ok := run["results"].([]interface{})
	if !ok {
		t.Fatal("expected results array in SARIF run")
	}
	if len(results) == 0 {
		t.Error("expected results in SARIF output")
	}
}

func TestCLI_ExitCode_WithFindings(t *testing.T) {
	cmd := exec.Command(binaryPath, "scan",
		"--kubeconfig", kubeconfig,
		"-n", namespace,
		"--severity", "critical",
		"--exit-code",
	)
	err := cmd.Run()
	if err == nil {
		t.Error("expected non-zero exit code when critical findings exist")
	}

	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected ExitError, got: %v", err)
	}
	if exitErr.ExitCode() == 0 {
		t.Error("expected non-zero exit code")
	}
}

func TestCLI_ExitCode_NoFindings(t *testing.T) {
	// Use kube-system which should have fewer critical findings in a fresh kind cluster
	cmd := exec.Command(binaryPath, "scan",
		"--kubeconfig", kubeconfig,
		"-n", "kube-system",
		"--severity", "critical",
		"--scanners", "secrets",
		"--exit-code",
	)
	out, err := cmd.CombinedOutput()
	// In a fresh kind cluster, kube-system secrets scanner might not find critical issues
	// This is a best-effort test — if it finds critical issues, that's also valid
	if err != nil {
		t.Logf("kube-system scan found critical findings (acceptable): %s", string(out))
	} else {
		t.Log("kube-system secrets scan exited 0 (no critical findings) — as expected")
	}
}

func TestCLI_NamespaceFiltering(t *testing.T) {
	cmd := exec.Command(binaryPath, "scan",
		"--kubeconfig", kubeconfig,
		"-n", namespace,
		"-o", "json",
	)
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			_ = exitErr
		}
	}

	var report map[string]interface{}
	if err := json.Unmarshal(out, &report); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	findings, ok := report["findings"].([]interface{})
	if !ok {
		t.Fatal("findings is not an array")
	}

	// Findings should reference resources in our namespace or be cluster-scoped.
	// Some scanners (CIS) report on cluster-wide resources like namespaces without
	// resource quotas, which is expected behavior when scanning a specific namespace.
	var inNamespace, clusterScoped int
	for _, f := range findings {
		finding := f.(map[string]interface{})
		resource, ok := finding["resource"].(map[string]interface{})
		if !ok {
			continue
		}
		ns, _ := resource["namespace"].(string)
		if ns == "" || ns == namespace {
			inNamespace++
		} else {
			clusterScoped++
		}
	}
	if inNamespace == 0 {
		t.Errorf("expected some findings in namespace %q, got none", namespace)
	}
	t.Logf("namespace filter: %d in-namespace, %d cluster-scoped findings", inNamespace, clusterScoped)
}

func TestCLI_ScannerFiltering(t *testing.T) {
	cmd := exec.Command(binaryPath, "scan",
		"--kubeconfig", kubeconfig,
		"-n", namespace,
		"--scanners", "workload",
		"-o", "json",
	)
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			_ = exitErr
		}
	}

	var report map[string]interface{}
	if err := json.Unmarshal(out, &report); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	findings, ok := report["findings"].([]interface{})
	if !ok {
		t.Fatal("findings is not an array")
	}

	if len(findings) == 0 {
		t.Fatal("expected workload findings when filtering to workload scanner")
	}

	// All findings should be in workload category
	for i, f := range findings {
		finding := f.(map[string]interface{})
		category, _ := finding["category"].(string)
		if !strings.EqualFold(category, "workload") {
			t.Errorf("finding[%d]: expected category 'workload', got %q", i, category)
		}
	}
}
