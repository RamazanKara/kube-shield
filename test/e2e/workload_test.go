//go:build e2e

package e2e

import (
	"context"
	"testing"
	"time"

	"github.com/RamazanKara/kube-shield/pkg/k8s"
	"github.com/RamazanKara/kube-shield/pkg/scanner/engine"
	"github.com/RamazanKara/kube-shield/pkg/scanner/workload"
)

func TestWorkloadScanner(t *testing.T) {
	client, err := k8s.NewClient(kubeconfig, "")
	if err != nil {
		t.Fatalf("failed to create k8s client: %v", err)
	}

	scanner := workload.New()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := scanner.Scan(ctx, client.Clientset, namespace)
	if err != nil {
		t.Fatalf("workload scan failed: %v", err)
	}

	if len(result.Findings) == 0 {
		t.Fatal("expected workload findings from vulnerable fixtures, got none")
	}

	// Verify expected check IDs are present
	expectedChecks := map[string]bool{
		"WL-001": false, // hostPID
		"WL-002": false, // hostIPC
		"WL-003": false, // hostNetwork
		"WL-010": false, // privileged
		"WL-011": false, // no security context
		"WL-020": false, // SYS_ADMIN capability
		"WL-030": false, // latest/no tag
		"WL-031": false, // no resource limits
	}

	for _, f := range result.Findings {
		if _, ok := expectedChecks[f.CheckID]; ok {
			expectedChecks[f.CheckID] = true
		}
	}

	for checkID, found := range expectedChecks {
		if !found {
			t.Errorf("expected check %s to be detected, but it was not found", checkID)
		}
	}

	// Verify severity levels
	hasCritical := false
	hasHigh := false
	for _, f := range result.Findings {
		if f.Severity == engine.SeverityCritical {
			hasCritical = true
		}
		if f.Severity == engine.SeverityHigh {
			hasHigh = true
		}
	}
	if !hasCritical {
		t.Error("expected at least one CRITICAL finding")
	}
	if !hasHigh {
		t.Error("expected at least one HIGH finding")
	}

	t.Logf("workload scanner found %d findings", len(result.Findings))
}
