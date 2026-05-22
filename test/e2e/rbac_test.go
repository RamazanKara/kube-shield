//go:build e2e

package e2e

import (
	"context"
	"testing"
	"time"

	"github.com/RamazanKara/kube-shield/pkg/k8s"
	"github.com/RamazanKara/kube-shield/pkg/scanner/rbac"
)

func TestRBACScanner(t *testing.T) {
	client, err := k8s.NewClient(kubeconfig, "")
	if err != nil {
		t.Fatalf("failed to create k8s client: %v", err)
	}

	scanner := rbac.New()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := scanner.Scan(ctx, client.Clientset, "")
	if err != nil {
		t.Fatalf("RBAC scan failed: %v", err)
	}

	if len(result.Findings) == 0 {
		t.Fatal("expected RBAC findings from vulnerable fixtures, got none")
	}

	expectedChecks := map[string]bool{
		"RBAC-001": false, // wildcard permissions
		"RBAC-010": false, // secret read access
		"RBAC-011": false, // secret write access
		"RBAC-020": false, // privilege escalation verbs
		"RBAC-021": false, // pod exec/attach
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

	t.Logf("RBAC scanner found %d findings", len(result.Findings))
}
