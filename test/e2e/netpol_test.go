//go:build e2e

package e2e

import (
	"context"
	"testing"
	"time"

	"github.com/RamazanKara/kube-shield/pkg/k8s"
	"github.com/RamazanKara/kube-shield/pkg/scanner/netpol"
)

func TestNetpolScanner(t *testing.T) {
	client, err := k8s.NewClient(kubeconfig, "")
	if err != nil {
		t.Fatalf("failed to create k8s client: %v", err)
	}

	scanner := netpol.New()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := scanner.Scan(ctx, client.Clientset, "")
	if err != nil {
		t.Fatalf("netpol scan failed: %v", err)
	}

	if len(result.Findings) == 0 {
		t.Fatal("expected network policy findings from vulnerable fixtures, got none")
	}

	expectedChecks := map[string]bool{
		"NET-001": false, // no network policies (kube-shield-e2e namespace)
		"NET-010": false, // allow-all ingress
		"NET-011": false, // allow-all egress
		"NET-020": false, // wide CIDR range
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

	t.Logf("netpol scanner found %d findings", len(result.Findings))
}

func TestNetpolScanner_NamespaceFilter(t *testing.T) {
	client, err := k8s.NewClient(kubeconfig, "")
	if err != nil {
		t.Fatalf("failed to create k8s client: %v", err)
	}

	scanner := netpol.New()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Scan only the netpol-specific namespace
	result, err := scanner.Scan(ctx, client.Clientset, "kube-shield-e2e-netpol")
	if err != nil {
		t.Fatalf("netpol scan failed: %v", err)
	}

	// Should find allow-all policies but NOT NET-001 (since that namespace has policies)
	hasNET010 := false
	hasNET001 := false
	for _, f := range result.Findings {
		if f.CheckID == "NET-010" {
			hasNET010 = true
		}
		if f.CheckID == "NET-001" && f.Resource.Name == "kube-shield-e2e-netpol" {
			hasNET001 = true
		}
	}

	if !hasNET010 {
		t.Error("expected NET-010 (allow-all ingress) in kube-shield-e2e-netpol namespace")
	}
	if hasNET001 {
		t.Error("did not expect NET-001 for kube-shield-e2e-netpol (it has policies)")
	}
}
