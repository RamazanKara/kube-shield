//go:build e2e

package e2e

import (
	"context"
	"testing"
	"time"

	"github.com/RamazanKara/kube-shield/internal/k8s"
	"github.com/RamazanKara/kube-shield/internal/scanner/cis"
)

func TestCISScanner(t *testing.T) {
	client, err := k8s.NewClient(kubeconfig, "")
	if err != nil {
		t.Fatalf("failed to create k8s client: %v", err)
	}

	scanner := cis.New()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := scanner.Scan(ctx, client.Clientset, namespace)
	if err != nil {
		t.Fatalf("CIS scan failed: %v", err)
	}

	if len(result.Findings) == 0 {
		t.Fatal("expected CIS findings from vulnerable fixtures, got none")
	}

	expectedChecks := map[string]bool{
		"CIS-4.1.1": false, // cluster-admin bound to SA
		"CIS-4.1.6": false, // default SA automounts token
		"CIS-4.2.1": false, // privileged container
		"CIS-4.2.6": false, // container may run as root
		"CIS-4.2.9": false, // added capabilities
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

	t.Logf("CIS scanner found %d findings", len(result.Findings))
}

func TestCISScanner_HostNamespaceChecks(t *testing.T) {
	client, err := k8s.NewClient(kubeconfig, "")
	if err != nil {
		t.Fatalf("failed to create k8s client: %v", err)
	}

	scanner := cis.New()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := scanner.Scan(ctx, client.Clientset, namespace)
	if err != nil {
		t.Fatalf("CIS scan failed: %v", err)
	}

	hostChecks := map[string]bool{
		"CIS-4.2.2": false, // hostPID
		"CIS-4.2.3": false, // hostIPC
		"CIS-4.2.4": false, // hostNetwork
	}

	for _, f := range result.Findings {
		if _, ok := hostChecks[f.CheckID]; ok {
			hostChecks[f.CheckID] = true
		}
	}

	for checkID, found := range hostChecks {
		if !found {
			t.Errorf("expected check %s (host namespace) to be detected, but it was not found", checkID)
		}
	}
}
