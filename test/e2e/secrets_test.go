//go:build e2e

package e2e

import (
	"context"
	"testing"
	"time"

	"github.com/RamazanKara/kube-shield/internal/k8s"
	"github.com/RamazanKara/kube-shield/internal/scanner/engine"
	"github.com/RamazanKara/kube-shield/internal/scanner/secrets"
)

func TestSecretsScanner(t *testing.T) {
	client, err := k8s.NewClient(kubeconfig, "")
	if err != nil {
		t.Fatalf("failed to create k8s client: %v", err)
	}

	scanner := secrets.New()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := scanner.ScanWithContext(ctx, engine.ScanContext{
		Client:         client.Clientset,
		MetadataClient: client.MetadataClient,
		Namespace:      namespace,
		Options: engine.ScannerOptions{
			ReadSecretData: true,
		},
	})
	if err != nil {
		t.Fatalf("secrets scan failed: %v", err)
	}

	if len(result.Findings) == 0 {
		t.Fatal("expected secrets findings from vulnerable fixtures, got none")
	}

	expectedChecks := map[string]bool{
		"SEC-001": false, // secret exposed as env var
		"SEC-003": false, // entire secret via envFrom
		"SEC-004": false, // permissive file mode
		"SEC-005": false, // mounted at sensitive path
		"SEC-010": false, // empty secret
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

	t.Logf("secrets scanner found %d findings", len(result.Findings))
}
