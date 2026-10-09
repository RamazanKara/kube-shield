package k8s

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

func TestKubeconfigLoading(t *testing.T) {
	full := writeTestKubeconfig(t, t.TempDir())
	cfg, err := clientcmd.LoadFromFile(full)
	if err != nil {
		t.Fatal(err)
	}
	cluster := clientcmdapi.NewConfig()
	cluster.Clusters = cfg.Clusters
	clustersPath := filepath.Join(t.TempDir(), "clusters")
	if err := clientcmd.WriteToFile(*cluster, clustersPath); err != nil {
		t.Fatal(err)
	}
	cfg.Clusters = nil
	contextsPath := filepath.Join(t.TempDir(), "contexts")
	if err := clientcmd.WriteToFile(*cfg, contextsPath); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(t.TempDir(), "missing")
	malformed := filepath.Join(t.TempDir(), "invalid")
	if err := os.WriteFile(malformed, []byte("clusters: ["), 0o600); err != nil {
		t.Fatal(err)
	}
	merged := strings.Join([]string{missing, clustersPath, contextsPath}, string(os.PathListSeparator))
	for _, tt := range []struct {
		name, explicit, env, context, wantContext, wantErr string
	}{
		{"environment file", "", full, "", "test-context", ""},
		{"merged environment files", "", merged, "", "test-context", ""},
		{"context override", "", merged, "other-context", "other-context", ""},
		{"explicit file overrides environment", full, malformed, "", "test-context", ""},
		{"explicit missing does not fall back", missing, full, "", "", "failed to load kubeconfig"},
		{"malformed environment", "", malformed, "", "", "failed to load kubeconfig"},
		{"unknown context", full, "", "absent", "", "context"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("KUBECONFIG", tt.env)
			client, err := NewClient(tt.explicit, tt.context)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected %q, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if client.Context != tt.wantContext || client.ServerURL != "https://127.0.0.1:6443" {
				t.Fatalf("unexpected config: context=%q server=%q", client.Context, client.ServerURL)
			}
		})
	}
}
