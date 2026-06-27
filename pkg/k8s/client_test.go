package k8s

import (
	"path/filepath"
	"testing"

	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

func writeTestKubeconfig(t *testing.T, dir string) string {
	t.Helper()
	cfg := clientcmdapi.NewConfig()
	cfg.Clusters["test-cluster"] = &clientcmdapi.Cluster{
		Server:                "https://127.0.0.1:6443",
		InsecureSkipTLSVerify: true,
	}
	cfg.AuthInfos["test-user"] = &clientcmdapi.AuthInfo{
		Token: "test-token",
	}
	cfg.Contexts["test-context"] = &clientcmdapi.Context{
		Cluster:  "test-cluster",
		AuthInfo: "test-user",
	}
	cfg.Contexts["other-context"] = &clientcmdapi.Context{
		Cluster:  "test-cluster",
		AuthInfo: "test-user",
	}
	cfg.CurrentContext = "test-context"

	path := filepath.Join(dir, "config")
	if err := clientcmd.WriteToFile(*cfg, path); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestNewClient(t *testing.T) {
	dir := t.TempDir()
	kubeconfig := writeTestKubeconfig(t, dir)

	client, err := NewClient(kubeconfig, "test-context")
	if err != nil {
		t.Fatalf("NewClient error: %v", err)
	}
	if client.Clientset == nil {
		t.Error("expected non-nil Clientset")
	}
	if client.MetadataClient == nil {
		t.Error("expected non-nil MetadataClient")
	}
	if client.Context != "test-context" {
		t.Errorf("expected context 'test-context', got %q", client.Context)
	}
	if client.ServerURL != "https://127.0.0.1:6443" {
		t.Errorf("expected server URL, got %q", client.ServerURL)
	}
}

func TestNewClient_DefaultContext(t *testing.T) {
	dir := t.TempDir()
	kubeconfig := writeTestKubeconfig(t, dir)

	client, err := NewClient(kubeconfig, "")
	if err != nil {
		t.Fatalf("NewClient error: %v", err)
	}
	if client.Context != "test-context" {
		t.Errorf("expected default context 'test-context', got %q", client.Context)
	}
}

func TestNewClient_InvalidPath(t *testing.T) {
	_, err := NewClient("/nonexistent/path/kubeconfig", "")
	if err == nil {
		t.Error("expected error for invalid kubeconfig path")
	}
}
