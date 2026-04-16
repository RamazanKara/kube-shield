package k8s

import (
	"os"
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

func TestNewMultiClient(t *testing.T) {
	dir := t.TempDir()
	kubeconfig := writeTestKubeconfig(t, dir)

	mc, err := NewMultiClient(kubeconfig, []string{"test-context", "other-context"})
	if err != nil {
		t.Fatalf("NewMultiClient error: %v", err)
	}

	c, ok := mc.Get("test-context")
	if !ok || c == nil {
		t.Error("expected test-context client")
	}

	c, ok = mc.Get("other-context")
	if !ok || c == nil {
		t.Error("expected other-context client")
	}

	_, ok = mc.Get("nonexistent")
	if ok {
		t.Error("expected false for nonexistent context")
	}

	all := mc.All()
	if len(all) != 2 {
		t.Errorf("expected 2 clients, got %d", len(all))
	}
}

func TestNewMultiClient_InvalidContext(t *testing.T) {
	dir := t.TempDir()
	kubeconfig := writeTestKubeconfig(t, dir)

	_, err := NewMultiClient(kubeconfig, []string{"nonexistent-context"})
	if err == nil {
		t.Error("expected error for invalid context")
	}
}

func TestListContexts(t *testing.T) {
	dir := t.TempDir()
	kubeconfig := writeTestKubeconfig(t, dir)

	// ListContexts uses env var or default path; we set env
	old := os.Getenv("KUBECONFIG")
	os.Setenv("KUBECONFIG", kubeconfig)
	defer os.Setenv("KUBECONFIG", old)

	contexts, err := ListContexts("")
	if err != nil {
		t.Fatalf("ListContexts error: %v", err)
	}
	if len(contexts) != 2 {
		t.Errorf("expected 2 contexts, got %d", len(contexts))
	}

	found := map[string]bool{}
	for _, c := range contexts {
		found[c] = true
	}
	if !found["test-context"] || !found["other-context"] {
		t.Errorf("expected test-context and other-context, got %v", contexts)
	}
}

func TestListContexts_ExplicitPath(t *testing.T) {
	dir := t.TempDir()
	kubeconfig := writeTestKubeconfig(t, dir)

	contexts, err := ListContexts(kubeconfig)
	if err != nil {
		t.Fatalf("ListContexts error: %v", err)
	}
	if len(contexts) != 2 {
		t.Errorf("expected 2 contexts, got %d", len(contexts))
	}
}
