//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

const (
	clusterName = "kube-shield-e2e"
	namespace   = "kube-shield-e2e"
)

var (
	kubeconfig string
	projectDir string
	binaryPath string
)

func TestMain(m *testing.M) {
	// Find project root (two levels up from test/e2e)
	wd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to get working directory: %v\n", err)
		os.Exit(1)
	}
	projectDir = filepath.Join(wd, "..", "..")
	binaryPath = filepath.Join(projectDir, "bin", "kube-shield")

	// Build the binary
	fmt.Println("==> Building kube-shield binary...")
	if err := runCmd(projectDir, "go", "build", "-o", binaryPath, "./cmd/kube-shield"); err != nil {
		fmt.Fprintf(os.Stderr, "failed to build binary: %v\n", err)
		os.Exit(1)
	}

	// Create kind cluster
	fmt.Println("==> Creating kind cluster...")
	kindConfig := filepath.Join(wd, "testdata", "kind-config.yaml")
	kubeconfig = filepath.Join(os.TempDir(), "kube-shield-e2e-kubeconfig")

	if err := runCmd("", "kind", "create", "cluster",
		"--name", clusterName,
		"--config", kindConfig,
		"--kubeconfig", kubeconfig,
		"--wait", "120s",
	); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create kind cluster: %v\n", err)
		os.Exit(1)
	}

	// Deploy fixtures
	fmt.Println("==> Deploying test fixtures...")
	fixtureDir := filepath.Join(wd, "testdata", "fixtures")
	fixtures := []string{
		"workload-vulnerable.yaml",
		"rbac-vulnerable.yaml",
		"netpol-vulnerable.yaml",
		"secrets-vulnerable.yaml",
		"cis-vulnerable.yaml",
	}
	for _, f := range fixtures {
		path := filepath.Join(fixtureDir, f)
		if err := kubectl("apply", "-f", path); err != nil {
			fmt.Fprintf(os.Stderr, "failed to apply fixture %s: %v\n", f, err)
			cleanup()
			os.Exit(1)
		}
	}

	// Wait for pods to be scheduled (not necessarily Running — some may fail due to securityContext)
	fmt.Println("==> Waiting for pods to be scheduled...")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := waitForPods(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "warning: not all pods ready (expected for some test fixtures): %v\n", err)
	}

	// Run tests
	fmt.Println("==> Running e2e tests...")
	code := m.Run()

	// Cleanup
	cleanup()
	os.Exit(code)
}

func cleanup() {
	fmt.Println("==> Cleaning up kind cluster...")
	_ = runCmd("", "kind", "delete", "cluster", "--name", clusterName)
	_ = os.Remove(kubeconfig)
}

func kubectl(args ...string) error {
	allArgs := append([]string{"--kubeconfig", kubeconfig}, args...)
	return runCmd("", "kubectl", allArgs...)
}

func waitForPods(ctx context.Context) error {
	// Wait until at least some pods exist in our test namespace
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		cmd := exec.CommandContext(ctx, "kubectl", "--kubeconfig", kubeconfig,
			"get", "pods", "-n", namespace, "--no-headers")
		out, err := cmd.Output()
		if err == nil && len(out) > 0 {
			return nil
		}
		time.Sleep(2 * time.Second)
	}
}

func runCmd(dir string, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if dir != "" {
		cmd.Dir = dir
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
