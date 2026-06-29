package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RamazanKara/kube-shield/internal/config"
	"github.com/RamazanKara/kube-shield/internal/k8s"
	"github.com/RamazanKara/kube-shield/internal/scanner/engine"
	"github.com/spf13/cobra"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

type scanCommandScanner struct {
	findings []engine.Finding
}

func (s scanCommandScanner) Name() string              { return "workload" }
func (s scanCommandScanner) Category() engine.Category { return engine.CategoryWorkload }
func (s scanCommandScanner) Description() string       { return "scan command test scanner" }
func (s scanCommandScanner) Scan(ctx context.Context, client kubernetes.Interface, namespace string) (*engine.ScanResult, error) {
	return &engine.ScanResult{Scanner: s.Name(), Findings: s.findings}, nil
}

func TestRunScanAppliesSuppressionsBeforeExitCode(t *testing.T) {
	finding := scanCommandFinding()
	suppressions := filepath.Join(t.TempDir(), "suppressions.yaml")
	data := []byte(`suppressions:
  - id: accepted-risk
    checkId: WL-010
    resource:
      kind: Pod
      name: app
      namespace: default
    reason: accepted until migration completes
    expires: 2099-01-01
`)
	if err := os.WriteFile(suppressions, data, 0o600); err != nil {
		t.Fatalf("write suppressions: %v", err)
	}
	cfg := scanCommandConfig("json")
	cfg.ExitCode = true
	cfg.Suppressions = suppressions
	restore := installRunScanRuntime(t, cfg, []engine.Finding{finding})
	defer restore()

	stdout, _, err := captureStdoutStderr(t, func() error {
		return runScan(&cobra.Command{}, nil)
	})
	if err != nil {
		t.Fatalf("runScan returned error: %v", err)
	}
	if !strings.Contains(stdout, `"suppressedFindings"`) || !strings.Contains(stdout, `"suppressedTotal": 1`) {
		t.Fatalf("expected suppressed finding JSON, got: %s", stdout)
	}
}

func TestRunScanExitCodeReturnsErrorForActiveFindings(t *testing.T) {
	cfg := scanCommandConfig("table")
	cfg.ExitCode = true
	restore := installRunScanRuntime(t, cfg, []engine.Finding{scanCommandFinding()})
	defer restore()

	stdout, _, err := captureStdoutStderr(t, func() error {
		return runScan(&cobra.Command{}, nil)
	})
	if err == nil || !strings.Contains(err.Error(), "findings detected") {
		t.Fatalf("expected findings detected error, got %v", err)
	}
	if !strings.Contains(stdout, "WL-010") {
		t.Fatalf("expected table output before exit error, got: %s", stdout)
	}
}

func TestRunScanWritesSARIF(t *testing.T) {
	cfg := scanCommandConfig("sarif")
	restore := installRunScanRuntime(t, cfg, []engine.Finding{scanCommandFinding()})
	defer restore()

	stdout, _, err := captureStdoutStderr(t, func() error {
		return runScan(&cobra.Command{}, nil)
	})
	if err != nil {
		t.Fatalf("runScan returned error: %v", err)
	}
	if !strings.Contains(stdout, `"version": "2.1.0"`) || !strings.Contains(stdout, `"ruleId": "WL-010"`) {
		t.Fatalf("expected SARIF output, got: %s", stdout)
	}
}

func scanCommandFinding() engine.Finding {
	return engine.Finding{
		ID:          "WL-010-default/Pod/app/container/web",
		CheckID:     "WL-010",
		Title:       "Privileged container: web",
		Description: "Container runs in privileged mode.",
		Severity:    engine.SeverityCritical,
		Category:    engine.CategoryWorkload,
		Resource:    engine.Resource{Kind: "Pod", Name: "app", Namespace: "default"},
		Remediation: "Remove privileged mode.",
	}
}

func scanCommandConfig(output string) *config.Config {
	return &config.Config{
		Output:   output,
		Severity: "low",
		Timeout:  time.Minute,
		Scanners: []string{"workload"},
	}
}

func installRunScanRuntime(t *testing.T, cfg *config.Config, findings []engine.Finding) func() {
	t.Helper()
	registry := engine.NewRegistry()
	registry.Register(scanCommandScanner{findings: findings})
	old := prepareScanRuntimeFunc
	prepareScanRuntimeFunc = func(cmd *cobra.Command, applyOverrides func(changedFlags, *config.Config), validate func(*config.Config) error) (*scanRuntime, error) {
		return &scanRuntime{
			cfg: cfg,
			k8sClient: &k8s.Client{
				Clientset: fake.NewSimpleClientset(),
				Context:   "test-context",
				ServerURL: "https://127.0.0.1:6443",
			},
			engine: engine.NewEngine(registry, 1),
		}, nil
	}
	return func() {
		prepareScanRuntimeFunc = old
	}
}

func captureStdoutStderr(t *testing.T, fn func() error) (string, string, error) {
	t.Helper()
	oldStdout := os.Stdout
	oldStderr := os.Stderr
	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdout pipe: %v", err)
	}
	stderrReader, stderrWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stderr pipe: %v", err)
	}
	os.Stdout = stdoutWriter
	os.Stderr = stderrWriter

	runErr := fn()

	_ = stdoutWriter.Close()
	_ = stderrWriter.Close()
	os.Stdout = oldStdout
	os.Stderr = oldStderr

	stdout, err := io.ReadAll(stdoutReader)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	stderr, err := io.ReadAll(stderrReader)
	if err != nil {
		t.Fatalf("read stderr: %v", err)
	}
	return string(stdout), string(stderr), runErr
}
