package config

import (
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Output != "table" {
		t.Errorf("expected output 'table', got %q", cfg.Output)
	}
	if cfg.Severity != "low" {
		t.Errorf("expected severity 'low', got %q", cfg.Severity)
	}
	if cfg.Timeout != 5*time.Minute {
		t.Errorf("expected timeout 5m, got %v", cfg.Timeout)
	}
	if len(cfg.Scanners) != 5 {
		t.Errorf("expected 5 default scanners, got %d", len(cfg.Scanners))
	}
	if cfg.AI.Provider != "" {
		t.Errorf("expected empty AI provider, got %q", cfg.AI.Provider)
	}
}

func TestLoad(t *testing.T) {
	viper.Reset()
	viper.Set("kubeconfig", "/tmp/test-kubeconfig")
	viper.Set("context", "test-ctx")
	viper.Set("namespace", "test-ns")
	viper.Set("output", "json")
	viper.Set("verbose", true)
	viper.Set("severity", "high")
	viper.Set("ai.provider", "openai")
	viper.Set("ai.model", "gpt-4o-mini")
	viper.Set("ai.apikey", "sk-test")
	viper.Set("ai.endpoint", "https://api.example.com")
	viper.Set("scanners", []string{"workload", "rbac"})
	viper.Set("timeout", 10*time.Minute)
	viper.Set("exit-code", true)
	viper.Set("read-secret-data", true)
	viper.Set("suppressions", "suppressions.yaml")
	viper.Set("category", []string{"workload"})
	defer viper.Reset()

	cfg := Load()

	if cfg.Kubeconfig != "/tmp/test-kubeconfig" {
		t.Errorf("expected kubeconfig '/tmp/test-kubeconfig', got %q", cfg.Kubeconfig)
	}
	if cfg.Context != "test-ctx" {
		t.Errorf("expected context 'test-ctx', got %q", cfg.Context)
	}
	if cfg.Namespace != "test-ns" {
		t.Errorf("expected namespace 'test-ns', got %q", cfg.Namespace)
	}
	if cfg.Output != "json" {
		t.Errorf("expected output 'json', got %q", cfg.Output)
	}
	if !cfg.Verbose {
		t.Error("expected verbose true")
	}
	if cfg.Severity != "high" {
		t.Errorf("expected severity 'high', got %q", cfg.Severity)
	}
	if cfg.AI.Provider != "openai" {
		t.Errorf("expected AI provider 'openai', got %q", cfg.AI.Provider)
	}
	if cfg.AI.Model != "gpt-4o-mini" {
		t.Errorf("expected AI model 'gpt-4o-mini', got %q", cfg.AI.Model)
	}
	if cfg.AI.APIKey != "sk-test" {
		t.Errorf("expected AI API key 'sk-test', got %q", cfg.AI.APIKey)
	}
	if cfg.AI.Endpoint != "https://api.example.com" {
		t.Errorf("expected AI endpoint 'https://api.example.com', got %q", cfg.AI.Endpoint)
	}
	if len(cfg.Scanners) != 2 || cfg.Scanners[0] != "workload" || cfg.Scanners[1] != "rbac" {
		t.Errorf("expected scanners [workload rbac], got %v", cfg.Scanners)
	}
	if cfg.Timeout != 10*time.Minute {
		t.Errorf("expected timeout 10m, got %v", cfg.Timeout)
	}
	if !cfg.ExitCode {
		t.Error("expected exit-code true")
	}
	if !cfg.ReadSecretData {
		t.Error("expected read-secret-data true")
	}
	if cfg.Suppressions != "suppressions.yaml" {
		t.Errorf("expected suppressions path, got %q", cfg.Suppressions)
	}
	if len(cfg.Categories) != 1 || cfg.Categories[0] != "workload" {
		t.Errorf("expected categories [workload], got %v", cfg.Categories)
	}
}

func TestLoadNormalizesCommaSeparatedLists(t *testing.T) {
	viper.Reset()
	viper.Set("scanners", []string{"workload,rbac", "secrets"})
	viper.Set("categories", []string{"cis,netpol"})
	defer viper.Reset()

	cfg := Load()

	if len(cfg.Scanners) != 3 || cfg.Scanners[0] != "workload" || cfg.Scanners[1] != "rbac" || cfg.Scanners[2] != "secrets" {
		t.Errorf("expected split scanners, got %v", cfg.Scanners)
	}
	if len(cfg.Categories) != 2 || cfg.Categories[0] != "cis" || cfg.Categories[1] != "netpol" {
		t.Errorf("expected split categories, got %v", cfg.Categories)
	}
}

func TestLoadEnvironmentVariablesWithNestedKeys(t *testing.T) {
	viper.Reset()
	t.Setenv("KUBE_SHIELD_SCANNERS", "rbac,secrets")
	t.Setenv("KUBE_SHIELD_AI_APIKEY", "sk-env")
	viper.SetEnvPrefix("KUBE_SHIELD")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	viper.AutomaticEnv()
	defer viper.Reset()

	cfg := Load()

	if len(cfg.Scanners) != 2 || cfg.Scanners[0] != "rbac" || cfg.Scanners[1] != "secrets" {
		t.Fatalf("expected env scanners to split, got %v", cfg.Scanners)
	}
	if cfg.AI.APIKey != "sk-env" {
		t.Fatalf("expected AI API key from env, got %q", cfg.AI.APIKey)
	}
}

func TestLoadDefaults(t *testing.T) {
	viper.Reset()
	defer viper.Reset()

	cfg := Load()

	// Should get default values when viper has nothing
	if cfg.Output != "table" {
		t.Errorf("expected default output 'table', got %q", cfg.Output)
	}
	if cfg.Severity != "low" {
		t.Errorf("expected default severity 'low', got %q", cfg.Severity)
	}
	if len(cfg.Scanners) != 5 {
		t.Errorf("expected 5 default scanners, got %d", len(cfg.Scanners))
	}
	if cfg.Timeout != 5*time.Minute {
		t.Errorf("expected default timeout 5m, got %v", cfg.Timeout)
	}
}
