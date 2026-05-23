package cmd

import (
	"strings"
	"testing"
	"time"

	"github.com/RamazanKara/kube-shield/pkg/config"
)

func TestValidateScanConfigNormalizesValidValues(t *testing.T) {
	cfg := &config.Config{
		Output:     "JSON",
		Severity:   "HIGH",
		Scanners:   []string{"workload,RBAC"},
		Categories: []string{"Secrets"},
		Timeout:    time.Minute,
		AI: config.AIConfig{
			Provider: "OpenAI",
		},
	}

	if err := validateScanConfig(cfg); err != nil {
		t.Fatalf("validateScanConfig returned error: %v", err)
	}

	if cfg.Output != "json" || cfg.Severity != "high" || cfg.AI.Provider != "openai" {
		t.Fatalf("config was not normalized: %#v", cfg)
	}
	if got := strings.Join(cfg.Scanners, ","); got != "workload,rbac" {
		t.Fatalf("scanners not normalized: %s", got)
	}
	if got := strings.Join(cfg.Categories, ","); got != "secrets" {
		t.Fatalf("categories not normalized: %s", got)
	}
}

func TestValidateScanConfigRejectsInvalidOutput(t *testing.T) {
	cfg := validScanConfig()
	cfg.Output = "yaml"

	if err := validateScanConfig(cfg); err == nil {
		t.Fatal("expected invalid output error")
	}
}

func TestValidateScanConfigRejectsInvalidSeverity(t *testing.T) {
	cfg := validScanConfig()
	cfg.Severity = "urgent"

	if err := validateScanConfig(cfg); err == nil {
		t.Fatal("expected invalid severity error")
	}
}

func TestValidateScanConfigRejectsInvalidScanner(t *testing.T) {
	cfg := validScanConfig()
	cfg.Scanners = []string{"rbac", "unknown"}

	if err := validateScanConfig(cfg); err == nil {
		t.Fatal("expected invalid scanner error")
	}
}

func TestValidateScanConfigRejectsInvalidCategory(t *testing.T) {
	cfg := validScanConfig()
	cfg.Categories = []string{"rbac", "unknown"}

	if err := validateScanConfig(cfg); err == nil {
		t.Fatal("expected invalid category error")
	}
}

func TestValidateScanConfigRejectsInvalidAIProvider(t *testing.T) {
	cfg := validScanConfig()
	cfg.AI.Provider = "anthropic"

	if err := validateScanConfig(cfg); err == nil {
		t.Fatal("expected invalid AI provider error")
	}
}

func TestApplyScanFlagOverridesOnlyUsesChangedFlags(t *testing.T) {
	cfg := &config.Config{
		Output:   "json",
		Severity: "high",
		Scanners: []string{"workload"},
		Timeout:  2 * time.Minute,
	}

	oldSeverity := severity
	oldScanners := scanners
	t.Cleanup(func() {
		severity = oldSeverity
		scanners = oldScanners
	})

	severity = "critical"
	scanners = []string{"rbac"}

	applyScanFlagOverrides(fakeChangedFlags{"severity": true}, cfg)

	if cfg.Severity != "critical" {
		t.Fatalf("expected changed severity to override config, got %q", cfg.Severity)
	}
	if got := strings.Join(cfg.Scanners, ","); got != "workload" {
		t.Fatalf("unchanged scanners should not override config, got %s", got)
	}
}

func validScanConfig() *config.Config {
	cfg := config.DefaultConfig()
	cfg.Timeout = time.Minute
	return cfg
}

type fakeChangedFlags map[string]bool

func (f fakeChangedFlags) Changed(name string) bool {
	return f[name]
}
