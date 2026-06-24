package cmd

import (
	"fmt"
	"sort"
	"strings"

	"github.com/RamazanKara/kube-shield/pkg/config"
	"github.com/RamazanKara/kube-shield/pkg/scanner"
	"github.com/RamazanKara/kube-shield/pkg/scanner/engine"
)

var (
	validOutputs = map[string]struct{}{
		"table": {},
		"json":  {},
		"sarif": {},
	}

	validAIProviders = map[string]struct{}{
		"":       {},
		"openai": {},
		"ollama": {},
	}
)

func applyScanFlagOverrides(cmdFlags changedFlags, cfg *config.Config) {
	if cmdFlags.Changed("scanners") {
		cfg.Scanners = normalizeList(scanners)
	}
	if cmdFlags.Changed("severity") {
		cfg.Severity = severity
	}
	if cmdFlags.Changed("timeout") {
		cfg.Timeout = timeout
	}
	if cmdFlags.Changed("exit-code") {
		cfg.ExitCode = exitCode
	}
	if cmdFlags.Changed("category") {
		cfg.Categories = normalizeList(categories)
	}
}

func applyDashboardFlagOverrides(cmdFlags changedFlags, cfg *config.Config) {
	if cmdFlags.Changed("scanners") {
		cfg.Scanners = normalizeList(dashboardScanners)
	}
}

func validateScanConfig(cfg *config.Config) error {
	normalizeConfig(cfg)

	if _, ok := validOutputs[cfg.Output]; !ok {
		return fmt.Errorf("invalid output format %q: supported values are table, json, sarif", cfg.Output)
	}
	if _, ok := engine.ParseSeverity(cfg.Severity); !ok {
		return fmt.Errorf("invalid severity %q: supported values are critical, high, medium, low, info", cfg.Severity)
	}
	if err := validateValues("scanner", cfg.Scanners, scanner.NameSet()); err != nil {
		return err
	}
	if err := validateValues("category", cfg.Categories, scanner.CategorySet()); err != nil {
		return err
	}
	if _, ok := validAIProviders[cfg.AI.Provider]; !ok {
		return fmt.Errorf("invalid AI provider %q: supported values are openai, ollama", cfg.AI.Provider)
	}
	if cfg.Timeout <= 0 {
		return fmt.Errorf("timeout must be greater than zero")
	}
	return nil
}

func validateDashboardConfig(cfg *config.Config) error {
	normalizeConfig(cfg)

	if err := validateValues("scanner", cfg.Scanners, scanner.NameSet()); err != nil {
		return err
	}
	if _, ok := validAIProviders[cfg.AI.Provider]; !ok {
		return fmt.Errorf("invalid AI provider %q: supported values are openai, ollama", cfg.AI.Provider)
	}
	if cfg.Timeout <= 0 {
		return fmt.Errorf("timeout must be greater than zero")
	}
	return nil
}

func validateValues(name string, values []string, valid map[string]struct{}) error {
	for _, value := range values {
		if _, ok := valid[value]; !ok {
			return fmt.Errorf("invalid %s %q: supported values are %s", name, value, strings.Join(sortedKeys(valid), ", "))
		}
	}
	return nil
}

func sortedKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for value := range values {
		keys = append(keys, value)
	}
	sort.Strings(keys)
	return keys
}

func normalizeConfig(cfg *config.Config) {
	cfg.Output = strings.ToLower(strings.TrimSpace(cfg.Output))
	cfg.Severity = strings.ToLower(strings.TrimSpace(cfg.Severity))
	cfg.Scanners = normalizeList(cfg.Scanners)
	cfg.Categories = normalizeList(cfg.Categories)
	cfg.AI.Provider = strings.ToLower(strings.TrimSpace(cfg.AI.Provider))
}

func normalizeList(values []string) []string {
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			part = strings.ToLower(strings.TrimSpace(part))
			if part != "" {
				normalized = append(normalized, part)
			}
		}
	}
	return normalized
}

type changedFlags interface {
	Changed(name string) bool
}
