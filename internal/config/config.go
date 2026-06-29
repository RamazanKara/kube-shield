package config

import (
	"strings"
	"time"

	"github.com/RamazanKara/kube-shield/internal/scanner"
	"github.com/spf13/viper"
)

// Config holds all configuration for kube-shield.
type Config struct {
	Kubeconfig     string        `yaml:"kubeconfig" mapstructure:"kubeconfig"`
	Context        string        `yaml:"context" mapstructure:"context"`
	Namespace      string        `yaml:"namespace" mapstructure:"namespace"`
	Output         string        `yaml:"output" mapstructure:"output"`
	Verbose        bool          `yaml:"verbose" mapstructure:"verbose"`
	Scanners       []string      `yaml:"scanners" mapstructure:"scanners"`
	Severity       string        `yaml:"severity" mapstructure:"severity"`
	Timeout        time.Duration `yaml:"timeout" mapstructure:"timeout"`
	ExitCode       bool          `yaml:"exit-code" mapstructure:"exit-code"`
	ReadSecretData bool          `yaml:"read-secret-data" mapstructure:"read-secret-data"`
	Suppressions   string        `yaml:"suppressions" mapstructure:"suppressions"`
	Categories     []string      `yaml:"categories" mapstructure:"categories"`
	AI             AIConfig      `yaml:"ai" mapstructure:"ai"`
}

// AIConfig holds AI provider configuration.
type AIConfig struct {
	Provider string `yaml:"provider" mapstructure:"provider"`
	Model    string `yaml:"model" mapstructure:"model"`
	APIKey   string `yaml:"apiKey" mapstructure:"apiKey"`
	Endpoint string `yaml:"endpoint" mapstructure:"endpoint"`
}

// DefaultConfig returns a config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Output:   "table",
		Severity: "low",
		Timeout:  5 * time.Minute,
		Scanners: scanner.Names(),
	}
}

// Load reads configuration from viper into a Config struct.
func Load() *Config {
	cfg := DefaultConfig()
	if v := viper.GetString("kubeconfig"); v != "" {
		cfg.Kubeconfig = v
	}
	if v := viper.GetString("context"); v != "" {
		cfg.Context = v
	}
	if v := viper.GetString("namespace"); v != "" {
		cfg.Namespace = v
	}
	if v := viper.GetString("output"); v != "" {
		cfg.Output = v
	}
	if viper.IsSet("verbose") {
		cfg.Verbose = viper.GetBool("verbose")
	}
	if v := viper.GetString("severity"); v != "" {
		cfg.Severity = v
	}
	cfg.AI.Provider = viper.GetString("ai.provider")
	cfg.AI.Model = viper.GetString("ai.model")
	cfg.AI.APIKey = viper.GetString("ai.apikey")
	if cfg.AI.APIKey == "" {
		cfg.AI.APIKey = viper.GetString("ai.apiKey")
	}
	cfg.AI.Endpoint = viper.GetString("ai.endpoint")
	if s := normalizeStringSlice(viper.GetStringSlice("scanners")); len(s) > 0 {
		cfg.Scanners = s
	}
	if d := viper.GetDuration("timeout"); d > 0 {
		cfg.Timeout = d
	}
	if viper.IsSet("exit-code") {
		cfg.ExitCode = viper.GetBool("exit-code")
	}
	if viper.IsSet("read-secret-data") {
		cfg.ReadSecretData = viper.GetBool("read-secret-data")
	}
	if v := viper.GetString("suppressions"); v != "" {
		cfg.Suppressions = v
	}
	if categories := normalizeStringSlice(viper.GetStringSlice("category")); len(categories) > 0 {
		cfg.Categories = categories
	} else {
		cfg.Categories = normalizeStringSlice(viper.GetStringSlice("categories"))
	}
	return cfg
}

func normalizeStringSlice(values []string) []string {
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				normalized = append(normalized, part)
			}
		}
	}
	return normalized
}
