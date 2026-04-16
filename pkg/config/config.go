package config

import (
	"time"

	"github.com/spf13/viper"
)

// Config holds all configuration for kube-shield.
type Config struct {
	Kubeconfig string        `yaml:"kubeconfig" mapstructure:"kubeconfig"`
	Context    string        `yaml:"context" mapstructure:"context"`
	Namespace  string        `yaml:"namespace" mapstructure:"namespace"`
	Output     string        `yaml:"output" mapstructure:"output"`
	Verbose    bool          `yaml:"verbose" mapstructure:"verbose"`
	Scanners   []string      `yaml:"scanners" mapstructure:"scanners"`
	Severity   string        `yaml:"severity" mapstructure:"severity"`
	Timeout    time.Duration `yaml:"timeout" mapstructure:"timeout"`
	ExitCode   bool          `yaml:"exitCode" mapstructure:"exit-code"`
	Categories []string      `yaml:"categories" mapstructure:"categories"`
	AI         AIConfig      `yaml:"ai" mapstructure:"ai"`
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
		Scanners: []string{"workload", "cis", "rbac", "netpol", "secrets"},
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
	cfg.AI.Endpoint = viper.GetString("ai.endpoint")
	if s := viper.GetStringSlice("scanners"); len(s) > 0 {
		cfg.Scanners = s
	}
	if d := viper.GetDuration("timeout"); d > 0 {
		cfg.Timeout = d
	}
	if viper.IsSet("exit-code") {
		cfg.ExitCode = viper.GetBool("exit-code")
	}
	cfg.Categories = viper.GetStringSlice("categories")
	return cfg
}
