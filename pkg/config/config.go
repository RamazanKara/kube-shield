package config

import "time"

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
