package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/RamazanKara/kube-shield/v2/internal/scanner"
	"github.com/RamazanKara/kube-shield/v2/internal/scanner/engine"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Check configuration files without connecting to a cluster",
}

var configValidateCmd = &cobra.Command{
	Use:   "validate FILE",
	Short: "Validate a YAML configuration file with line-numbered errors",
	Long:  "Validate one YAML file, including unknown keys, types, and supported values.\nEnvironment variables, --config, and other configuration overrides are not used.",
	Args:  cobra.ExactArgs(1),
	// Validation must inspect the named file even when the default config is broken.
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error { return nil },
	RunE: func(cmd *cobra.Command, args []string) error {
		data, err := os.ReadFile(args[0])
		if err != nil {
			return fmt.Errorf("failed to read config: %w", err)
		}
		if err := validateConfigYAML(data); err != nil {
			return fmt.Errorf("%s: %w", args[0], err)
		}
		_, err = fmt.Fprintf(cmd.OutOrStdout(), "Configuration valid: %s\n", args[0])
		return err
	},
}

func init() {
	configCmd.AddCommand(configValidateCmd)
	rootCmd.AddCommand(configCmd)
}

func validateConfigYAML(data []byte) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		if err == io.EOF {
			return nil
		}
		return err
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		if err != nil {
			return err
		}
		return fmt.Errorf("line %d: expected a single YAML document", extra.Line)
	}
	// Let YAML reject duplicate keys and cyclic or excessive aliases before walking nodes.
	var decoded interface{}
	if err := document.Decode(&decoded); err != nil {
		return err
	}
	return validateConfigMapping(document.Content[0], "")
}

func validateConfigMapping(node *yaml.Node, prefix string) error {
	if node.Kind == yaml.AliasNode {
		node = node.Alias
	}
	if node.Tag == "!!null" {
		return nil
	}
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("line %d, column %d: %sconfig must be a mapping", node.Line, node.Column, prefix)
	}
	seen := make(map[string]bool)
	for i := 0; i < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		if key.Tag == "!!merge" {
			merged := []*yaml.Node{value}
			if value.Kind == yaml.SequenceNode {
				merged = value.Content
			}
			for _, mapping := range merged {
				if err := validateConfigMapping(mapping, prefix); err != nil {
					return err
				}
			}
			continue
		}
		if key.Tag != "!!str" {
			return fmt.Errorf("line %d, column %d: configuration keys must be strings", key.Line, key.Column)
		}
		name := prefix + strings.ToLower(key.Value)
		if seen[name] {
			return fmt.Errorf("line %d, column %d: duplicate configuration key %q", key.Line, key.Column, name)
		}
		seen[name] = true
		if name == "ai" {
			if err := validateConfigMapping(value, "ai."); err != nil {
				return err
			}
			continue
		}
		if err := validateConfigValue(name, value); err != nil {
			return fmt.Errorf("line %d, column %d: %s: %w", value.Line, value.Column, name, err)
		}
	}
	return nil
}

func validateConfigValue(name string, node *yaml.Node) error {
	if node.Kind == yaml.AliasNode {
		node = node.Alias
	}
	switch name {
	case "kubeconfig", "context", "namespace", "suppressions", "ai.model", "ai.apikey", "ai.endpoint":
		if node.Tag != "!!null" && node.Tag != "!!str" {
			return fmt.Errorf("expected a string")
		}
	case "verbose", "exit-code", "read-secret-data":
		if node.Tag != "!!null" && node.Tag != "!!bool" {
			return fmt.Errorf("expected a boolean (true or false)")
		}
	case "timeout":
		if node.Tag == "!!null" {
			return nil
		}
		var value time.Duration
		if err := node.Decode(&value); err != nil || value <= 0 {
			return fmt.Errorf("expected a positive duration (for example 5m)")
		}
	case "scanners", "category", "categories":
		if node.Tag == "!!null" {
			return nil
		}
		values := []*yaml.Node{node}
		if node.Kind == yaml.SequenceNode {
			values = node.Content
		}
		valid := scanner.NameSet()
		if name != "scanners" {
			valid = scanner.CategorySet()
		}
		for _, value := range values {
			if value.Kind == yaml.AliasNode {
				value = value.Alias
			}
			if value.Tag != "!!str" {
				return fmt.Errorf("line %d: expected a string or list of strings", value.Line)
			}
			if err := validateValues(name, normalizeList([]string{value.Value}), valid); err != nil {
				return fmt.Errorf("line %d: %w", value.Line, err)
			}
		}
	case "output", "severity", "ai.provider":
		if node.Tag == "!!null" {
			return nil
		}
		if node.Tag != "!!str" {
			return fmt.Errorf("expected a string")
		}
		value := strings.ToLower(strings.TrimSpace(node.Value))
		if node.Value == "" {
			return nil
		}
		switch name {
		case "ai.provider":
			if _, ok := validAIProviders[value]; !ok {
				return fmt.Errorf("supported values are openai, ollama, or empty")
			}
		case "severity":
			if _, ok := engine.ParseSeverity(value); !ok {
				return fmt.Errorf("supported values are critical, high, medium, low, info")
			}
		default:
			return validateValues(name, []string{value}, validOutputs)
		}
	default:
		return fmt.Errorf("unknown configuration key")
	}
	return nil
}
