package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestValidateConfigYAML(t *testing.T) {
	for _, tt := range []struct{ name, input, want string }{
		{"empty", "", ""},
		{"defaults", "{}", ""},
		{"null", "null", ""},
		{"valid", "output: Markdown\nseverity: HIGH\nscanners: [workload, 'rbac,netpol']\ncategories: secrets,cis\ntimeout: 1m\nverbose: true\nexit-code: false\nread-secret-data: true\nai:\n  provider: ollama\n  apiKey: synthetic\n", ""},
		{"null values", "scanners: null\nai: null\ntimeout: null\noutput: null\ncontext: null\n", ""},
		{"aliases", "context: &value staging\nnamespace: *value\n", ""},
		{"merge", "<<: &defaults {output: json, scanners: [rbac]}\nseverity: high", ""},
		{"merge sequence", "<<: [{output: json}, {severity: high}]", ""},
		{"nested merge", "ai:\n  <<: {provider: ollama, model: local}\n", ""},
		{"unknown", "output: json\nseverty: high", "line 2, column 10: severty: unknown configuration key"},
		{"unknown nested", "ai:\n  api-key: private-value", "line 2, column 12: ai.api-key: unknown configuration key"},
		{"unknown null", "typo: null", "unknown configuration key"},
		{"duplicate", "output: json\noutput: table", "line 2"},
		{"case duplicate", "output: json\nOUTPUT: table", "duplicate configuration key"},
		{"wrong root", "- output: json", "line 1, column 1: config must be a mapping"},
		{"wrong key", "1: value", "configuration keys must be strings"},
		{"wrong ai", "ai: []", "ai.config must be a mapping"},
		{"wrong string", "namespace: [prod]", "namespace: expected a string"},
		{"wrong boolean", "exit-code: maybe", "exit-code: expected a boolean"},
		{"YAML 1.1 boolean", "exit-code: yes", "expected a boolean"},
		{"blank output", "output: '  '", "supported values"},
		{"wrong secret type", "ai:\n  apikey: [private-value]", "ai.apikey: expected a string"},
		{"wrong list", "scanners: [123]", "expected a string or list of strings"},
		{"unknown scanner", "scanners:\n  - rbac\n  - missing", "line 3: invalid scanners"},
		{"unknown category", "category: typo", "invalid category"},
		{"output", "output: yaml", "supported values"},
		{"severity", "severity: urgent", "supported values are critical"},
		{"provider", "ai: {provider: unknown}", "supported values"},
		{"duration", "timeout: forever", "expected a positive duration"},
		{"zero", "timeout: 0s", "expected a positive duration"},
		{"negative", "timeout: -1m", "expected a positive duration"},
		{"multiple documents", "output: json\n---\nseverity: high", "single YAML document"},
		{"malformed", "output: [", "line 1"},
		{"cycle", "ai: &ai {model: *ai}", "contains itself"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConfigYAML([]byte(tt.input))
			if tt.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("want %q, got %v", tt.want, err)
			}
			if err != nil && strings.Contains(err.Error(), "private-value") {
				t.Fatal("diagnostic disclosed a value")
			}
		})
	}
}

func TestConfigValidateCommand(t *testing.T) {
	for _, tt := range []struct {
		name, input string
		missing     bool
		want        string
	}{
		{name: "valid", input: "output: markdown"},
		{name: "invalid", input: "output: invalid", want: "line 1"},
		{name: "missing", missing: true, want: "failed to read config"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			t.Chdir(dir)
			t.Setenv("HOME", dir)
			t.Setenv("USERPROFILE", dir)
			t.Setenv("KUBE_SHIELD_OUTPUT", "invalid")
			if err := os.WriteFile(".kube-shield.yaml", []byte("broken: ["), 0o600); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "test.yaml")
			if !tt.missing {
				if err := os.WriteFile(path, []byte(tt.input), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			var output bytes.Buffer
			root := &cobra.Command{Use: "test", PersistentPreRunE: rootCmd.PersistentPreRunE}
			command := *configValidateCmd
			root.AddCommand(&command)
			root.SetOut(&output)
			root.SetErr(&output)
			root.SetArgs([]string{"validate", path})
			err := root.Execute()
			if tt.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(output.String(), "Configuration valid: "+path) {
					t.Fatal(output.String())
				}
			} else if err == nil || !strings.Contains(err.Error(), tt.want) || !strings.Contains(err.Error(), path) {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateExampleConfig(t *testing.T) {
	data, err := os.ReadFile("../../examples/.kube-shield.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateConfigYAML(data); err != nil {
		t.Fatal(err)
	}
}

func FuzzValidateConfigYAML(f *testing.F) {
	for _, seed := range []string{"", "{}", "output: markdown", "ai: &ai {model: *ai}", "<<: [{output: json}]", "scanners: [rbac, secrets]", "a: [", "---\n---"} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) { _ = validateConfigYAML(data) })
}
