package cmd

import (
	"os"
	"strings"
	"testing"
)

func TestValidateRulesOutput(t *testing.T) {
	oldOutput := rulesOutput
	t.Cleanup(func() { rulesOutput = oldOutput })

	for _, value := range []string{"table", "json"} {
		rulesOutput = value
		if err := validateRulesOutput(); err != nil {
			t.Fatalf("expected %s to be valid: %v", value, err)
		}
	}
	rulesOutput = "yaml"
	if err := validateRulesOutput(); err == nil {
		t.Fatal("expected invalid rules output error")
	}
}

func TestWriteJSON(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "rules-*.json")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer file.Close()

	if err := writeJSON(file, map[string]string{"checkId": "WL-010"}); err != nil {
		t.Fatalf("writeJSON returned error: %v", err)
	}
	if _, err := file.Seek(0, 0); err != nil {
		t.Fatalf("seek temp file: %v", err)
	}
	data, err := os.ReadFile(file.Name())
	if err != nil {
		t.Fatalf("read temp file: %v", err)
	}
	if !strings.Contains(string(data), `"checkId": "WL-010"`) {
		t.Fatalf("unexpected JSON output: %s", string(data))
	}
}
