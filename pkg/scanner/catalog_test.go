package scanner

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestBuiltInsAreValid(t *testing.T) {
	defs := BuiltIns()
	if len(defs) != 5 {
		t.Fatalf("expected 5 built-in scanners, got %d", len(defs))
	}

	names := make(map[string]bool, len(defs))
	categories := make(map[string]bool, len(defs))
	for _, def := range defs {
		if def.Name == "" {
			t.Fatal("scanner definition has empty name")
		}
		if names[def.Name] {
			t.Fatalf("duplicate scanner name %q", def.Name)
		}
		names[def.Name] = true
		if def.Category == "" {
			t.Fatalf("scanner %q has empty category", def.Name)
		}
		categories[string(def.Category)] = true
		if def.CheckCount <= 0 {
			t.Fatalf("scanner %q has invalid check count %d", def.Name, def.CheckCount)
		}
		if def.SeverityRange == "" {
			t.Fatalf("scanner %q has empty severity range", def.Name)
		}
		if def.New == nil || def.New().Name() != def.Name {
			t.Fatalf("scanner %q factory does not return matching scanner", def.Name)
		}
	}

	if len(NameSet()) != len(names) {
		t.Fatalf("name set size mismatch")
	}
	if len(CategorySet()) != len(categories) {
		t.Fatalf("category set size mismatch")
	}
}

func TestDefaultRegistryUsesBuiltIns(t *testing.T) {
	registry := DefaultRegistry()
	for _, def := range BuiltIns() {
		if _, ok := registry.Get(def.Name); !ok {
			t.Fatalf("default registry missing scanner %q", def.Name)
		}
	}
}

func TestCatalogMatchesScannerDocs(t *testing.T) {
	scannerDocs := readCatalogDoc(t, "../../docs/SCANNERS.md")
	readme := readCatalogDoc(t, "../../README.md")

	for _, def := range BuiltIns() {
		scannerDocRow := fmt.Sprintf("| `%s` | %d | `%s` | %s |", def.Name, def.CheckCount, def.Category, def.SeverityRange)
		if !strings.Contains(scannerDocs, scannerDocRow) {
			t.Fatalf("docs/SCANNERS.md missing catalog row: %s", scannerDocRow)
		}

		readmeRow := fmt.Sprintf("| `%s` | %d |", def.Name, def.CheckCount)
		if !strings.Contains(readme, readmeRow) {
			t.Fatalf("README.md missing scanner count row prefix: %s", readmeRow)
		}
	}
}

func readCatalogDoc(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}
