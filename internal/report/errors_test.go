package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/RamazanKara/kube-shield/v2/internal/scanner/engine"
)

type failingWriter struct{}

func (failingWriter) Write(p []byte) (int, error) { return 0, io.ErrClosedPipe }

func TestTableWriterWriteErrors(t *testing.T) {
	for _, tt := range []struct {
		name   string
		report *engine.Report
	}{
		{"empty", &engine.Report{}}, {"findings", sampleReport()},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := TableWriter(failingWriter{}, tt.report); !errors.Is(err, io.ErrClosedPipe) {
				t.Fatalf("expected write error, got %v", err)
			}
		})
	}
}

func TestTableWriterIncompleteScan(t *testing.T) {
	var output bytes.Buffer
	report := &engine.Report{Results: []*engine.ScanResult{{Scanner: "rbac", Error: errors.New("forbidden")}}}
	if err := TableWriter(&output, report); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "looks good") || !strings.Contains(output.String(), "rbac scanner failed: forbidden") {
		t.Fatalf("misleading output: %s", output.String())
	}
}

func TestSARIFWriterEmptyArrays(t *testing.T) {
	var output bytes.Buffer
	if err := SARIFWriter(&output, &engine.Report{}); err != nil {
		t.Fatal(err)
	}
	var document struct {
		Runs []struct {
			Results []json.RawMessage
			Tool    struct {
				Driver struct{ Rules []json.RawMessage }
			}
		}
	}
	if err := json.Unmarshal(output.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Runs) != 1 {
		t.Fatalf("unexpected runs: %s", output.String())
	}
	if document.Runs[0].Results == nil || document.Runs[0].Tool.Driver.Rules == nil {
		t.Fatalf("empty SARIF collections must be arrays: %s", output.String())
	}
}

func TestSARIFRemediationIsNotAnAutomaticEdit(t *testing.T) {
	finding := sampleReport().Findings[0]
	result := buildSARIFResults([]engine.Finding{finding})[0]
	if _, exists := result["fixes"]; exists {
		t.Fatal("SARIF fixes require artifact edits, not just remediation text")
	}
	properties := result["properties"].(map[string]interface{})
	if properties["remediation"] != finding.Remediation {
		t.Fatalf("missing remediation: %#v", properties)
	}
}
