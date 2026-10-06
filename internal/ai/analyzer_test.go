package ai

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/RamazanKara/kube-shield/internal/scanner/engine"
)

type analyzerProvider struct {
	err error
}

func (p analyzerProvider) Name() string { return "test-ai" }
func (p analyzerProvider) Explain(ctx context.Context, finding engine.Finding) (string, error) {
	if p.err != nil {
		return "", p.err
	}
	return "explanation for " + finding.CheckID, nil
}

func TestAnalyzeFindingsFiltersLimitsAndWritesExplanations(t *testing.T) {
	findings := []engine.Finding{
		{CheckID: "LOW", Title: "low", Severity: engine.SeverityLow},
		{CheckID: "HIGH", Title: "high", Severity: engine.SeverityHigh},
		{CheckID: "CRITICAL", Title: "critical", Severity: engine.SeverityCritical},
		{CheckID: "HIGH-2", Title: "high 2", Severity: engine.SeverityHigh},
		{CheckID: "HIGH-3", Title: "high 3", Severity: engine.SeverityHigh},
		{CheckID: "HIGH-4", Title: "high 4", Severity: engine.SeverityHigh},
		{CheckID: "SKIPPED", Title: "skipped", Severity: engine.SeverityCritical},
	}
	var buf bytes.Buffer

	AnalyzeFindings(context.Background(), &buf, analyzerProvider{}, findings)

	output := buf.String()
	if !strings.Contains(output, "AI Analysis (test-ai)") || !strings.Contains(output, "explanation for HIGH") {
		t.Fatalf("expected AI explanation output, got: %s", output)
	}
	if strings.Contains(output, "LOW") || strings.Contains(output, "SKIPPED") || strings.Count(output, "explanation for ") != 5 {
		t.Fatalf("expected filter and limit to apply, got: %s", output)
	}
}

func TestAnalyzeFindingsWritesProviderErrors(t *testing.T) {
	var buf bytes.Buffer
	AnalyzeFindings(context.Background(), &buf, analyzerProvider{err: errors.New("offline")}, []engine.Finding{
		{CheckID: "HIGH", Title: "high", Severity: engine.SeverityHigh},
	})

	if !strings.Contains(buf.String(), "AI error: offline") {
		t.Fatalf("expected AI error output, got: %s", buf.String())
	}
}

func TestAnalyzeFindingsNoMatchingFindingsWritesNothing(t *testing.T) {
	var buf bytes.Buffer
	AnalyzeFindings(context.Background(), &buf, analyzerProvider{}, []engine.Finding{
		{CheckID: "LOW", Title: "low", Severity: engine.SeverityLow},
	})
	if buf.Len() != 0 {
		t.Fatalf("expected no output for filtered findings, got: %s", buf.String())
	}
}
