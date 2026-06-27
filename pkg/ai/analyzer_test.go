package ai

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/RamazanKara/kube-shield/pkg/scanner/engine"
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

func TestDefaultAnalyzeOptions(t *testing.T) {
	opts := DefaultAnalyzeOptions()
	if opts.MaxFindings != 5 || opts.MinSeverity != engine.SeverityHigh || opts.RequestTimeout != 30*time.Second {
		t.Fatalf("unexpected default options: %#v", opts)
	}
}

func TestAnalyzeFindingsFiltersLimitsAndWritesExplanations(t *testing.T) {
	findings := []engine.Finding{
		{CheckID: "LOW", Title: "low", Severity: engine.SeverityLow},
		{CheckID: "HIGH", Title: "high", Severity: engine.SeverityHigh},
		{CheckID: "CRITICAL", Title: "critical", Severity: engine.SeverityCritical},
	}
	var buf bytes.Buffer

	AnalyzeFindings(context.Background(), &buf, analyzerProvider{}, findings, AnalyzeOptions{
		MaxFindings:    1,
		MinSeverity:    engine.SeverityHigh,
		RequestTimeout: time.Second,
	})

	output := buf.String()
	if !strings.Contains(output, "AI Analysis (test-ai)") || !strings.Contains(output, "explanation for HIGH") {
		t.Fatalf("expected AI explanation output, got: %s", output)
	}
	if strings.Contains(output, "LOW") || strings.Contains(output, "CRITICAL") {
		t.Fatalf("expected filter and limit to apply, got: %s", output)
	}
}

func TestAnalyzeFindingsWritesProviderErrors(t *testing.T) {
	var buf bytes.Buffer
	AnalyzeFindings(context.Background(), &buf, analyzerProvider{err: errors.New("offline")}, []engine.Finding{
		{CheckID: "HIGH", Title: "high", Severity: engine.SeverityHigh},
	}, AnalyzeOptions{
		MaxFindings:    5,
		MinSeverity:    engine.SeverityHigh,
		RequestTimeout: time.Second,
	})

	if !strings.Contains(buf.String(), "AI error: offline") {
		t.Fatalf("expected AI error output, got: %s", buf.String())
	}
}

func TestAnalyzeFindingsNoMatchingFindingsWritesNothing(t *testing.T) {
	var buf bytes.Buffer
	AnalyzeFindings(context.Background(), &buf, analyzerProvider{}, []engine.Finding{
		{CheckID: "LOW", Title: "low", Severity: engine.SeverityLow},
	}, DefaultAnalyzeOptions())
	if buf.Len() != 0 {
		t.Fatalf("expected no output for filtered findings, got: %s", buf.String())
	}
}
