package ai

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/RamazanKara/kube-shield/pkg/scanner/engine"
)

// AnalyzeOptions configures the AI analysis behavior.
type AnalyzeOptions struct {
	MaxFindings    int
	MinSeverity    engine.Severity
	RequestTimeout time.Duration
}

// DefaultAnalyzeOptions returns sensible defaults for AI analysis.
func DefaultAnalyzeOptions() AnalyzeOptions {
	return AnalyzeOptions{
		MaxFindings:    5,
		MinSeverity:    engine.SeverityHigh,
		RequestTimeout: 30 * time.Second,
	}
}

// AnalyzeFindings runs AI explanation on high-severity findings and writes results to w.
func AnalyzeFindings(ctx context.Context, w io.Writer, provider Provider, findings []engine.Finding, opts AnalyzeOptions) {
	var filtered []engine.Finding
	for _, f := range findings {
		if f.Severity >= opts.MinSeverity {
			filtered = append(filtered, f)
		}
	}
	if len(filtered) == 0 {
		return
	}

	_, _ = fmt.Fprintf(w, "\n🤖 AI Analysis (%s):\n", provider.Name())

	limit := len(filtered)
	if limit > opts.MaxFindings {
		limit = opts.MaxFindings
	}

	for _, f := range filtered[:limit] {
		aiCtx, cancel := context.WithTimeout(ctx, opts.RequestTimeout)
		explanation, err := provider.Explain(aiCtx, f)
		cancel()
		if err != nil {
			_, _ = fmt.Fprintf(w, "  %s: AI error: %v\n", f.CheckID, err)
			continue
		}
		_, _ = fmt.Fprintf(w, "\n  📋 %s (%s)\n  %s\n", f.Title, f.CheckID, explanation)
	}
}
