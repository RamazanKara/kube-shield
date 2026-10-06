package ai

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/RamazanKara/kube-shield/internal/scanner/engine"
)

// AnalyzeFindings runs AI explanation on high-severity findings and writes results to w.
func AnalyzeFindings(ctx context.Context, w io.Writer, provider Provider, findings []engine.Finding) {
	var filtered []engine.Finding
	for _, f := range findings {
		if f.Severity >= engine.SeverityHigh {
			filtered = append(filtered, f)
		}
	}
	if len(filtered) == 0 {
		return
	}

	_, _ = fmt.Fprintf(w, "\n🤖 AI Analysis (%s):\n", provider.Name())

	for _, f := range filtered[:min(len(filtered), 5)] {
		aiCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		explanation, err := provider.Explain(aiCtx, f)
		cancel()
		if err != nil {
			_, _ = fmt.Fprintf(w, "  %s: AI error: %v\n", f.CheckID, err)
			continue
		}
		_, _ = fmt.Fprintf(w, "\n  📋 %s (%s)\n  %s\n", f.Title, f.CheckID, explanation)
	}
}
