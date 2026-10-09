package report

import (
	"bufio"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/RamazanKara/kube-shield/v2/internal/scanner/engine"
)

// MarkdownWriter writes a report suitable for issue descriptions and CI summaries.
func MarkdownWriter(w io.Writer, report *engine.Report) error {
	buffer := bufio.NewWriter(w)
	_, _ = fmt.Fprint(buffer, "# kube-shield security report\n\n")
	if report.ClusterInfo != "" {
		_, _ = fmt.Fprintf(buffer, "Cluster: %s\n\n", markdownText(report.ClusterInfo))
	}
	if !report.GeneratedAt.IsZero() {
		_, _ = fmt.Fprintf(buffer, "Generated: %s\n\n", report.GeneratedAt.UTC().Format(time.RFC3339))
	}
	incomplete := false
	for _, result := range report.Results {
		if result.Error != nil {
			incomplete = true
			_, _ = fmt.Fprintf(buffer, "> Scan incomplete: %s scanner failed: %s\n\n", markdownText(result.Scanner), markdownText(result.Error.Error()))
		}
	}
	if incomplete {
		_, _ = fmt.Fprint(buffer, "The score and findings below cover completed scanners only.\n\n")
	}
	_, _ = fmt.Fprintf(buffer, "Security score: %s (%.0f/100)\n\n", markdownText(report.Summary.Grade), report.Summary.Score)
	_, _ = fmt.Fprintf(buffer, "Active findings: %d", report.Summary.Total)
	if report.Summary.RawTotal > report.Summary.Total {
		_, _ = fmt.Fprintf(buffer, " (%d raw)", report.Summary.RawTotal)
	}
	_, _ = fmt.Fprintf(buffer, " · Suppressed findings: %d\n\n", report.Summary.SuppressedTotal)
	_, _ = fmt.Fprintln(buffer, "| Critical | High | Medium | Low | Info |\n| --- | --- | --- | --- | --- |")
	_, _ = fmt.Fprintf(buffer, "| %d | %d | %d | %d | %d |\n",
		report.Summary.BySeverity[engine.SeverityCritical], report.Summary.BySeverity[engine.SeverityHigh],
		report.Summary.BySeverity[engine.SeverityMedium], report.Summary.BySeverity[engine.SeverityLow], report.Summary.BySeverity[engine.SeverityInfo])
	for _, section := range []struct {
		title    string
		findings []engine.Finding
	}{
		{"Findings", report.Findings},
		{"Suppressed findings", report.SuppressedFindings},
	} {
		_, _ = fmt.Fprintf(buffer, "\n## %s\n\n", section.title)
		if len(section.findings) == 0 {
			_, _ = fmt.Fprintln(buffer, "None reported.")
			continue
		}
		findings := append([]engine.Finding(nil), section.findings...)
		sort.SliceStable(findings, func(i, j int) bool {
			if findings[i].Severity != findings[j].Severity {
				return findings[i].Severity > findings[j].Severity
			}
			return findings[i].ID < findings[j].ID
		})
		_, _ = fmt.Fprintln(buffer, "| Severity | Check | Resource | Finding | Remediation | Suppression |\n| --- | --- | --- | --- | --- | --- |")
		for _, finding := range findings {
			suppression := ""
			if finding.Suppression != nil {
				suppression = fmt.Sprintf("%s: %s (expires %s)", finding.Suppression.ID, finding.Suppression.Reason, finding.Suppression.Expires)
			}
			_, _ = fmt.Fprintf(buffer, "| %s | %s | %s | %s<br>%s | %s | %s |\n",
				finding.Severity, markdownText(finding.CheckID), markdownText(finding.Resource.String()),
				markdownText(finding.Title), markdownText(finding.Description), markdownText(finding.Remediation), markdownText(suppression))
		}
	}
	return buffer.Flush()
}

func markdownText(value string) string {
	value = strings.ReplaceAll(value, "\r\n", "\n")
	return strings.NewReplacer(
		"&", "&amp;", "<", "&lt;", ">", "&gt;", "|", "&#124;", "\\", "&#92;",
		"`", "&#96;", "*", "&#42;", "_", "&#95;", "~", "&#126;", "[", "&#91;", "]", "&#93;",
		"\r", "<br>", "\n", "<br>",
	).Replace(value)
}
