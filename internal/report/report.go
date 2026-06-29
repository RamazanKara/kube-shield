package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/RamazanKara/kube-shield/internal/scanner/engine"
	"github.com/RamazanKara/kube-shield/internal/version"
)

// TableWriter writes findings in a colored table format.
func TableWriter(w io.Writer, report *engine.Report) error {
	decorated := useDecorations(w)
	if len(report.Findings) == 0 {
		if decorated {
			_, _ = fmt.Fprintln(w, "\n✅ No security findings detected! Your cluster looks good.")
		} else {
			_, _ = fmt.Fprintln(w, "\nNo security findings detected. Your cluster looks good.")
		}
		if report.Summary.SuppressedTotal > 0 {
			_, _ = fmt.Fprintf(w, "Suppressed Findings: %d\n", report.Summary.SuppressedTotal)
		}
		return nil
	}

	// Sort findings by severity (critical first)
	findings := make([]engine.Finding, len(report.Findings))
	copy(findings, report.Findings)
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Severity > findings[j].Severity
	})

	// Header
	_, _ = fmt.Fprintf(w, "\n%s\n", strings.Repeat("─", 100))
	_, _ = fmt.Fprintf(w, "  %-10s %-12s %-40s %s\n", "SEVERITY", "CHECK", "RESOURCE", "TITLE")
	_, _ = fmt.Fprintf(w, "%s\n", strings.Repeat("─", 100))

	for _, f := range findings {
		severityStr := formatSeverity(f.Severity, decorated)
		resource := f.Resource.String()
		if len(resource) > 38 {
			resource = resource[:35] + "..."
		}
		title := f.Title
		if len(title) > 50 {
			title = title[:47] + "..."
		}

		_, _ = fmt.Fprintf(w, "  %-21s %-12s %-40s %s\n", severityStr, f.CheckID, resource, title)
	}

	_, _ = fmt.Fprintf(w, "%s\n\n", strings.Repeat("─", 100))

	// Summary
	scoreLabel := "Security Score"
	totalLabel := "Total Findings"
	if decorated {
		scoreLabel = "📊 " + scoreLabel
		totalLabel = "📋 " + totalLabel
	}
	_, _ = fmt.Fprintf(w, "  %s: %s (%.0f/100)\n", scoreLabel, report.Summary.Grade, report.Summary.Score)
	if report.Summary.RawTotal > report.Summary.Total {
		_, _ = fmt.Fprintf(w, "  %s: %d (%d raw)\n", totalLabel, report.Summary.Total, report.Summary.RawTotal)
	} else {
		_, _ = fmt.Fprintf(w, "  %s: %d\n", totalLabel, report.Summary.Total)
	}
	if report.Summary.SuppressedTotal > 0 {
		_, _ = fmt.Fprintf(w, "  Suppressed Findings: %d\n", report.Summary.SuppressedTotal)
	}
	writeSeveritySummary(w, report, decorated)
	_, _ = fmt.Fprintln(w)

	return nil
}

// JSONWriter writes findings as JSON.
func JSONWriter(w io.Writer, report *engine.Report) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

// SARIFWriter writes findings in SARIF format for GitHub Code Scanning.
func SARIFWriter(w io.Writer, report *engine.Report) error {
	findings := append([]engine.Finding{}, report.Findings...)
	findings = append(findings, report.SuppressedFindings...)
	sarif := map[string]interface{}{
		"version": "2.1.0",
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"runs": []map[string]interface{}{
			{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":           "kube-shield",
						"informationUri": "https://github.com/RamazanKara/kube-shield",
						"version":        version.Version,
						"rules":          buildSARIFRules(findings),
					},
				},
				"results": buildSARIFResults(findings),
			},
		},
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(sarif)
}

func buildSARIFRules(findings []engine.Finding) []map[string]interface{} {
	seen := make(map[string]bool)
	var rules []map[string]interface{}

	for _, f := range findings {
		if seen[f.CheckID] {
			continue
		}
		seen[f.CheckID] = true

		rule := map[string]interface{}{
			"id": f.CheckID,
			"shortDescription": map[string]string{
				"text": f.Title,
			},
			"defaultConfiguration": map[string]string{
				"level": sarifLevel(f.Severity),
			},
			"helpUri": "https://github.com/RamazanKara/kube-shield/blob/main/docs/reference/scanners.md#" + strings.ToLower(f.CheckID),
		}
		if metadata, ok := engine.RuleByID(f.CheckID); ok {
			rule["shortDescription"] = map[string]string{"text": metadata.Title}
			rule["fullDescription"] = map[string]string{"text": metadata.Rationale}
			rule["help"] = map[string]string{"text": metadata.Remediation}
			rule["properties"] = map[string]interface{}{
				"category":       metadata.Category,
				"scanner":        metadata.Scanner,
				"confidence":     metadata.Confidence,
				"impact":         metadata.Impact,
				"dataAccess":     metadata.DataAccess,
				"defaultEnabled": metadata.DefaultEnabled,
				"standards":      metadata.Standards,
				"references":     metadata.References,
			}
		}
		rules = append(rules, rule)
	}

	return rules
}

func buildSARIFResults(findings []engine.Finding) []map[string]interface{} {
	var results []map[string]interface{}

	for _, f := range findings {
		result := map[string]interface{}{
			"ruleId":  f.CheckID,
			"level":   sarifLevel(f.Severity),
			"message": map[string]string{"text": f.Description},
			"locations": []map[string]interface{}{
				{
					"logicalLocations": []map[string]string{
						{
							"name":               f.Resource.String(),
							"kind":               f.Resource.Kind,
							"fullyQualifiedName": f.Resource.String(),
						},
					},
				},
			},
			"fixes": []map[string]interface{}{
				{
					"description": map[string]string{
						"text": f.Remediation,
					},
				},
			},
			"properties": map[string]interface{}{
				"fingerprint": f.Fingerprint,
				"confidence":  f.Confidence,
				"category":    f.Category,
			},
		}
		if f.Suppression != nil {
			result["suppressions"] = []map[string]string{
				{
					"kind":          "external",
					"justification": fmt.Sprintf("%s (expires %s)", f.Suppression.Reason, f.Suppression.Expires),
				},
			}
		}
		results = append(results, result)
	}

	return results
}

func sarifLevel(s engine.Severity) string {
	switch s {
	case engine.SeverityCritical, engine.SeverityHigh:
		return "error"
	case engine.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func writeSeveritySummary(w io.Writer, report *engine.Report, decorated bool) {
	if decorated {
		_, _ = fmt.Fprintf(w, "     %s %d Critical  %s %d High  %s %d Medium  %s %d Low  %s %d Info\n",
			"🔴", report.Summary.BySeverity[engine.SeverityCritical],
			"🟠", report.Summary.BySeverity[engine.SeverityHigh],
			"🟡", report.Summary.BySeverity[engine.SeverityMedium],
			"🔵", report.Summary.BySeverity[engine.SeverityLow],
			"⚪", report.Summary.BySeverity[engine.SeverityInfo],
		)
		return
	}
	_, _ = fmt.Fprintf(w, "     Critical: %d  High: %d  Medium: %d  Low: %d  Info: %d\n",
		report.Summary.BySeverity[engine.SeverityCritical],
		report.Summary.BySeverity[engine.SeverityHigh],
		report.Summary.BySeverity[engine.SeverityMedium],
		report.Summary.BySeverity[engine.SeverityLow],
		report.Summary.BySeverity[engine.SeverityInfo],
	)
}

func formatSeverity(s engine.Severity, decorated bool) string {
	if !decorated {
		return s.String()
	}
	switch s {
	case engine.SeverityCritical:
		return "\033[1;31mCRITICAL\033[0m"
	case engine.SeverityHigh:
		return "\033[31mHIGH\033[0m"
	case engine.SeverityMedium:
		return "\033[33mMEDIUM\033[0m"
	case engine.SeverityLow:
		return "\033[34mLOW\033[0m"
	case engine.SeverityInfo:
		return "\033[37mINFO\033[0m"
	default:
		return s.String()
	}
}

func useDecorations(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	file, ok := w.(*os.File)
	if !ok {
		return false
	}
	stat, err := file.Stat()
	if err != nil {
		return false
	}
	return stat.Mode()&os.ModeCharDevice != 0
}
