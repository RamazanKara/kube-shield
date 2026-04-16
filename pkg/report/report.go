package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/RamazanKara/kube-shield/pkg/scanner/engine"
)

// TableWriter writes findings in a colored table format.
func TableWriter(w io.Writer, report *engine.Report) error {
	if len(report.Findings) == 0 {
		_, _ = fmt.Fprintln(w, "\n✅ No security findings detected! Your cluster looks good.")
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
		severityStr := colorSeverity(f.Severity)
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
	_, _ = fmt.Fprintf(w, "  📊 Security Score: %s (%.0f/100)\n", report.Summary.Grade, report.Summary.Score)
	_, _ = fmt.Fprintf(w, "  📋 Total Findings: %d\n", report.Summary.Total)
	_, _ = fmt.Fprintf(w, "     %s %d Critical  %s %d High  %s %d Medium  %s %d Low  %s %d Info\n",
		"🔴", report.Summary.BySeverity[engine.SeverityCritical],
		"🟠", report.Summary.BySeverity[engine.SeverityHigh],
		"🟡", report.Summary.BySeverity[engine.SeverityMedium],
		"🔵", report.Summary.BySeverity[engine.SeverityLow],
		"⚪", report.Summary.BySeverity[engine.SeverityInfo],
	)
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
	sarif := map[string]interface{}{
		"version": "2.1.0",
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"runs": []map[string]interface{}{
			{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":           "kube-shield",
						"informationUri": "https://github.com/RamazanKara/kube-shield",
						"version":        "0.1.0",
						"rules":          buildSARIFRules(report.Findings),
					},
				},
				"results": buildSARIFResults(report.Findings),
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

		rules = append(rules, map[string]interface{}{
			"id": f.CheckID,
			"shortDescription": map[string]string{
				"text": f.Title,
			},
			"defaultConfiguration": map[string]string{
				"level": sarifLevel(f.Severity),
			},
			"helpUri": fmt.Sprintf("https://github.com/RamazanKara/kube-shield/docs/checks/%s", f.CheckID),
		})
	}

	return rules
}

func buildSARIFResults(findings []engine.Finding) []map[string]interface{} {
	var results []map[string]interface{}

	for _, f := range findings {
		results = append(results, map[string]interface{}{
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
		})
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

func colorSeverity(s engine.Severity) string {
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
