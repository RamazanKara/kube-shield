package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/RamazanKara/kube-shield/pkg/scanner/engine"
	"github.com/spf13/cobra"
)

var rulesOutput string

var rulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "Inspect kube-shield rule metadata",
	Long:  "Inspect built-in kube-shield rule metadata, including severity, confidence, data access, references, and standards mappings.",
}

var rulesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List built-in rules",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateRulesOutput(); err != nil {
			return err
		}
		rules := engine.Rules()
		if rulesOutput == "json" {
			return writeJSON(os.Stdout, rules)
		}
		_, _ = fmt.Fprintf(os.Stdout, "%-12s %-10s %-10s %-10s %-8s %s\n", "CHECK", "SCANNER", "SEVERITY", "CONF", "DEFAULT", "TITLE")
		for _, rule := range rules {
			_, _ = fmt.Fprintf(os.Stdout, "%-12s %-10s %-10s %-10s %-8t %s\n",
				rule.CheckID,
				rule.Scanner,
				rule.Severity,
				rule.Confidence,
				rule.DefaultEnabled,
				rule.Title,
			)
		}
		return nil
	},
}

var rulesShowCmd = &cobra.Command{
	Use:   "show CHECK_ID",
	Short: "Show one built-in rule",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateRulesOutput(); err != nil {
			return err
		}
		rule, ok := engine.RuleByID(strings.ToUpper(args[0]))
		if !ok {
			return fmt.Errorf("unknown rule %q", args[0])
		}
		if rulesOutput == "json" {
			return writeJSON(os.Stdout, rule)
		}
		_, _ = fmt.Fprintf(os.Stdout, "Check: %s\n", rule.CheckID)
		_, _ = fmt.Fprintf(os.Stdout, "Title: %s\n", rule.Title)
		_, _ = fmt.Fprintf(os.Stdout, "Scanner: %s\n", rule.Scanner)
		_, _ = fmt.Fprintf(os.Stdout, "Category: %s\n", rule.Category)
		_, _ = fmt.Fprintf(os.Stdout, "Severity: %s\n", rule.Severity)
		_, _ = fmt.Fprintf(os.Stdout, "Confidence: %s\n", rule.Confidence)
		_, _ = fmt.Fprintf(os.Stdout, "Default Enabled: %t\n", rule.DefaultEnabled)
		_, _ = fmt.Fprintf(os.Stdout, "Data Access: %s\n", rule.DataAccess)
		_, _ = fmt.Fprintf(os.Stdout, "\nRationale:\n%s\n", rule.Rationale)
		_, _ = fmt.Fprintf(os.Stdout, "\nImpact:\n%s\n", rule.Impact)
		_, _ = fmt.Fprintf(os.Stdout, "\nRemediation:\n%s\n", rule.Remediation)
		if rule.FalsePositives != "" {
			_, _ = fmt.Fprintf(os.Stdout, "\nFalse Positives:\n%s\n", rule.FalsePositives)
		}
		if len(rule.Standards) > 0 {
			_, _ = fmt.Fprintln(os.Stdout, "\nStandards:")
			for _, standard := range rule.Standards {
				_, _ = fmt.Fprintf(os.Stdout, "- %s: %s\n", standard.Name, standard.Control)
			}
		}
		if len(rule.References) > 0 {
			_, _ = fmt.Fprintln(os.Stdout, "\nReferences:")
			for _, ref := range rule.References {
				_, _ = fmt.Fprintf(os.Stdout, "- %s\n", ref)
			}
		}
		return nil
	},
}

func init() {
	rulesCmd.PersistentFlags().StringVar(&rulesOutput, "output", "table", "output format: table or json")
	rulesCmd.AddCommand(rulesListCmd)
	rulesCmd.AddCommand(rulesShowCmd)
	rootCmd.AddCommand(rulesCmd)
}

func validateRulesOutput() error {
	rulesOutput = strings.ToLower(strings.TrimSpace(rulesOutput))
	switch rulesOutput {
	case "table", "json":
		return nil
	default:
		return fmt.Errorf("invalid rules output format %q: supported values are table, json", rulesOutput)
	}
}

func writeJSON(file *os.File, value interface{}) error {
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
