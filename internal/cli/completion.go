package cli

import (
	"slices"
	"strings"

	"github.com/RamazanKara/kube-shield/v2/internal/scanner/engine"
	"github.com/spf13/cobra"
)

func completeValues(values []string, commaSeparated bool) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		prefix, partial := "", toComplete
		var selected []string
		if commaSeparated {
			if index := strings.LastIndex(toComplete, ","); index >= 0 {
				prefix, partial = toComplete[:index+1], toComplete[index+1:]
				selected = normalizeList([]string{toComplete[:index]})
			}
		}
		var matches []string
		for _, value := range values {
			if strings.HasPrefix(value, strings.ToLower(partial)) && !slices.Contains(selected, value) {
				matches = append(matches, prefix+value)
			}
		}
		return matches, cobra.ShellCompDirectiveNoFileComp
	}
}

func completeRules(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	var matches []string
	if len(args) == 0 {
		for _, rule := range engine.Rules() {
			if strings.HasPrefix(rule.CheckID, strings.ToUpper(toComplete)) {
				matches = append(matches, rule.CheckID+"\t"+rule.Title)
			}
		}
	}
	return matches, cobra.ShellCompDirectiveNoFileComp
}
