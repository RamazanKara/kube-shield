package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/RamazanKara/kube-shield/pkg/ai"
	"github.com/RamazanKara/kube-shield/pkg/tui"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"
)

var dashboardCmd = &cobra.Command{
	Use:   "dashboard",
	Short: "Launch the interactive security dashboard (TUI)",
	Long: `Launch an interactive terminal dashboard for reviewing scan findings.

The dashboard provides:
  • Security score overview with grade (A-F)
  • Findings explorer with drill-down details
  • RBAC and network policy finding panels
  • Risk chains derived from high-risk findings
  • Optional AI explanations for individual findings

Examples:
  kube-shield dashboard
  kube-shield dashboard --context production
  kube-shield dashboard -n kube-system`,
	RunE: runDashboard,
}

var dashboardScanners []string

func init() {
	dashboardCmd.Flags().StringSliceVar(&dashboardScanners, "scanners", nil, "comma-separated list of scanners to run (workload,cis,rbac,netpol,secrets)")
	rootCmd.AddCommand(dashboardCmd)
}

func runDashboard(cmd *cobra.Command, args []string) error {
	runtime, err := prepareScanRuntime(cmd, applyDashboardFlagOverrides, validateDashboardConfig)
	if err != nil {
		return err
	}
	cfg := runtime.cfg
	k8sClient := runtime.k8sClient

	fmt.Fprintf(os.Stderr, "🛡️  Scanning cluster %s...\n", k8sClient.ServerURL)

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	report, err := runtime.run(ctx)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Create AI provider if configured
	var aiProvider ai.Provider
	if cfg.AI.Provider != "" {
		aiCfg := ai.Config{
			Provider: cfg.AI.Provider,
			Model:    cfg.AI.Model,
			APIKey:   cfg.AI.APIKey,
			Endpoint: cfg.AI.Endpoint,
		}
		aiProvider, err = ai.NewProvider(aiCfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "⚠️  AI provider error: %v\n", err)
		}
	}

	clusterInfo := fmt.Sprintf("%s (%s)", k8sClient.Context, k8sClient.ServerURL)
	model := tui.NewModel(report, clusterInfo, aiProvider, k8sClient.Clientset, cfg.Namespace, cfg.Scanners, runtime.engine)

	p := tea.NewProgram(model, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		return fmt.Errorf("TUI error: %w", err)
	}

	return nil
}
