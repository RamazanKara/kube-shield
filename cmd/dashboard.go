package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/RamazanKara/kube-shield/pkg/ai"
	"github.com/RamazanKara/kube-shield/pkg/config"
	"github.com/RamazanKara/kube-shield/pkg/k8s"
	"github.com/RamazanKara/kube-shield/pkg/scanner"
	"github.com/RamazanKara/kube-shield/pkg/scanner/engine"
	"github.com/RamazanKara/kube-shield/pkg/tui"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"
)

var dashboardCmd = &cobra.Command{
	Use:   "dashboard",
	Short: "Launch the interactive security dashboard (TUI)",
	Long: `Launch a beautiful interactive terminal UI to explore security findings.

The dashboard provides:
  • Security score overview with grade (A-F)
  • Findings explorer with drill-down details
  • RBAC analysis panel
  • Network policy visualization
  • Attack path graph

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
	cfg := config.Load()
	applyDashboardFlagOverrides(cmd.Flags(), cfg)
	if err := validateDashboardConfig(cfg); err != nil {
		return err
	}

	k8sClient, err := k8s.NewClient(cfg.Kubeconfig, cfg.Context)
	if err != nil {
		return fmt.Errorf("failed to connect to cluster: %w", err)
	}

	fmt.Fprintf(os.Stderr, "🛡️  Scanning cluster %s...\n", k8sClient.ServerURL)

	registry := scanner.DefaultRegistry()

	eng := engine.NewEngine(registry, 5)

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	var report *engine.Report
	if len(cfg.Scanners) > 0 {
		report, err = eng.Run(ctx, k8sClient.Clientset, cfg.Namespace, cfg.Scanners)
	} else {
		report, err = eng.RunAll(ctx, k8sClient.Clientset, cfg.Namespace)
	}
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
	model := tui.NewModel(report, clusterInfo, aiProvider, k8sClient.Clientset, cfg.Namespace, eng)

	p := tea.NewProgram(model, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		return fmt.Errorf("TUI error: %w", err)
	}

	return nil
}
