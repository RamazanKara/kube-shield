package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/RamazanKara/kube-shield/pkg/k8s"
	"github.com/RamazanKara/kube-shield/pkg/scanner/cis"
	"github.com/RamazanKara/kube-shield/pkg/scanner/engine"
	"github.com/RamazanKara/kube-shield/pkg/scanner/netpol"
	"github.com/RamazanKara/kube-shield/pkg/scanner/rbac"
	"github.com/RamazanKara/kube-shield/pkg/scanner/secrets"
	"github.com/RamazanKara/kube-shield/pkg/scanner/workload"
	"github.com/RamazanKara/kube-shield/pkg/tui"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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

func init() {
	rootCmd.AddCommand(dashboardCmd)
}

func runDashboard(cmd *cobra.Command, args []string) error {
	kubeconfigPath := viper.GetString("kubeconfig")
	contextName := viper.GetString("context")
	ns := viper.GetString("namespace")

	k8sClient, err := k8s.NewClient(kubeconfigPath, contextName)
	if err != nil {
		return fmt.Errorf("failed to connect to cluster: %w", err)
	}

	fmt.Fprintf(os.Stderr, "🛡️  Scanning cluster %s...\n", k8sClient.ServerURL)

	registry := engine.NewRegistry()
	registry.Register(workload.New())
	registry.Register(cis.New())
	registry.Register(rbac.New())
	registry.Register(netpol.New())
	registry.Register(secrets.New())

	eng := engine.NewEngine(registry, 5)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	report, err := eng.RunAll(ctx, k8sClient.Clientset, ns)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	clusterInfo := fmt.Sprintf("%s (%s)", k8sClient.Context, k8sClient.ServerURL)
	model := tui.NewModel(report, clusterInfo)

	p := tea.NewProgram(model, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		return fmt.Errorf("TUI error: %w", err)
	}

	return nil
}
