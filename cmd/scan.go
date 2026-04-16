package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/RamazanKara/kube-shield/pkg/ai"
	"github.com/RamazanKara/kube-shield/pkg/k8s"
	"github.com/RamazanKara/kube-shield/pkg/report"
	"github.com/RamazanKara/kube-shield/pkg/scanner/cis"
	"github.com/RamazanKara/kube-shield/pkg/scanner/engine"
	"github.com/RamazanKara/kube-shield/pkg/scanner/netpol"
	"github.com/RamazanKara/kube-shield/pkg/scanner/rbac"
	"github.com/RamazanKara/kube-shield/pkg/scanner/secrets"
	"github.com/RamazanKara/kube-shield/pkg/scanner/workload"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	scanners   []string
	severity   string
	timeout    time.Duration
	exitCode   bool
	categories []string
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan a Kubernetes cluster for security issues",
	Long: `Scan performs a comprehensive security analysis of your Kubernetes cluster.

By default, all scanners are enabled: workload, cis, rbac, netpol, secrets.
Use --scanners to run specific scanners only.

Examples:
  # Scan all namespaces with all scanners
  kube-shield scan

  # Scan a specific namespace
  kube-shield scan -n production

  # Run only RBAC and network policy checks
  kube-shield scan --scanners rbac,netpol

  # Output as JSON
  kube-shield scan -o json

  # Output as SARIF for GitHub Code Scanning
  kube-shield scan -o sarif > results.sarif

  # Use a specific kubeconfig context
  kube-shield scan --context staging-cluster

  # Fail CI if critical findings exist
  kube-shield scan --exit-code --severity critical`,
	RunE: runScan,
}

func init() {
	scanCmd.Flags().StringSliceVar(&scanners, "scanners", nil, "comma-separated list of scanners to run (workload,cis,rbac,netpol,secrets)")
	scanCmd.Flags().StringVar(&severity, "severity", "low", "minimum severity to report (critical,high,medium,low,info)")
	scanCmd.Flags().DurationVar(&timeout, "timeout", 5*time.Minute, "scan timeout")
	scanCmd.Flags().BoolVar(&exitCode, "exit-code", false, "exit with non-zero code if findings match severity threshold")
	scanCmd.Flags().StringSliceVar(&categories, "category", nil, "filter by category (workload,cis,rbac,netpol,secrets)")

	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	kubeconfigPath := viper.GetString("kubeconfig")
	contextName := viper.GetString("context")
	ns := viper.GetString("namespace")
	output := viper.GetString("output")

	// Create Kubernetes client
	k8sClient, err := k8s.NewClient(kubeconfigPath, contextName)
	if err != nil {
		return fmt.Errorf("failed to connect to cluster: %w", err)
	}

	fmt.Fprintf(os.Stderr, "🛡️  kube-shield — Kubernetes Security Posture Manager\n")
	fmt.Fprintf(os.Stderr, "   Cluster: %s (context: %s)\n", k8sClient.ServerURL, k8sClient.Context)
	if ns != "" {
		fmt.Fprintf(os.Stderr, "   Namespace: %s\n", ns)
	} else {
		fmt.Fprintf(os.Stderr, "   Namespace: all\n")
	}
	fmt.Fprintf(os.Stderr, "   Scanning...\n\n")

	// Register scanners
	registry := engine.NewRegistry()
	registry.Register(workload.New())
	registry.Register(cis.New())
	registry.Register(rbac.New())
	registry.Register(netpol.New())
	registry.Register(secrets.New())

	// Create engine
	eng := engine.NewEngine(registry, 5)

	// Run scan with timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var result *engine.Report
	if len(scanners) > 0 {
		result, err = eng.Run(ctx, k8sClient.Clientset, ns, scanners)
	} else {
		result, err = eng.RunAll(ctx, k8sClient.Clientset, ns)
	}
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Filter by severity and category
	minSev := engine.SeverityFromString(severity)
	var catFilter []engine.Category
	for _, c := range categories {
		catFilter = append(catFilter, engine.Category(c))
	}
	result.Findings = engine.FilterFindings(result.Findings, minSev, catFilter, "")

	// Recalculate summary after filtering
	result.Summary.Total = len(result.Findings)
	result.Summary.BySeverity = make(map[engine.Severity]int)
	result.Summary.ByCategory = make(map[engine.Category]int)
	for _, f := range result.Findings {
		result.Summary.BySeverity[f.Severity]++
		result.Summary.ByCategory[f.Category]++
	}

	// Output results
	switch output {
	case "json":
		if err := report.JSONWriter(os.Stdout, result); err != nil {
			return fmt.Errorf("failed to write JSON report: %w", err)
		}
	case "sarif":
		if err := report.SARIFWriter(os.Stdout, result); err != nil {
			return fmt.Errorf("failed to write SARIF report: %w", err)
		}
	default:
		if err := report.TableWriter(os.Stdout, result); err != nil {
			return fmt.Errorf("failed to write table report: %w", err)
		}
	}

	// AI-powered explanation for critical/high findings
	aiProvider := viper.GetString("ai.provider")
	if aiProvider != "" {
		aiCfg := ai.Config{
			Provider: aiProvider,
			Model:    viper.GetString("ai.model"),
			APIKey:   viper.GetString("ai.apikey"),
			Endpoint: viper.GetString("ai.endpoint"),
		}
		provider, aiErr := ai.NewProvider(aiCfg)
		if aiErr != nil {
			fmt.Fprintf(os.Stderr, "\n⚠️  AI provider error: %v\n", aiErr)
		} else {
			var critHigh []engine.Finding
			for _, f := range result.Findings {
				if f.Severity >= engine.SeverityHigh {
					critHigh = append(critHigh, f)
				}
			}
			if len(critHigh) > 0 {
				fmt.Fprintf(os.Stderr, "\n🤖 AI Analysis (%s):\n", provider.Name())
				limit := len(critHigh)
				if limit > 5 {
					limit = 5
				}
				for _, f := range critHigh[:limit] {
					aiCtx, aiCancel := context.WithTimeout(context.Background(), 30*time.Second)
					explanation, expErr := provider.Explain(aiCtx, f)
					aiCancel()
					if expErr != nil {
						fmt.Fprintf(os.Stderr, "  %s: AI error: %v\n", f.CheckID, expErr)
						continue
					}
					fmt.Fprintf(os.Stderr, "\n  📋 %s (%s)\n  %s\n", f.Title, f.CheckID, explanation)
				}
			}
		}
	}

	// Exit code
	if exitCode && result.Summary.Total > 0 {
		return fmt.Errorf("findings detected: %d findings at or above %s severity (exit-code enabled)", result.Summary.Total, severity)
	}

	return nil
}
