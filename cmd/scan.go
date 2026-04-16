package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

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
		return fmt.Errorf("failed to connect to cluster: %w\n\nHint: Make sure your kubeconfig is valid and the cluster is reachable.\nUse --kubeconfig to specify a path or --context to select a context.", err)
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

	// Filter by severity
	minSev := engine.SeverityFromString(severity)
	result.Findings = engine.FilterFindings(result.Findings, minSev, nil, "")

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

	// Exit code
	if exitCode && result.Summary.Total > 0 {
		os.Exit(2)
	}

	return nil
}
