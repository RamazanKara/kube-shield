package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/RamazanKara/kube-shield/pkg/ai"
	"github.com/RamazanKara/kube-shield/pkg/config"
	"github.com/RamazanKara/kube-shield/pkg/k8s"
	"github.com/RamazanKara/kube-shield/pkg/logging"
	"github.com/RamazanKara/kube-shield/pkg/report"
	"github.com/RamazanKara/kube-shield/pkg/scanner"
	"github.com/RamazanKara/kube-shield/pkg/scanner/engine"
	"github.com/spf13/cobra"
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
	cfg := config.Load()
	applyScanFlagOverrides(cmd.Flags(), cfg)
	if err := validateScanConfig(cfg); err != nil {
		return err
	}

	log := logging.New(cfg.Verbose, cfg.Output)

	// Create Kubernetes client
	k8sClient, err := k8s.NewClient(cfg.Kubeconfig, cfg.Context)
	if err != nil {
		return fmt.Errorf("failed to connect to cluster: %w", err)
	}

	log.Info("starting scan",
		"cluster", k8sClient.ServerURL,
		"context", k8sClient.Context,
		"namespace", cfg.Namespace,
	)

	fmt.Fprintf(os.Stderr, "🛡️  kube-shield — Kubernetes Security Posture Manager\n")
	fmt.Fprintf(os.Stderr, "   Cluster: %s (context: %s)\n", k8sClient.ServerURL, k8sClient.Context)
	if cfg.Namespace != "" {
		fmt.Fprintf(os.Stderr, "   Namespace: %s\n", cfg.Namespace)
	} else {
		fmt.Fprintf(os.Stderr, "   Namespace: all\n")
	}
	fmt.Fprintf(os.Stderr, "   Scanning...\n\n")

	// Register scanners using centralized registry
	registry := scanner.DefaultRegistry()

	// Create engine
	eng := engine.NewEngine(registry, 5)

	// Run scan with timeout and signal handling for graceful cancellation
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	var result *engine.Report
	if len(cfg.Scanners) > 0 {
		result, err = eng.Run(ctx, k8sClient.Clientset, cfg.Namespace, cfg.Scanners)
	} else {
		result, err = eng.RunAll(ctx, k8sClient.Clientset, cfg.Namespace)
	}
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	log.Debug("scan complete", "findings", len(result.Findings))

	// Filter by severity and category
	minSev := engine.SeverityFromString(cfg.Severity)
	var catFilter []engine.Category
	for _, c := range cfg.Categories {
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
	switch cfg.Output {
	case "json":
		if err := report.JSONWriter(os.Stdout, result); err != nil {
			return fmt.Errorf("failed to write JSON report: %w", err)
		}
	case "sarif":
		if err := report.SARIFWriter(os.Stdout, result); err != nil {
			return fmt.Errorf("failed to write SARIF report: %w", err)
		}
	case "table":
		if err := report.TableWriter(os.Stdout, result); err != nil {
			return fmt.Errorf("failed to write table report: %w", err)
		}
	}

	// AI-powered explanation for critical/high findings
	if cfg.AI.Provider != "" {
		aiCfg := ai.Config{
			Provider: cfg.AI.Provider,
			Model:    cfg.AI.Model,
			APIKey:   cfg.AI.APIKey,
			Endpoint: cfg.AI.Endpoint,
		}
		provider, aiErr := ai.NewProvider(aiCfg)
		if aiErr != nil {
			fmt.Fprintf(os.Stderr, "\n⚠️  AI provider error: %v\n", aiErr)
		} else {
			ai.AnalyzeFindings(ctx, os.Stderr, provider, result.Findings, ai.DefaultAnalyzeOptions())
		}
	}

	// Exit code
	if cfg.ExitCode && result.Summary.Total > 0 {
		return fmt.Errorf("findings detected: %d findings at or above %s severity (exit-code enabled)", result.Summary.Total, cfg.Severity)
	}

	return nil
}
