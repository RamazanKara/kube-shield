package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile     string
	kubeconfig  string
	kubeContext string
	namespace   string
	outputFmt   string
	verbose     bool
)

var rootCmd = &cobra.Command{
	Use:   "kube-shield",
	Short: "Kubernetes Security Posture Manager",
	Long: `kube-shield is a Kubernetes security posture scanner for local reviews,
CI gates, and scheduled cluster checks.

It reads Kubernetes API objects and reports common workload, CIS, RBAC,
network policy, and secret configuration risks.

Features:
  • Interactive terminal dashboard for findings review
  • Workload, CIS, RBAC, network policy, and secrets scanners
  • Table, JSON, and SARIF output
  • Severity thresholds and CI-friendly exit codes
  • Optional AI explanations for high-risk findings`,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.kube-shield.yaml)")
	rootCmd.PersistentFlags().StringVar(&kubeconfig, "kubeconfig", "", "path to kubeconfig file (default is $KUBECONFIG or $HOME/.kube/config)")
	rootCmd.PersistentFlags().StringVar(&kubeContext, "context", "", "kubernetes context to use")
	rootCmd.PersistentFlags().StringVarP(&namespace, "namespace", "n", "", "namespace to scan (default: all namespaces)")
	rootCmd.PersistentFlags().StringVarP(&outputFmt, "output", "o", "table", "output format: table, json, sarif")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose output")

	_ = viper.BindPFlag("kubeconfig", rootCmd.PersistentFlags().Lookup("kubeconfig"))
	_ = viper.BindPFlag("context", rootCmd.PersistentFlags().Lookup("context"))
	_ = viper.BindPFlag("namespace", rootCmd.PersistentFlags().Lookup("namespace"))
	_ = viper.BindPFlag("output", rootCmd.PersistentFlags().Lookup("output"))
	_ = viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))

	// AI flags
	rootCmd.PersistentFlags().String("ai-provider", "", "AI provider: openai, ollama")
	rootCmd.PersistentFlags().String("ai-model", "", "AI model name (e.g., gpt-4o-mini, llama3.2)")
	rootCmd.PersistentFlags().String("ai-api-key", "", "AI provider API key")
	rootCmd.PersistentFlags().String("ai-endpoint", "", "AI provider endpoint URL")

	_ = viper.BindPFlag("ai.provider", rootCmd.PersistentFlags().Lookup("ai-provider"))
	_ = viper.BindPFlag("ai.model", rootCmd.PersistentFlags().Lookup("ai-model"))
	_ = viper.BindPFlag("ai.apikey", rootCmd.PersistentFlags().Lookup("ai-api-key"))
	_ = viper.BindPFlag("ai.endpoint", rootCmd.PersistentFlags().Lookup("ai-endpoint"))
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintln(os.Stderr, "Warning: could not determine home directory:", err)
			return
		}
		viper.AddConfigPath(home)
		viper.AddConfigPath(".")
		viper.SetConfigType("yaml")
		viper.SetConfigName(".kube-shield")
	}

	viper.SetEnvPrefix("KUBE_SHIELD")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	viper.AutomaticEnv()

	_ = viper.ReadInConfig()
}
