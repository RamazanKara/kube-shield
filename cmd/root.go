package cmd

import (
	"fmt"
	"os"

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

	// Version info (set at build time via ldflags)
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

var rootCmd = &cobra.Command{
	Use:   "kube-shield",
	Short: "Kubernetes Security Posture Manager",
	Long: `kube-shield is a comprehensive Kubernetes security posture management tool.

It scans your clusters for security issues including CIS benchmark violations,
RBAC misconfigurations, network policy gaps, secret exposure, and more.

Features:
  • Beautiful interactive terminal UI (TUI)
  • Deep RBAC analysis with effective permissions resolution
  • Network policy validation and connectivity mapping
  • AI-powered remediation suggestions
  • Attack path visualization
  • Multi-cluster support
  • SARIF output for GitHub Code Scanning integration`,
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
	rootCmd.PersistentFlags().String("ai-model", "", "AI model name (e.g., gpt-4, llama3)")
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
	viper.AutomaticEnv()

	_ = viper.ReadInConfig()
}
