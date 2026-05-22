package cmd

import (
	"fmt"

	"github.com/RamazanKara/kube-shield/pkg/version"
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version of kube-shield",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("kube-shield %s\n", version.Info())
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
