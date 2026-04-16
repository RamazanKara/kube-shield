package main

import (
	"os"

	"github.com/RamazanKara/kube-shield/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
