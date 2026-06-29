package main

//go:generate go run ../../internal/tools/gen-scanners-docs/main.go

import (
	"os"

	"github.com/RamazanKara/kube-shield/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
