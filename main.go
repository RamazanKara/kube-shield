package main

//go:generate go run ./internal/cmd/gen-scanners-docs/main.go

import (
	"os"

	"github.com/RamazanKara/kube-shield/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
