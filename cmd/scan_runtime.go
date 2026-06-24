package cmd

import (
	"context"
	"fmt"

	"github.com/RamazanKara/kube-shield/pkg/config"
	"github.com/RamazanKara/kube-shield/pkg/k8s"
	"github.com/RamazanKara/kube-shield/pkg/scanner"
	"github.com/RamazanKara/kube-shield/pkg/scanner/engine"
	"github.com/spf13/cobra"
)

type scanRuntime struct {
	cfg       *config.Config
	k8sClient *k8s.Client
	engine    *engine.Engine
}

func prepareScanRuntime(cmd *cobra.Command, applyOverrides func(changedFlags, *config.Config), validate func(*config.Config) error) (*scanRuntime, error) {
	cfg := config.Load()
	applyOverrides(cmd.Flags(), cfg)
	if err := validate(cfg); err != nil {
		return nil, err
	}

	k8sClient, err := k8s.NewClient(cfg.Kubeconfig, cfg.Context)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to cluster: %w", err)
	}

	return &scanRuntime{
		cfg:       cfg,
		k8sClient: k8sClient,
		engine:    engine.NewEngine(scanner.DefaultRegistry(), 5),
	}, nil
}

func (r *scanRuntime) run(ctx context.Context) (*engine.Report, error) {
	if len(r.cfg.Scanners) > 0 {
		return r.engine.Run(ctx, r.k8sClient.Clientset, r.cfg.Namespace, r.cfg.Scanners)
	}
	return r.engine.RunAll(ctx, r.k8sClient.Clientset, r.cfg.Namespace)
}
