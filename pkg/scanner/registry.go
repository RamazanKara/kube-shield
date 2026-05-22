package scanner

import (
	"github.com/RamazanKara/kube-shield/pkg/scanner/cis"
	"github.com/RamazanKara/kube-shield/pkg/scanner/engine"
	"github.com/RamazanKara/kube-shield/pkg/scanner/netpol"
	"github.com/RamazanKara/kube-shield/pkg/scanner/rbac"
	"github.com/RamazanKara/kube-shield/pkg/scanner/secrets"
	"github.com/RamazanKara/kube-shield/pkg/scanner/workload"
)

// DefaultRegistry returns a registry with all built-in scanners registered.
func DefaultRegistry() *engine.Registry {
	registry := engine.NewRegistry()
	registry.Register(workload.New())
	registry.Register(cis.New())
	registry.Register(rbac.New())
	registry.Register(netpol.New())
	registry.Register(secrets.New())
	return registry
}
