package scanner

import "github.com/RamazanKara/kube-shield/internal/scanner/engine"

// DefaultRegistry returns a registry with all built-in scanners registered.
func DefaultRegistry() *engine.Registry {
	registry := engine.NewRegistry()
	for _, def := range BuiltIns() {
		registry.Register(def.New())
	}
	return registry
}
