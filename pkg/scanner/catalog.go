package scanner

import (
	"sort"

	"github.com/RamazanKara/kube-shield/pkg/scanner/cis"
	"github.com/RamazanKara/kube-shield/pkg/scanner/engine"
	"github.com/RamazanKara/kube-shield/pkg/scanner/netpol"
	"github.com/RamazanKara/kube-shield/pkg/scanner/rbac"
	"github.com/RamazanKara/kube-shield/pkg/scanner/secrets"
	"github.com/RamazanKara/kube-shield/pkg/scanner/workload"
)

// Definition describes one built-in scanner and its public metadata.
type Definition struct {
	Name          string
	Category      engine.Category
	CheckCount    int
	SeverityRange string
	New           func() engine.Scanner
}

var builtIns = []Definition{
	{Name: "workload", Category: engine.CategoryWorkload, CheckCount: 17, SeverityRange: "Critical to Info", New: func() engine.Scanner { return workload.New() }},
	{Name: "cis", Category: engine.CategoryCIS, CheckCount: 14, SeverityRange: "Critical to Low", New: func() engine.Scanner { return cis.New() }},
	{Name: "rbac", Category: engine.CategoryRBAC, CheckCount: 12, SeverityRange: "Critical to Medium", New: func() engine.Scanner { return rbac.New() }},
	{Name: "netpol", Category: engine.CategoryNetpol, CheckCount: 6, SeverityRange: "High to Medium", New: func() engine.Scanner { return netpol.New() }},
	{Name: "secrets", Category: engine.CategorySecrets, CheckCount: 6, SeverityRange: "High to Info", New: func() engine.Scanner { return secrets.New() }},
}

// BuiltIns returns the built-in scanner definitions in registry order.
func BuiltIns() []Definition {
	defs := make([]Definition, len(builtIns))
	copy(defs, builtIns)
	return defs
}

// Names returns all built-in scanner names.
func Names() []string {
	names := make([]string, 0, len(builtIns))
	for _, def := range builtIns {
		names = append(names, def.Name)
	}
	return names
}

// Categories returns all built-in scanner categories.
func Categories() []engine.Category {
	categories := make([]engine.Category, 0, len(builtIns))
	for _, def := range builtIns {
		categories = append(categories, def.Category)
	}
	return categories
}

// NameSet returns a lookup set for built-in scanner names.
func NameSet() map[string]struct{} {
	set := make(map[string]struct{}, len(builtIns))
	for _, name := range Names() {
		set[name] = struct{}{}
	}
	return set
}

// CategorySet returns a lookup set for built-in scanner categories.
func CategorySet() map[string]struct{} {
	set := make(map[string]struct{}, len(builtIns))
	for _, category := range Categories() {
		set[string(category)] = struct{}{}
	}
	return set
}

// SortedNames returns all built-in scanner names in deterministic display order.
func SortedNames() []string {
	names := Names()
	sort.Strings(names)
	return names
}
