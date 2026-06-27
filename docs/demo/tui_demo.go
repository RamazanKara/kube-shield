//go:build ignore

package main

import (
	"time"

	"github.com/RamazanKara/kube-shield/pkg/scanner/engine"
	"github.com/RamazanKara/kube-shield/pkg/tui"
	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	findings := []engine.Finding{
		{
			ID:          "demo-workload-privileged",
			CheckID:     "WL-010",
			Title:       "Privileged container enabled",
			Description: "The api-gateway workload can access host-level capabilities.",
			Severity:    engine.SeverityCritical,
			Category:    engine.CategoryWorkload,
			Resource:    engine.Resource{Namespace: "payments", Kind: "Deployment", Name: "api-gateway"},
			Remediation: "Disable privileged mode, drop Linux capabilities, and enforce a restricted Pod Security profile.",
			CISRef:      "CIS Kubernetes Benchmark v1.12 5.2.1",
		},
		{
			ID:          "demo-rbac-cluster-admin",
			CheckID:     "RBAC-030",
			Title:       "Cluster-admin role bound to service account",
			Description: "A workload service account has unrestricted cluster-admin permissions.",
			Severity:    engine.SeverityCritical,
			Category:    engine.CategoryRBAC,
			Resource:    engine.Resource{Namespace: "payments", Kind: "ServiceAccount", Name: "reconciler"},
			Remediation: "Replace cluster-admin with narrowly scoped Roles and bind only the verbs and resources required.",
			CISRef:      "CIS Kubernetes Benchmark v1.12 5.1.1",
		},
		{
			ID:          "demo-secret-env",
			CheckID:     "SEC-001",
			Title:       "Secret exposed through environment variable",
			Description: "Database credentials are injected into the worker pod environment.",
			Severity:    engine.SeverityHigh,
			Category:    engine.CategorySecrets,
			Resource:    engine.Resource{Namespace: "payments", Kind: "Deployment", Name: "worker"},
			Remediation: "Mount secrets as files with least-privilege access and rotate credentials after remediation.",
		},
		{
			ID:          "demo-netpol-default-deny",
			CheckID:     "NET-001",
			Title:       "Namespace has no default-deny NetworkPolicy",
			Description: "Pods in the namespace can receive traffic unless another policy restricts them.",
			Severity:    engine.SeverityMedium,
			Category:    engine.CategoryNetpol,
			Resource:    engine.Resource{Namespace: "payments", Kind: "Namespace", Name: "payments"},
			Remediation: "Create default-deny ingress and egress policies, then allow required application flows.",
			CISRef:      "CIS Kubernetes Benchmark v1.12 5.3.2",
		},
		{
			ID:          "demo-cis-automount",
			CheckID:     "CIS-4.1.6",
			Title:       "Service account token automount is enabled",
			Description: "The default service account can mount API credentials into pods.",
			Severity:    engine.SeverityMedium,
			Category:    engine.CategoryCIS,
			Resource:    engine.Resource{Namespace: "payments", Kind: "ServiceAccount", Name: "default"},
			Remediation: "Set automountServiceAccountToken: false and create dedicated service accounts for workloads.",
			CISRef:      "CIS Kubernetes Benchmark v1.12 4.1.6",
		},
		{
			ID:          "demo-workload-root",
			CheckID:     "WL-011",
			Title:       "Container runs as root",
			Description: "The migration job starts as UID 0.",
			Severity:    engine.SeverityHigh,
			Category:    engine.CategoryWorkload,
			Resource:    engine.Resource{Namespace: "platform", Kind: "Job", Name: "schema-migrate"},
			Remediation: "Set runAsNonRoot: true and assign an explicit non-root runAsUser.",
		},
		{
			ID:          "demo-rbac-secrets",
			CheckID:     "RBAC-010",
			Title:       "Role allows broad secret reads",
			Description: "A namespace Role grants get/list/watch access to all secrets.",
			Severity:    engine.SeverityHigh,
			Category:    engine.CategoryRBAC,
			Resource:    engine.Resource{Namespace: "platform", Kind: "Role", Name: "support-read"},
			Remediation: "Remove broad secret permissions and expose only the specific data required by support workflows.",
		},
	}

	report := &engine.Report{
		Findings:    findings,
		Summary:     engine.SummarizeFindings(findings),
		GeneratedAt: time.Now(),
		ClusterInfo: "kind-kube-shield-demo",
	}

	model := tui.NewModel(report, "kind-kube-shield-demo (https://127.0.0.1:6443)", nil, nil, nil, "", nil, engine.ScannerOptions{}, nil)
	program := tea.NewProgram(model, tea.WithAltScreen())
	if _, err := program.Run(); err != nil {
		panic(err)
	}
}
