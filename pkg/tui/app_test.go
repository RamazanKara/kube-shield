package tui

import (
	"strings"
	"testing"

	"github.com/RamazanKara/kube-shield/pkg/scanner/engine"
)

func testReport() *engine.Report {
	return &engine.Report{
		Findings: []engine.Finding{
			{
				CheckID:     "WL-010",
				Title:       "Privileged container",
				Severity:    engine.SeverityCritical,
				Category:    engine.CategoryWorkload,
				Description: "Container is running in privileged mode",
				Remediation: "Set securityContext.privileged to false",
				Resource:    engine.Resource{Kind: "Pod", Name: "test-pod", Namespace: "default"},
			},
			{
				CheckID:  "RBAC-030",
				Title:    "ServiceAccount bound to cluster-admin",
				Severity: engine.SeverityCritical,
				Category: engine.CategoryRBAC,
				Resource: engine.Resource{Kind: "ClusterRoleBinding", Name: "admin-binding"},
			},
			{
				CheckID:  "NET-001",
				Title:    "No default deny ingress",
				Severity: engine.SeverityHigh,
				Category: engine.CategoryNetpol,
				Resource: engine.Resource{Kind: "Namespace", Name: "default"},
			},
			{
				CheckID:  "SEC-001",
				Title:    "Secret in env var",
				Severity: engine.SeverityMedium,
				Category: engine.CategorySecrets,
				Resource: engine.Resource{Kind: "Pod", Name: "app-pod", Namespace: "staging"},
			},
			{
				CheckID:  "CIS-4.1.6",
				Title:    "CIS RBAC check",
				Severity: engine.SeverityHigh,
				Category: engine.CategoryCIS,
				Resource: engine.Resource{Kind: "ClusterRole", Name: "wide-role"},
			},
			{
				CheckID:  "CIS-4.3.2",
				Title:    "CIS network check",
				Severity: engine.SeverityMedium,
				Category: engine.CategoryCIS,
				Resource: engine.Resource{Kind: "Namespace", Name: "dev"},
			},
		},
		Summary: engine.Summary{
			Total:      6,
			BySeverity: map[engine.Severity]int{engine.SeverityCritical: 2, engine.SeverityHigh: 2, engine.SeverityMedium: 2},
			ByCategory: map[engine.Category]int{engine.CategoryWorkload: 1, engine.CategoryRBAC: 1, engine.CategoryNetpol: 1, engine.CategorySecrets: 1, engine.CategoryCIS: 2},
			Score:      45.0,
			Grade:      "D",
		},
	}
}

func TestNewModel(t *testing.T) {
	report := testReport()
	m := NewModel(report, "test-cluster", nil, nil, "", nil)

	if m.activeTab != TabDashboard {
		t.Errorf("expected initial tab Dashboard, got %v", m.activeTab)
	}
	if m.report != report {
		t.Error("expected report to be set")
	}
	if m.clusterInfo != "test-cluster" {
		t.Errorf("expected clusterInfo 'test-cluster', got %q", m.clusterInfo)
	}
	if m.graphCache == nil {
		t.Error("expected graphCache to be initialized")
	}
	if m.cursor != 0 {
		t.Errorf("expected cursor at 0, got %d", m.cursor)
	}
}

func TestFilteredFindings(t *testing.T) {
	report := testReport()
	m := NewModel(report, "test-cluster", nil, nil, "", nil)

	// No filter — return all
	all := m.filteredFindings()
	if len(all) != 6 {
		t.Errorf("expected 6 findings with no filter, got %d", len(all))
	}

	// Filter by name
	m.filterText = "test-pod"
	filtered := m.filteredFindings()
	if len(filtered) != 1 {
		t.Errorf("expected 1 finding matching 'test-pod', got %d", len(filtered))
	}
	if filtered[0].CheckID != "WL-010" {
		t.Errorf("expected WL-010, got %s", filtered[0].CheckID)
	}

	// Filter by severity
	m.filterText = "critical"
	filtered = m.filteredFindings()
	if len(filtered) != 2 {
		t.Errorf("expected 2 critical findings, got %d", len(filtered))
	}

	// Filter by namespace
	m.filterText = "staging"
	filtered = m.filteredFindings()
	if len(filtered) != 1 {
		t.Errorf("expected 1 finding in staging, got %d", len(filtered))
	}

	// Filter by check ID
	m.filterText = "CIS-4.1"
	filtered = m.filteredFindings()
	if len(filtered) != 1 {
		t.Errorf("expected 1 CIS-4.1 finding, got %d", len(filtered))
	}

	// No match
	m.filterText = "nonexistent"
	filtered = m.filteredFindings()
	if len(filtered) != 0 {
		t.Errorf("expected 0 findings, got %d", len(filtered))
	}
}

func TestMaxCursorItems(t *testing.T) {
	report := testReport()
	m := NewModel(report, "test-cluster", nil, nil, "", nil)

	// Findings tab — all 6
	m.activeTab = TabFindings
	if got := m.maxCursorItems(); got != 6 {
		t.Errorf("TabFindings: expected 6, got %d", got)
	}

	// Findings tab with filter
	m.filterText = "critical"
	if got := m.maxCursorItems(); got != 2 {
		t.Errorf("TabFindings filtered: expected 2, got %d", got)
	}
	m.filterText = ""

	// RBAC tab — CategoryRBAC (1) + CIS-4.1 prefix (1) = 2
	m.activeTab = TabRBAC
	if got := m.maxCursorItems(); got != 2 {
		t.Errorf("TabRBAC: expected 2, got %d", got)
	}

	// Network tab — CategoryNetpol (1) + CIS-4.3 prefix (1) = 2
	m.activeTab = TabNetwork
	if got := m.maxCursorItems(); got != 2 {
		t.Errorf("TabNetwork: expected 2, got %d", got)
	}

	// Dashboard tab — no cursor items
	m.activeTab = TabDashboard
	if got := m.maxCursorItems(); got != 0 {
		t.Errorf("TabDashboard: expected 0, got %d", got)
	}

	// Graph tab — no cursor items
	m.activeTab = TabGraph
	if got := m.maxCursorItems(); got != 0 {
		t.Errorf("TabGraph: expected 0, got %d", got)
	}
}

func TestTabString(t *testing.T) {
	tests := []struct {
		tab  Tab
		want string
	}{
		{TabDashboard, "Dashboard"},
		{TabFindings, "Findings"},
		{TabRBAC, "RBAC"},
		{TabNetwork, "Network"},
		{TabGraph, "Attack Paths"},
		{Tab(99), "Unknown"},
	}
	for _, tt := range tests {
		if got := tt.tab.String(); got != tt.want {
			t.Errorf("Tab(%d).String() = %q, want %q", tt.tab, got, tt.want)
		}
	}
}

func TestRenderDashboard(t *testing.T) {
	report := testReport()
	m := NewModel(report, "test-cluster", nil, nil, "", nil)

	output := m.renderDashboard()
	if !strings.Contains(output, "Security Grade") {
		t.Error("expected dashboard to contain 'Security Grade'")
	}
	if !strings.Contains(output, "Critical") {
		t.Error("expected dashboard to contain 'Critical'")
	}
	if !strings.Contains(output, "Findings Summary") {
		t.Error("expected dashboard to contain 'Findings Summary'")
	}
}

func TestRenderFindings_Empty(t *testing.T) {
	report := &engine.Report{
		Summary: engine.Summary{
			BySeverity: make(map[engine.Severity]int),
			ByCategory: make(map[engine.Category]int),
		},
	}
	m := NewModel(report, "test-cluster", nil, nil, "", nil)
	m.activeTab = TabFindings

	output := m.renderFindings()
	if !strings.Contains(output, "No findings") {
		t.Error("expected empty findings message")
	}
}

func TestRenderFindings_WithFilter(t *testing.T) {
	report := testReport()
	m := NewModel(report, "test-cluster", nil, nil, "", nil)
	m.filterText = "zzz-no-match"

	output := m.renderFindings()
	if !strings.Contains(output, "No findings match filter") {
		t.Error("expected filter no-match message")
	}
}

func TestRenderFindingDetail(t *testing.T) {
	report := testReport()
	m := NewModel(report, "test-cluster", nil, nil, "", nil)
	m.activeTab = TabFindings
	m.showDetail = true
	m.cursor = 0

	output := m.renderFindingDetail()
	if !strings.Contains(output, "Privileged container") {
		t.Error("expected finding title in detail")
	}
	if !strings.Contains(output, "WL-010") {
		t.Error("expected check ID in detail")
	}
	if !strings.Contains(output, "Remediation") {
		t.Error("expected remediation in detail")
	}
}

func TestRenderRBACPanel(t *testing.T) {
	report := testReport()
	m := NewModel(report, "test-cluster", nil, nil, "", nil)
	m.activeTab = TabRBAC

	output := m.renderRBACPanel()
	if !strings.Contains(output, "RBAC Security Analysis") {
		t.Error("expected RBAC panel header")
	}
	if !strings.Contains(output, "cluster-admin") {
		t.Error("expected cluster-admin finding in RBAC panel")
	}
}

func TestRenderNetworkPanel(t *testing.T) {
	report := testReport()
	m := NewModel(report, "test-cluster", nil, nil, "", nil)
	m.activeTab = TabNetwork

	output := m.renderNetworkPanel()
	if !strings.Contains(output, "Network Policy Analysis") {
		t.Error("expected network panel header")
	}
	if !strings.Contains(output, "default deny") {
		t.Error("expected network finding in panel")
	}
}

func TestRenderGraphPanel(t *testing.T) {
	report := testReport()
	m := NewModel(report, "test-cluster", nil, nil, "", nil)
	m.activeTab = TabGraph

	output := m.renderGraphPanel()
	if !strings.Contains(output, "Attack Path") {
		t.Error("expected attack path header")
	}
}

func TestRenderHelp(t *testing.T) {
	report := testReport()
	m := NewModel(report, "test-cluster", nil, nil, "", nil)

	output := m.renderHelp()
	if !strings.Contains(output, "Keyboard Shortcuts") {
		t.Error("expected keyboard shortcuts help")
	}
	if !strings.Contains(output, "Tab") {
		t.Error("expected Tab key in help")
	}
}

func TestRenderRBACPanel_NoFindings(t *testing.T) {
	report := &engine.Report{
		Findings: []engine.Finding{
			{CheckID: "WL-010", Category: engine.CategoryWorkload, Severity: engine.SeverityCritical},
		},
		Summary: engine.Summary{
			BySeverity: make(map[engine.Severity]int),
			ByCategory: make(map[engine.Category]int),
		},
	}
	m := NewModel(report, "test-cluster", nil, nil, "", nil)
	m.activeTab = TabRBAC

	output := m.renderRBACPanel()
	if !strings.Contains(output, "No RBAC issues") {
		t.Error("expected no RBAC issues message")
	}
}

func TestRenderNetworkPanel_NoFindings(t *testing.T) {
	report := &engine.Report{
		Findings: []engine.Finding{
			{CheckID: "WL-010", Category: engine.CategoryWorkload, Severity: engine.SeverityCritical},
		},
		Summary: engine.Summary{
			BySeverity: make(map[engine.Severity]int),
			ByCategory: make(map[engine.Category]int),
		},
	}
	m := NewModel(report, "test-cluster", nil, nil, "", nil)
	m.activeTab = TabNetwork

	output := m.renderNetworkPanel()
	if !strings.Contains(output, "look good") {
		t.Error("expected network looks good message")
	}
}
