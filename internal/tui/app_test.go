package tui

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/RamazanKara/kube-shield/internal/scanner/engine"
	tea "github.com/charmbracelet/bubbletea"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

type tuiAIProvider struct {
	err error
}

func (p tuiAIProvider) Name() string { return "test-ai" }
func (p tuiAIProvider) Explain(ctx context.Context, finding engine.Finding) (string, error) {
	if p.err != nil {
		return "", p.err
	}
	return "ai explanation", nil
}

type tuiScanner struct{}

func (s tuiScanner) Name() string              { return "workload" }
func (s tuiScanner) Category() engine.Category { return engine.CategoryWorkload }
func (s tuiScanner) Description() string       { return "tui scanner" }
func (s tuiScanner) Scan(ctx context.Context, client kubernetes.Interface, namespace string) (*engine.ScanResult, error) {
	return &engine.ScanResult{
		Scanner: s.Name(),
		Findings: []engine.Finding{{
			CheckID:  "WL-010",
			Title:    "Refreshed privileged container",
			Severity: engine.SeverityCritical,
			Category: engine.CategoryWorkload,
			Resource: engine.Resource{Kind: "Pod", Name: "refreshed", Namespace: namespace},
		}},
	}, nil
}

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
	m := NewModel(report, "test-cluster", nil, nil, nil, "", nil, engine.ScannerOptions{}, nil)

	if m.activeTab != TabDashboard {
		t.Errorf("expected initial tab Dashboard, got %v", m.activeTab)
	}
	if m.report != report {
		t.Error("expected report to be set")
	}
	if m.clusterInfo != "test-cluster" {
		t.Errorf("expected clusterInfo 'test-cluster', got %q", m.clusterInfo)
	}
	if m.cursor != 0 {
		t.Errorf("expected cursor at 0, got %d", m.cursor)
	}
}

func TestFilteredFindings(t *testing.T) {
	report := testReport()
	m := NewModel(report, "test-cluster", nil, nil, nil, "", nil, engine.ScannerOptions{}, nil)

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
	m := NewModel(report, "test-cluster", nil, nil, nil, "", nil, engine.ScannerOptions{}, nil)

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

	// Risk chains tab — no cursor items
	m.activeTab = TabRiskChains
	if got := m.maxCursorItems(); got != 0 {
		t.Errorf("TabRiskChains: expected 0, got %d", got)
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
		{TabRiskChains, "Risk Chains"},
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
	m := NewModel(report, "test-cluster", nil, nil, nil, "", nil, engine.ScannerOptions{}, nil)

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
	m := NewModel(report, "test-cluster", nil, nil, nil, "", nil, engine.ScannerOptions{}, nil)
	m.activeTab = TabFindings

	output := m.renderFindings()
	if !strings.Contains(output, "No findings") {
		t.Error("expected empty findings message")
	}
}

func TestRenderFindings_WithFilter(t *testing.T) {
	report := testReport()
	m := NewModel(report, "test-cluster", nil, nil, nil, "", nil, engine.ScannerOptions{}, nil)
	m.filterText = "zzz-no-match"

	output := m.renderFindings()
	if !strings.Contains(output, "No findings match filter") {
		t.Error("expected filter no-match message")
	}
}

func TestRenderFindings_NarrowWidthDoesNotPanic(t *testing.T) {
	report := testReport()
	m := NewModel(report, "test-cluster", nil, nil, nil, "", nil, engine.ScannerOptions{}, nil)
	m.activeTab = TabFindings
	m.width = 0

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("renderFindings panicked with narrow width: %v", r)
		}
	}()

	output := m.renderFindings()
	if !strings.Contains(output, "SEVERITY") {
		t.Error("expected findings table header")
	}
}

func TestRenderFindingDetail(t *testing.T) {
	report := testReport()
	m := NewModel(report, "test-cluster", nil, nil, nil, "", nil, engine.ScannerOptions{}, nil)
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
	m := NewModel(report, "test-cluster", nil, nil, nil, "", nil, engine.ScannerOptions{}, nil)
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
	m := NewModel(report, "test-cluster", nil, nil, nil, "", nil, engine.ScannerOptions{}, nil)
	m.activeTab = TabNetwork

	output := m.renderNetworkPanel()
	if !strings.Contains(output, "Network Policy Analysis") {
		t.Error("expected network panel header")
	}
	if !strings.Contains(output, "default deny") {
		t.Error("expected network finding in panel")
	}
}

func TestRenderRiskChainsPanel(t *testing.T) {
	report := testReport()
	m := NewModel(report, "test-cluster", nil, nil, nil, "", nil, engine.ScannerOptions{}, nil)
	m.activeTab = TabRiskChains

	output := m.renderRiskChainsPanel()
	if !strings.Contains(output, "Risk Chains") {
		t.Error("expected risk chains header")
	}
	if strings.Contains(output, "Attack Path") {
		t.Error("risk chains panel should not refer to attack paths")
	}
}

func TestRenderHelp(t *testing.T) {
	report := testReport()
	m := NewModel(report, "test-cluster", nil, nil, nil, "", nil, engine.ScannerOptions{}, nil)

	output := m.renderHelp()
	if !strings.Contains(output, "Keyboard Shortcuts") {
		t.Error("expected keyboard shortcuts help")
	}
	if !strings.Contains(output, "Tab") {
		t.Error("expected Tab key in help")
	}
}

func TestUpdateViewAndContentRouting(t *testing.T) {
	report := testReport()
	m := NewModel(report, "test-cluster", nil, nil, nil, "", nil, engine.ScannerOptions{}, nil)

	if cmd := m.Init(); cmd != nil {
		t.Fatal("expected nil init command")
	}

	updated, cmd := m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	if cmd != nil {
		t.Fatal("expected no command for window size")
	}
	m = updated.(Model)
	if !m.ready {
		t.Fatal("expected model to be ready after window size")
	}
	if view := m.View(); !strings.Contains(view, "kube-shield") || !strings.Contains(view, "Cluster: test-cluster") {
		t.Fatalf("unexpected view output: %s", view)
	}

	for _, tab := range allTabs {
		m.activeTab = tab
		m.showHelp = false
		m.showDetail = false
		if content := m.renderContent(); content == "" {
			t.Fatalf("expected content for tab %s", tab)
		}
	}

	m.activeTab = TabFindings
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	if !m.showDetail {
		t.Fatal("expected enter on findings tab to open detail")
	}
	if content := m.renderContent(); !strings.Contains(content, "Remediation") {
		t.Fatalf("expected finding detail content, got: %s", content)
	}

	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = updated.(Model)
	if m.showDetail {
		t.Fatal("expected esc to close detail")
	}

	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = updated.(Model)
	if m.cursor != 1 {
		t.Fatalf("expected cursor to move down, got %d", m.cursor)
	}
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyUp})
	m = updated.(Model)
	if m.cursor != 0 {
		t.Fatalf("expected cursor to move up, got %d", m.cursor)
	}

	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'?'}})
	m = updated.(Model)
	if !m.showHelp || !strings.Contains(m.renderContent(), "Keyboard Shortcuts") {
		t.Fatal("expected help content after ? key")
	}

	updated, cmd = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	m = updated.(Model)
	if !m.filtering || cmd == nil {
		t.Fatal("expected slash key to enter filter mode with blink command")
	}
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	m = updated.(Model)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	if m.filtering || m.filterText != "r" {
		t.Fatalf("expected filter text to be applied, filtering=%t filter=%q", m.filtering, m.filterText)
	}
}

func TestUpdateAsyncAndNavigationBranches(t *testing.T) {
	registry := engine.NewRegistry()
	registry.Register(tuiScanner{})
	eng := engine.NewEngine(registry, 1)
	m := NewModel(testReport(), "test-cluster", tuiAIProvider{}, fake.NewSimpleClientset(), nil, "default", []string{"workload"}, engine.ScannerOptions{}, eng)
	updated, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	m = updated.(Model)

	updated, _ = m.Update(aiExplainMsg{result: "done"})
	m = updated.(Model)
	if m.aiResult != "done" {
		t.Fatalf("expected AI result, got %q", m.aiResult)
	}
	updated, _ = m.Update(aiExplainMsg{err: errors.New("offline")})
	m = updated.(Model)
	if !strings.Contains(m.aiResult, "AI error") {
		t.Fatalf("expected AI error, got %q", m.aiResult)
	}

	updated, _ = m.Update(refreshMsg{err: errors.New("forbidden")})
	m = updated.(Model)
	if !strings.Contains(m.aiResult, "Refresh error") {
		t.Fatalf("expected refresh error, got %q", m.aiResult)
	}
	updated, _ = m.Update(refreshMsg{report: testReport()})
	m = updated.(Model)
	if m.aiResult != "" || m.cursor != 0 {
		t.Fatalf("expected successful refresh to clear result and cursor, got result=%q cursor=%d", m.aiResult, m.cursor)
	}

	updated, _ = m.Update(tea.WindowSizeMsg{Width: 120, Height: 32})
	m = updated.(Model)
	if m.width != 120 || m.viewport.Width != 120 {
		t.Fatalf("expected resize to update viewport, width=%d viewport=%d", m.width, m.viewport.Width)
	}

	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyShiftTab})
	m = updated.(Model)
	if m.activeTab != TabRiskChains {
		t.Fatalf("expected shift-tab from dashboard to wrap to risk chains, got %s", m.activeTab)
	}
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyTab})
	m = updated.(Model)
	if m.activeTab != TabDashboard {
		t.Fatalf("expected tab from risk chains to wrap to dashboard, got %s", m.activeTab)
	}

	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	m = updated.(Model)
	if !m.filtering || cmd == nil {
		t.Fatal("expected filter mode")
	}
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = updated.(Model)
	if m.filtering {
		t.Fatal("expected escape to cancel filter mode")
	}

	m.activeTab = TabFindings
	m.showDetail = true
	updated, cmd = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e'}})
	m = updated.(Model)
	if !m.aiLoading || cmd == nil {
		t.Fatal("expected explain command")
	}
	updated, _ = m.Update(cmd())
	m = updated.(Model)
	if m.aiResult != "ai explanation" {
		t.Fatalf("expected async AI explanation, got %q", m.aiResult)
	}

	updated, cmd = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	m = updated.(Model)
	if !m.aiLoading || cmd == nil {
		t.Fatal("expected refresh command")
	}
	updated, _ = m.Update(cmd())
	m = updated.(Model)
	if len(m.report.Findings) != 1 || m.report.Findings[0].Resource.Name != "refreshed" {
		t.Fatalf("expected refreshed report, got %#v", m.report.Findings)
	}

	_, cmd = m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	if cmd == nil {
		t.Fatal("expected quit command")
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
	m := NewModel(report, "test-cluster", nil, nil, nil, "", nil, engine.ScannerOptions{}, nil)
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
	m := NewModel(report, "test-cluster", nil, nil, nil, "", nil, engine.ScannerOptions{}, nil)
	m.activeTab = TabNetwork

	output := m.renderNetworkPanel()
	if !strings.Contains(output, "look good") {
		t.Error("expected network looks good message")
	}
}
