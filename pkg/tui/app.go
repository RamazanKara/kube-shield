package tui

import (
	"fmt"
	"strings"

	"github.com/RamazanKara/kube-shield/pkg/scanner/engine"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Tab represents a navigation tab.
type Tab int

const (
	TabDashboard Tab = iota
	TabFindings
	TabRBAC
	TabNetwork
	TabGraph
)

func (t Tab) String() string {
	switch t {
	case TabDashboard:
		return "Dashboard"
	case TabFindings:
		return "Findings"
	case TabRBAC:
		return "RBAC"
	case TabNetwork:
		return "Network"
	case TabGraph:
		return "Attack Paths"
	default:
		return "Unknown"
	}
}

// KeyMap defines the keybindings.
type KeyMap struct {
	Quit      key.Binding
	Tab       key.Binding
	ShiftTab  key.Binding
	Up        key.Binding
	Down      key.Binding
	Enter     key.Binding
	Back      key.Binding
	Filter    key.Binding
	Help      key.Binding
	Refresh   key.Binding
}

var keys = KeyMap{
	Quit:     key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "quit")),
	Tab:      key.NewBinding(key.WithKeys("tab"), key.WithHelp("tab", "next tab")),
	ShiftTab: key.NewBinding(key.WithKeys("shift+tab"), key.WithHelp("shift+tab", "prev tab")),
	Up:       key.NewBinding(key.WithKeys("up", "k"), key.WithHelp("↑/k", "up")),
	Down:     key.NewBinding(key.WithKeys("down", "j"), key.WithHelp("↓/j", "down")),
	Enter:    key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "select")),
	Back:     key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "back")),
	Filter:   key.NewBinding(key.WithKeys("/"), key.WithHelp("/", "filter")),
	Help:     key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "help")),
	Refresh:  key.NewBinding(key.WithKeys("r"), key.WithHelp("r", "refresh")),
}

// Model is the main TUI model.
type Model struct {
	report      *engine.Report
	clusterInfo string
	activeTab   Tab
	width       int
	height      int
	cursor      int
	viewport    viewport.Model
	showDetail  bool
	showHelp    bool
	ready       bool
}

// NewModel creates a new TUI model.
func NewModel(report *engine.Report, clusterInfo string) Model {
	return Model{
		report:      report,
		clusterInfo: clusterInfo,
		activeTab:   TabDashboard,
	}
}

func (m Model) Init() tea.Cmd {
	return nil
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		if !m.ready {
			m.viewport = viewport.New(msg.Width, msg.Height-6)
			m.ready = true
		} else {
			m.viewport.Width = msg.Width
			m.viewport.Height = msg.Height - 6
		}
		m.viewport.SetContent(m.renderContent())
		return m, nil

	case tea.KeyMsg:
		switch {
		case key.Matches(msg, keys.Quit):
			return m, tea.Quit

		case key.Matches(msg, keys.Tab):
			m.activeTab = Tab((int(m.activeTab) + 1) % 5)
			m.cursor = 0
			m.showDetail = false
			m.viewport.SetContent(m.renderContent())
			m.viewport.GotoTop()
			return m, nil

		case key.Matches(msg, keys.ShiftTab):
			m.activeTab = Tab((int(m.activeTab) + 4) % 5)
			m.cursor = 0
			m.showDetail = false
			m.viewport.SetContent(m.renderContent())
			m.viewport.GotoTop()
			return m, nil

		case key.Matches(msg, keys.Up):
			if m.cursor > 0 {
				m.cursor--
			}
			m.viewport.SetContent(m.renderContent())
			return m, nil

		case key.Matches(msg, keys.Down):
			maxItems := m.maxCursorItems()
			if m.cursor < maxItems-1 {
				m.cursor++
			}
			m.viewport.SetContent(m.renderContent())
			return m, nil

		case key.Matches(msg, keys.Enter):
			if m.activeTab == TabFindings && !m.showDetail {
				m.showDetail = true
				m.viewport.SetContent(m.renderContent())
				m.viewport.GotoTop()
			}
			return m, nil

		case key.Matches(msg, keys.Back):
			if m.showDetail {
				m.showDetail = false
				m.viewport.SetContent(m.renderContent())
			}
			return m, nil

		case key.Matches(msg, keys.Help):
			m.showHelp = !m.showHelp
			m.viewport.SetContent(m.renderContent())
			return m, nil
		}
	}

	var cmd tea.Cmd
	m.viewport, cmd = m.viewport.Update(msg)
	return m, cmd
}

func (m Model) View() string {
	if !m.ready {
		return "\n  Initializing..."
	}

	// Header
	header := m.renderHeader()

	// Tabs
	tabs := m.renderTabs()

	// Content via viewport
	content := m.viewport.View()

	// Status bar
	statusBar := m.renderStatusBar()

	return lipgloss.JoinVertical(lipgloss.Left,
		header,
		tabs,
		content,
		statusBar,
	)
}

func (m Model) renderHeader() string {
	logo := titleStyle.Render("🛡️  kube-shield")
	info := headerStyle.Render(fmt.Sprintf("Cluster: %s", m.clusterInfo))
	return lipgloss.JoinHorizontal(lipgloss.Center, logo, "  ", info)
}

func (m Model) renderTabs() string {
	tabs := []Tab{TabDashboard, TabFindings, TabRBAC, TabNetwork, TabGraph}
	var rendered []string
	for _, t := range tabs {
		if t == m.activeTab {
			rendered = append(rendered, tabActiveStyle.Render(t.String()))
		} else {
			rendered = append(rendered, tabInactiveStyle.Render(t.String()))
		}
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, rendered...)
}

func (m Model) renderStatusBar() string {
	help := "tab: switch  ↑↓/jk: navigate  enter: select  esc: back  ?: help  q: quit"
	return statusBarStyle.Render(help)
}

func (m Model) renderContent() string {
	if m.showHelp {
		return m.renderHelp()
	}

	switch m.activeTab {
	case TabDashboard:
		return m.renderDashboard()
	case TabFindings:
		if m.showDetail {
			return m.renderFindingDetail()
		}
		return m.renderFindings()
	case TabRBAC:
		return m.renderRBACPanel()
	case TabNetwork:
		return m.renderNetworkPanel()
	case TabGraph:
		return m.renderGraphPanel()
	default:
		return "Unknown tab"
	}
}

func (m Model) renderDashboard() string {
	var sb strings.Builder

	// Security Score
	grade := m.report.Summary.Grade
	score := m.report.Summary.Score
	gs := gradeStyle(grade)

	scoreCard := fmt.Sprintf(
		"  Security Grade: %s  Score: %.0f/100\n",
		gs.Render(grade),
		score,
	)
	sb.WriteString("\n")
	sb.WriteString(cardStyle.Render(scoreCard))
	sb.WriteString("\n\n")

	// Severity breakdown
	severityCard := fmt.Sprintf(
		"  Findings Summary\n\n"+
			"  %s  Critical: %d\n"+
			"  %s  High:     %d\n"+
			"  %s  Medium:   %d\n"+
			"  %s  Low:      %d\n"+
			"  %s  Info:     %d\n"+
			"\n  Total: %d findings",
		criticalStyle.Render("●"), m.report.Summary.BySeverity[engine.SeverityCritical],
		highStyle.Render("●"), m.report.Summary.BySeverity[engine.SeverityHigh],
		mediumStyle.Render("●"), m.report.Summary.BySeverity[engine.SeverityMedium],
		lowStyle.Render("●"), m.report.Summary.BySeverity[engine.SeverityLow],
		infoStyle.Render("●"), m.report.Summary.BySeverity[engine.SeverityInfo],
		m.report.Summary.Total,
	)
	sb.WriteString(cardStyle.Render(severityCard))
	sb.WriteString("\n\n")

	// Category breakdown
	categoryCard := "  Findings by Category\n\n"
	for cat, count := range m.report.Summary.ByCategory {
		bar := strings.Repeat("█", min(count, 40))
		categoryCard += fmt.Sprintf("  %-10s %s %d\n", cat, bar, count)
	}
	sb.WriteString(cardStyle.Render(categoryCard))
	sb.WriteString("\n\n")

	// Top critical findings
	var criticals []engine.Finding
	for _, f := range m.report.Findings {
		if f.Severity == engine.SeverityCritical {
			criticals = append(criticals, f)
		}
	}
	if len(criticals) > 0 {
		topCard := "  🔴 Critical Findings (fix these first!)\n\n"
		for i, f := range criticals {
			if i >= 5 {
				topCard += fmt.Sprintf("  ... and %d more\n", len(criticals)-5)
				break
			}
			topCard += fmt.Sprintf("  • %s\n    %s\n\n", f.Title, f.Resource.String())
		}
		sb.WriteString(cardStyle.Render(topCard))
	}

	return sb.String()
}

func (m Model) renderFindings() string {
	if len(m.report.Findings) == 0 {
		return cardStyle.Render("\n  ✅ No findings! Your cluster is secure.\n")
	}

	var sb strings.Builder
	sb.WriteString("\n")

	header := fmt.Sprintf("  %-10s %-12s %-35s %s", "SEVERITY", "CHECK", "RESOURCE", "TITLE")
	sb.WriteString(headerStyle.Render(header))
	sb.WriteString("\n")
	sb.WriteString("  " + strings.Repeat("─", m.width-4) + "\n")

	for i, f := range m.report.Findings {
		resource := f.Resource.String()
		if len(resource) > 33 {
			resource = resource[:30] + "..."
		}
		title := f.Title
		if len(title) > 40 {
			title = title[:37] + "..."
		}

		sev := severityStyle(f.Severity.String()).Render(fmt.Sprintf("%-10s", f.Severity))
		line := fmt.Sprintf("  %s %-12s %-35s %s", sev, f.CheckID, resource, title)

		if i == m.cursor {
			sb.WriteString(selectedStyle.Render(line))
		} else {
			sb.WriteString(line)
		}
		sb.WriteString("\n")
	}

	sb.WriteString(fmt.Sprintf("\n  Showing %d findings. Press Enter for details.", len(m.report.Findings)))
	return sb.String()
}

func (m Model) renderFindingDetail() string {
	if m.cursor >= len(m.report.Findings) {
		return "No finding selected"
	}

	f := m.report.Findings[m.cursor]
	sev := severityStyle(f.Severity.String()).Render(f.Severity.String())

	detail := fmt.Sprintf(
		"  Finding Detail\n\n"+
			"  Title:       %s\n"+
			"  Severity:    %s\n"+
			"  Check ID:    %s\n"+
			"  Category:    %s\n"+
			"  Resource:    %s\n"+
			"  CIS Ref:     %s\n\n"+
			"  Description:\n  %s\n\n"+
			"  Remediation:\n  %s",
		f.Title,
		sev,
		f.CheckID,
		f.Category,
		f.Resource.String(),
		f.CISRef,
		f.Description,
		f.Remediation,
	)

	return "\n" + cardStyle.Render(detail)
}

func (m Model) renderRBACPanel() string {
	var sb strings.Builder
	sb.WriteString("\n")

	// Filter RBAC findings
	var rbacFindings []engine.Finding
	for _, f := range m.report.Findings {
		if f.Category == engine.CategoryRBAC || (f.Category == engine.CategoryCIS && strings.HasPrefix(f.CheckID, "CIS-4.1")) {
			rbacFindings = append(rbacFindings, f)
		}
	}

	if len(rbacFindings) == 0 {
		return cardStyle.Render("\n  ✅ No RBAC issues found.\n")
	}

	header := "  RBAC Security Analysis\n\n"
	header += fmt.Sprintf("  %d RBAC-related findings\n\n", len(rbacFindings))

	for i, f := range rbacFindings {
		sev := severityStyle(f.Severity.String()).Render(f.Severity.String())
		if i == m.cursor {
			header += selectedStyle.Render(fmt.Sprintf("  %s  %s - %s", sev, f.Resource.String(), f.Title)) + "\n"
		} else {
			header += fmt.Sprintf("  %s  %s - %s\n", sev, f.Resource.String(), f.Title)
		}
	}

	sb.WriteString(cardStyle.Render(header))
	return sb.String()
}

func (m Model) renderNetworkPanel() string {
	var sb strings.Builder
	sb.WriteString("\n")

	var netFindings []engine.Finding
	for _, f := range m.report.Findings {
		if f.Category == engine.CategoryNetpol || (f.Category == engine.CategoryCIS && strings.HasPrefix(f.CheckID, "CIS-4.3")) {
			netFindings = append(netFindings, f)
		}
	}

	if len(netFindings) == 0 {
		return cardStyle.Render("\n  ✅ Network policies look good.\n")
	}

	header := "  Network Policy Analysis\n\n"
	header += fmt.Sprintf("  %d network policy findings\n\n", len(netFindings))

	for i, f := range netFindings {
		sev := severityStyle(f.Severity.String()).Render(f.Severity.String())
		if i == m.cursor {
			header += selectedStyle.Render(fmt.Sprintf("  %s  %s - %s", sev, f.Resource.String(), f.Title)) + "\n"
		} else {
			header += fmt.Sprintf("  %s  %s - %s\n", sev, f.Resource.String(), f.Title)
		}
	}

	sb.WriteString(cardStyle.Render(header))
	return sb.String()
}

func (m Model) renderGraphPanel() string {
	return cardStyle.Render(
		"\n  Attack Path Analysis\n\n" +
			"  Attack path analysis requires a cluster connection.\n" +
			"  Run 'kube-shield scan' first, then use 'kube-shield dashboard'.\n\n" +
			"  The graph will show:\n" +
			"  • Pod → ServiceAccount → Role → Secret paths\n" +
			"  • Network connectivity between namespaces\n" +
			"  • Privilege escalation chains\n" +
			"  • Blast radius for compromised workloads\n",
	)
}

func (m Model) renderHelp() string {
	help := "  Keyboard Shortcuts\n\n" +
		"  Navigation:\n" +
		"    Tab / Shift+Tab    Switch between panels\n" +
		"    ↑/k  ↓/j           Navigate up/down\n" +
		"    Enter              Select / drill down\n" +
		"    Esc                Go back\n\n" +
		"  Actions:\n" +
		"    /                  Filter findings\n" +
		"    r                  Refresh scan\n" +
		"    ?                  Toggle this help\n" +
		"    q / Ctrl+C         Quit\n"

	return "\n" + cardStyle.Render(help)
}

func (m Model) maxCursorItems() int {
	switch m.activeTab {
	case TabFindings:
		return len(m.report.Findings)
	case TabRBAC:
		count := 0
		for _, f := range m.report.Findings {
			if f.Category == engine.CategoryRBAC {
				count++
			}
		}
		return count
	case TabNetwork:
		count := 0
		for _, f := range m.report.Findings {
			if f.Category == engine.CategoryNetpol {
				count++
			}
		}
		return count
	default:
		return 0
	}
}


