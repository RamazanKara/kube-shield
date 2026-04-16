package tui

import "github.com/charmbracelet/lipgloss"

// Color palette
var (
	primaryColor   = lipgloss.Color("#7C3AED") // Purple
	secondaryColor = lipgloss.Color("#06B6D4") // Cyan
	successColor   = lipgloss.Color("#22C55E") // Green
	warningColor   = lipgloss.Color("#EAB308") // Yellow
	dangerColor    = lipgloss.Color("#EF4444") // Red
	criticalColor  = lipgloss.Color("#DC2626") // Dark red
	mutedColor     = lipgloss.Color("#6B7280") // Gray
	textColor      = lipgloss.Color("#F9FAFB") // Near white
	bgColor        = lipgloss.Color("#111827") // Dark bg
	surfaceColor   = lipgloss.Color("#1F2937") // Card bg
	borderColor    = lipgloss.Color("#374151") // Border
)

// Layout styles
var (
	appStyle = lipgloss.NewStyle().
			Background(bgColor)

	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(primaryColor).
			Padding(0, 1)

	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(textColor).
			Background(primaryColor).
			Padding(0, 2)

	tabActiveStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(textColor).
			Background(primaryColor).
			Padding(0, 2)

	tabInactiveStyle = lipgloss.NewStyle().
				Foreground(mutedColor).
				Padding(0, 2)

	statusBarStyle = lipgloss.NewStyle().
			Foreground(mutedColor).
			Padding(0, 1)

	cardStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(borderColor).
			Padding(1, 2)

	scoreAStyle = lipgloss.NewStyle().Bold(true).Foreground(successColor)
	scoreBStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#84CC16"))
	scoreCStyle = lipgloss.NewStyle().Bold(true).Foreground(warningColor)
	scoreDStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#F97316"))
	scoreFStyle = lipgloss.NewStyle().Bold(true).Foreground(dangerColor)

	criticalStyle = lipgloss.NewStyle().Bold(true).Foreground(criticalColor)
	highStyle     = lipgloss.NewStyle().Foreground(dangerColor)
	mediumStyle   = lipgloss.NewStyle().Foreground(warningColor)
	lowStyle      = lipgloss.NewStyle().Foreground(secondaryColor)
	infoStyle     = lipgloss.NewStyle().Foreground(mutedColor)

	selectedStyle = lipgloss.NewStyle().
			Foreground(textColor).
			Background(lipgloss.Color("#374151")).
			Bold(true)

	helpStyle = lipgloss.NewStyle().
			Foreground(mutedColor)
)

func severityStyle(severity string) lipgloss.Style {
	switch severity {
	case "CRITICAL":
		return criticalStyle
	case "HIGH":
		return highStyle
	case "MEDIUM":
		return mediumStyle
	case "LOW":
		return lowStyle
	default:
		return infoStyle
	}
}

func gradeStyle(grade string) lipgloss.Style {
	switch grade {
	case "A":
		return scoreAStyle
	case "B":
		return scoreBStyle
	case "C":
		return scoreCStyle
	case "D":
		return scoreDStyle
	default:
		return scoreFStyle
	}
}
