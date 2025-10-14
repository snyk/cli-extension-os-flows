package presenters

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

var boxStyle = lipgloss.NewStyle().BorderStyle(lipgloss.RoundedBorder()).
	BorderForeground(lipgloss.NoColor{}).
	PaddingLeft(1).
	PaddingRight(4)
var pathCountStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#94e2d5"))

// renderBold renders text in bold style.
func renderBold(str string) string {
	return lipgloss.NewStyle().Bold(true).Render(str)
}

// renderInSeverityColor returns the color code for a given severity level.
func renderInSeverityColor(input string) string {
	upperInput := strings.ToUpper(input)
	var style lipgloss.TerminalColor
	switch {
	case strings.Contains(upperInput, "CRITICAL"):
		// Purple
		style = lipgloss.AdaptiveColor{Light: "13", Dark: "5"}
	case strings.Contains(upperInput, "HIGH"):
		// Red
		style = lipgloss.AdaptiveColor{Light: "9", Dark: "1"}
	case strings.Contains(upperInput, "MEDIUM"):
		// Yellow/Orange
		style = lipgloss.AdaptiveColor{Light: "11", Dark: "3"}
	default:
		style = lipgloss.NoColor{}
	}
	severityStyle := lipgloss.NewStyle().Foreground(style)
	return severityStyle.Render(input)
}

// renderGreen renders text in green.
func renderGreen(str string) string {
	style := lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
	return style.Render(str)
}

func renderGray(str string) string {
	style := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	return style.Render(str)
}
