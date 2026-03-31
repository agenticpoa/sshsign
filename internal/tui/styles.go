package tui

import "github.com/charmbracelet/lipgloss"

var (
	logoPromptStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("2")) // green >

	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("6")).
			MarginBottom(0)

	logoSignStyle = lipgloss.NewStyle().
			Italic(true).
			Foreground(lipgloss.Color("6"))

	taglineStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("241")).
			MarginBottom(1)

	subtitleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("241"))

	infoStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("252"))

	infoLabelStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("241"))

	selectedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("6")).
			Bold(true)

	normalStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("252"))

	exitStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("241"))

	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("196"))

	successStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("82"))

	dimStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("241"))

	borderStyle = lipgloss.NewStyle().
			Border(lipgloss.NormalBorder()).
			BorderForeground(lipgloss.Color("237")).
			Padding(0, 2)

	dividerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("237"))

	hintKeyStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("6")) // teal for action keys

	hintDangerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("196")) // red for destructive keys

	hintNavStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("99")) // purple for navigation keys

	hintSepStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("237")) // dim separator
)
