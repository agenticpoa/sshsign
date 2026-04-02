package tui

import "github.com/charmbracelet/lipgloss"

// Styles holds all TUI styles, bound to a specific lipgloss renderer.
// This is necessary for SSH sessions where each connection needs its own renderer.
type Styles struct {
	LogoPrompt  lipgloss.Style
	Title       lipgloss.Style
	LogoSign    lipgloss.Style
	Tagline     lipgloss.Style
	Subtitle    lipgloss.Style
	Info        lipgloss.Style
	InfoLabel   lipgloss.Style
	Selected    lipgloss.Style
	Normal      lipgloss.Style
	Exit        lipgloss.Style
	Error       lipgloss.Style
	Success     lipgloss.Style
	Dim         lipgloss.Style
	Border      lipgloss.Style
	Divider     lipgloss.Style
	HintKey     lipgloss.Style
	HintDanger  lipgloss.Style
	HintNav     lipgloss.Style
	HintSep     lipgloss.Style
}

func NewStyles(r *lipgloss.Renderer) Styles {
	return Styles{
		LogoPrompt: r.NewStyle().Bold(true).Foreground(lipgloss.Color("2")),
		Title:      r.NewStyle().Bold(true).Foreground(lipgloss.Color("6")).MarginBottom(0),
		LogoSign:   r.NewStyle().Italic(true).Foreground(lipgloss.Color("6")),
		Tagline:    r.NewStyle().Foreground(lipgloss.Color("241")).MarginBottom(1),
		Subtitle:   r.NewStyle().Foreground(lipgloss.Color("241")),
		Info:       r.NewStyle().Foreground(lipgloss.Color("252")),
		InfoLabel:  r.NewStyle().Foreground(lipgloss.Color("241")),
		Selected:   r.NewStyle().Foreground(lipgloss.Color("6")).Bold(true),
		Normal:     r.NewStyle().Foreground(lipgloss.Color("252")),
		Exit:       r.NewStyle().Foreground(lipgloss.Color("241")),
		Error:      r.NewStyle().Foreground(lipgloss.Color("196")),
		Success:    r.NewStyle().Foreground(lipgloss.Color("82")),
		Dim:        r.NewStyle().Foreground(lipgloss.Color("241")),
		Border:     r.NewStyle().Border(lipgloss.NormalBorder()).BorderForeground(lipgloss.Color("237")).Padding(0, 2),
		Divider:    r.NewStyle().Foreground(lipgloss.Color("237")),
		HintKey:    r.NewStyle().Foreground(lipgloss.Color("6")),
		HintDanger: r.NewStyle().Foreground(lipgloss.Color("196")),
		HintNav:    r.NewStyle().Foreground(lipgloss.Color("252")),
		HintSep:    r.NewStyle().Foreground(lipgloss.Color("237")),
	}
}

// DefaultStyles returns styles using the default renderer (for local/testing).
func DefaultStyles() Styles {
	return NewStyles(lipgloss.DefaultRenderer())
}
