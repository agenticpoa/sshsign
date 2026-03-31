package tui

import "strings"

type hintKind int

const (
	hintAction hintKind = iota // teal
	hintDanger                 // red
	hintNav                    // teal (navigation)
)

type hint struct {
	key   string
	label string
	kind  hintKind
}

func (m Model) buildHints(hints []hint) string {
	var b strings.Builder
	b.WriteString("  ")
	for i, h := range hints {
		if i > 0 {
			b.WriteString(m.s.HintSep.Render("  "))
		}
		switch h.kind {
		case hintAction:
			b.WriteString(m.s.HintKey.Render(h.key))
		case hintDanger:
			b.WriteString(m.s.HintDanger.Render(h.key))
		case hintNav:
			b.WriteString(m.s.HintNav.Render(h.key))
		}
		b.WriteString(m.s.Dim.Render(" " + h.label))
	}
	return b.String()
}
