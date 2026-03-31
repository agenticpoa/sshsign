package tui

import "strings"

type hintKind int

const (
	hintAction hintKind = iota // teal
	hintDanger                 // red
	hintNav                    // purple
)

type hint struct {
	key   string
	label string
	kind  hintKind
}

func buildHints(hints []hint) string {
	var b strings.Builder
	b.WriteString("  ")
	for i, h := range hints {
		if i > 0 {
			b.WriteString(hintSepStyle.Render("  "))
		}
		switch h.kind {
		case hintAction:
			b.WriteString(hintKeyStyle.Render(h.key))
		case hintDanger:
			b.WriteString(hintDangerStyle.Render(h.key))
		case hintNav:
			b.WriteString(hintNavStyle.Render(h.key))
		}
		b.WriteString(dimStyle.Render(" " + h.label))
	}
	return b.String()
}
