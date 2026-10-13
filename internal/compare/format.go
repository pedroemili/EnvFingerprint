package compare

import (
	"fmt"
	"strings"

	"github.com/envfingerprint/envfingerprint/internal/model"
)

var kindSymbol = map[string]string{
	model.ChangeAdded:    "+",
	model.ChangeRemoved:  "-",
	model.ChangeModified: "~",
	model.ChangeUnknown:  "?",
}

// FormatHuman renders a diff report for humans. It never includes values of
// sensitive variables (the engine never produces them).
func FormatHuman(d *model.DiffResult) string {
	var sb strings.Builder
	if !d.Compatible {
		sb.WriteString("AVISO: las huellas no son compatibles entre sí; la comparación puede ser incompleta.\n\n")
	}
	if len(d.Changes) == 0 && len(d.Notes) == 0 {
		sb.WriteString("Sin diferencias.\n")
		return sb.String()
	}
	for _, c := range d.Changes {
		sym := kindSymbol[c.Kind]
		fmt.Fprintf(&sb, "%s [%s] %s\n", sym, c.Severity, c.Path)
		fmt.Fprintf(&sb, "    %s\n", c.Description)
		if c.A != "" || c.B != "" {
			fmt.Fprintf(&sb, "    A: %s\n    B: %s\n", dash(c.A), dash(c.B))
		}
		if c.Rule != "" {
			fmt.Fprintf(&sb, "    regla: %s\n", c.Rule)
		}
		if c.Advice != "" {
			fmt.Fprintf(&sb, "    sugerencia: %s\n", c.Advice)
		}
	}
	if len(d.Notes) > 0 {
		sb.WriteString("\nnotas:\n")
		for _, n := range d.Notes {
			fmt.Fprintf(&sb, "  - %s\n", n)
		}
	}
	return sb.String()
}

func dash(s string) string {
	if s == "" {
		return "(vacío)"
	}
	return s
}
