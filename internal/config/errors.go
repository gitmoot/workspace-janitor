package config

import (
	"strings"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

// Error is a configuration failure carrying field-level detail. Callers can
// render every problem at once instead of reporting only the first.
type Error struct {
	// Scope names what failed: "paths", or the policy file path.
	Scope  string
	Errors core.FieldErrors
}

func (e *Error) Error() string {
	sorted := e.Errors.Sorted()
	var b strings.Builder
	b.WriteString("invalid configuration (")
	b.WriteString(e.Scope)
	b.WriteString("):")
	for _, fe := range sorted {
		b.WriteString("\n  - ")
		b.WriteString(fe.Field)
		b.WriteString(": ")
		b.WriteString(fe.Message)
	}
	return b.String()
}

// Fields returns the sorted field-level failures.
func (e *Error) Fields() core.FieldErrors { return e.Errors.Sorted() }
