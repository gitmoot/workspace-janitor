package core

import (
	"fmt"
	"sort"
	"strings"
)

// UnknownValueError reports a string that is not a member of an enumeration.
type UnknownValueError struct {
	Kind    string
	Value   string
	Allowed []string
}

func (e *UnknownValueError) Error() string {
	return fmt.Sprintf("unknown %s %q (allowed: %s)", e.Kind, e.Value, strings.Join(e.Allowed, ", "))
}

// FieldError is a single validation failure attached to a named field.
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

func (e FieldError) Error() string { return e.Field + ": " + e.Message }

// FieldErrors is an ordered collection of field-level validation failures.
// Its rendering is sorted so identical inputs always produce identical output.
type FieldErrors []FieldError

// Add appends a formatted failure for field.
func (e *FieldErrors) Add(field, format string, args ...any) {
	*e = append(*e, FieldError{Field: field, Message: fmt.Sprintf(format, args...)})
}

// Sorted returns the failures ordered by field then message.
func (e FieldErrors) Sorted() FieldErrors {
	out := make(FieldErrors, len(e))
	copy(out, e)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Field != out[j].Field {
			return out[i].Field < out[j].Field
		}
		return out[i].Message < out[j].Message
	})
	return out
}

func (e FieldErrors) Error() string {
	sorted := e.Sorted()
	parts := make([]string, len(sorted))
	for i, fe := range sorted {
		parts[i] = fe.Error()
	}
	return strings.Join(parts, "; ")
}

// ErrorOrNil returns nil when there are no failures, and otherwise the
// collection itself. It never returns a non-nil interface holding an empty
// slice, which would make `err != nil` lie.
func (e FieldErrors) ErrorOrNil() error {
	if len(e) == 0 {
		return nil
	}
	return e
}
