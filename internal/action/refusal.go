package action

import (
	"errors"
	"fmt"
)

// Refusal is a safety guard declining to act on one item: a fresh verdict
// that refuses, new protected references, or a changed identity. The item is
// left where it was (or recorded for investigation) and nothing was lost.
// It is not a failure of the janitor itself: an I/O error, a store error or
// a verification that could not complete is never a Refusal.
type Refusal struct {
	Err error
}

func (r *Refusal) Error() string { return r.Err.Error() }

func (r *Refusal) Unwrap() error { return r.Err }

// refused returns a Refusal with a formatted message.
func refused(format string, args ...any) error {
	return &Refusal{Err: fmt.Errorf(format, args...)}
}

// IsRefusal reports whether err is, or wraps, a Refusal.
func IsRefusal(err error) bool {
	var r *Refusal
	return errors.As(err, &r)
}
