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

// verdictError is the error for a revalidation whose verdict does not allow
// the action. When the fresh observation itself failed (observeErr: a
// collector that did not complete, an unreadable path), no safety decision
// was made, so the error is a failure that wraps observeErr, never a
// Refusal. Otherwise the verdict is a safety decision and the error a
// Refusal.
func verdictError(observeErr error, format string, args ...any) error {
	err := fmt.Errorf(format, args...)
	if observeErr != nil {
		return fmt.Errorf("%w; fresh observation failed: %w", err, observeErr)
	}
	return &Refusal{Err: err}
}

// IsRefusal reports whether err is, or wraps, a Refusal.
func IsRefusal(err error) bool {
	var r *Refusal
	return errors.As(err, &r)
}
