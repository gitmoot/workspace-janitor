package action

import (
	"errors"
	"fmt"

	"github.com/gitmoot/workspace-janitor/internal/core"
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

// verdictError is the error for a fresh verdict that does not allow the
// action. It is a Refusal only when the verdict is a safety decision made
// on a complete observation. It is a failure instead, wrapping the cause,
// when the observation was not complete: the recollection returned an
// error (observeErr), or the verdict holds a collector_failure protection,
// the kind every observation that could not be made is recorded as (a Git
// timeout that left only a partial Git report, unknown collector evidence,
// an unknown identity or destination). Such an item is still left in
// place; only how the run ends differs.
func verdictError(observeErr error, verdict core.Verdict, format string, args ...any) error {
	err := fmt.Errorf(format, args...)
	if observeErr != nil {
		return fmt.Errorf("%w; fresh observation failed: %w", err, observeErr)
	}
	for _, protection := range verdict.Protections {
		if protection.Blocking && protection.Kind == core.ProtectCollectorFailure {
			return fmt.Errorf("%w; fresh observation incomplete: %s", err, protection.Reason)
		}
	}
	return &Refusal{Err: err}
}

// IsRefusal reports whether err is, or wraps, a Refusal.
func IsRefusal(err error) bool {
	var r *Refusal
	return errors.As(err, &r)
}
