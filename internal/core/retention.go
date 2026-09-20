package core

import "time"

// Retention is how long a quarantined item is kept before deletion becomes
// eligible. Deletion is never automatic on expiry: a second full safety
// evaluation must also pass.
type Retention string

const (
	RetentionNone      Retention = "none"
	Retention7Days     Retention = "7d"
	Retention30Days    Retention = "30d"
	Retention90Days    Retention = "90d"
	RetentionPermanent Retention = "permanent"
)

var retentions = []Retention{RetentionNone, Retention7Days, Retention30Days, Retention90Days, RetentionPermanent}

// Retentions returns every valid retention period.
func Retentions() []Retention { return copyEnum(retentions) }

// Valid reports whether r is a known retention period.
func (r Retention) Valid() bool { return validEnum(r, retentions) }

// ParseRetention converts s into a Retention.
func ParseRetention(s string) (Retention, error) { return parseEnum(s, retentions, "retention") }

// Window returns the retention duration. ok is false for "permanent", which
// never expires.
func (r Retention) Window() (d time.Duration, ok bool) {
	switch r {
	case RetentionNone:
		return 0, true
	case Retention7Days:
		return 7 * 24 * time.Hour, true
	case Retention30Days:
		return 30 * 24 * time.Hour, true
	case Retention90Days:
		return 90 * 24 * time.Hour, true
	default:
		return 0, false
	}
}

// ExpiresAt returns the earliest instant at which deletion may be considered.
// ok is false when the item never becomes eligible.
func (r Retention) ExpiresAt(from time.Time) (t time.Time, ok bool) {
	window, ok := r.Window()
	if !ok {
		return time.Time{}, false
	}
	return from.UTC().Add(window), true
}

// Expired reports whether the retention window that started at from has
// elapsed by now. A permanent retention never expires.
func (r Retention) Expired(from, now time.Time) bool {
	expiry, ok := r.ExpiresAt(from)
	if !ok {
		return false
	}
	return !now.UTC().Before(expiry)
}
