package core

import (
	"fmt"
	"strings"
	"time"
)

// CleanupState is the durable phase of one cleanup action. Investigate marks
// an outcome that cannot be proven safe without inspecting the filesystem.
type CleanupState string

const (
	CleanupPrepared    CleanupState = "prepared"
	CleanupQuarantined CleanupState = "quarantined"
	CleanupRestored    CleanupState = "restored"
	CleanupDeleted     CleanupState = "deleted"
	CleanupInvestigate CleanupState = "investigate"
)

// Valid reports whether the state is part of the persisted cleanup contract.
func (s CleanupState) Valid() bool {
	switch s {
	case CleanupPrepared, CleanupQuarantined, CleanupRestored, CleanupDeleted, CleanupInvestigate:
		return true
	default:
		return false
	}
}

// CanTransitionTo permits only transitions that do not bypass recovery or
// deletion review. Investigate must first be reconciled to quarantined before
// deletion can be considered again.
func (s CleanupState) CanTransitionTo(next CleanupState) bool {
	switch s {
	case CleanupPrepared:
		return next == CleanupQuarantined || next == CleanupRestored || next == CleanupInvestigate
	case CleanupQuarantined:
		return next == CleanupRestored || next == CleanupDeleted || next == CleanupInvestigate
	case CleanupInvestigate:
		return next == CleanupPrepared || next == CleanupQuarantined || next == CleanupRestored
	default:
		return false
	}
}

// CleanupItem stores the original inventory and planned action alongside the
// paths needed for recovery after a process or machine restart. A cleanup ID
// groups actions; the action ID distinguishes items within that group.
type CleanupItem struct {
	CleanupID   string       `json:"cleanup_id"`
	PlanID      string       `json:"plan_id"`
	ActionID    string       `json:"action_id"`
	Source      string       `json:"source"`
	Destination string       `json:"destination"`
	State       CleanupState `json:"state"`
	Entry       Entry        `json:"entry"`
	Action      Action       `json:"action"`
	// Quarantined is the post-move evidence snapshot used for later expiry
	// checks; Entry remains the immutable pre-move inventory.
	Quarantined *Entry     `json:"quarantined,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	MovedAt     *time.Time `json:"moved_at,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	Reason      string     `json:"reason,omitempty"`
}

// Normalize canonicalizes timestamps and the nested snapshots before storage.
func (c *CleanupItem) Normalize() {
	c.Entry.Normalize()
	c.Action.Normalize()
	if c.Quarantined != nil {
		c.Quarantined.Normalize()
	}
	c.CreatedAt = c.CreatedAt.UTC()
	c.UpdatedAt = c.UpdatedAt.UTC()
	if c.MovedAt != nil {
		moved := c.MovedAt.UTC()
		c.MovedAt = &moved
	}
	if c.ExpiresAt != nil {
		expires := c.ExpiresAt.UTC()
		c.ExpiresAt = &expires
	}
}

// Validate rejects incomplete or contradictory records before any write.
func (c *CleanupItem) Validate() error {
	var errs FieldErrors
	for _, id := range [...]struct{ field, value string }{
		{"cleanup_id", c.CleanupID},
		{"plan_id", c.PlanID},
		{"action_id", c.ActionID},
	} {
		if strings.TrimSpace(id.value) == "" {
			errs.Add(id.field, "must not be empty")
		}
	}
	if !isAbsClean(c.Source) {
		errs.Add("source", "must be an absolute, cleaned path, got %q", c.Source)
	}
	if !isAbsClean(c.Destination) {
		errs.Add("destination", "must be an absolute, cleaned path, got %q", c.Destination)
	}
	if c.Source == c.Destination {
		errs.Add("destination", "must differ from source")
	}
	if !c.State.Valid() {
		errs.Add("state", "unknown cleanup state %q", c.State)
	}
	if c.CreatedAt.IsZero() {
		errs.Add("created_at", "must be set")
	}
	if c.UpdatedAt.IsZero() || c.UpdatedAt.Before(c.CreatedAt) {
		errs.Add("updated_at", "must be set and not precede created_at")
	}
	if c.MovedAt != nil && c.MovedAt.IsZero() {
		errs.Add("moved_at", "must be set when present")
	}
	if c.ExpiresAt != nil && c.ExpiresAt.IsZero() {
		errs.Add("expires_at", "must be set when present")
	}
	if err := c.Entry.Validate(); err != nil {
		errs.Add("entry", "%v", err)
	}
	errs = append(errs, c.Action.Validate("action")...)
	if c.Entry.Path != c.Source || c.Action.Path != c.Source {
		errs.Add("source", "must match entry and action paths")
	}
	if c.Action.ID != c.ActionID || c.Action.PlanID != c.PlanID {
		errs.Add("action", "ID and plan ID must match the cleanup item")
	}
	if c.Entry.FilesystemID != c.Action.FilesystemID {
		errs.Add("action.filesystem_id", "must match entry filesystem identity")
	}
	if c.Quarantined != nil {
		if err := c.Quarantined.Validate(); err != nil {
			errs.Add("quarantined", "%v", err)
		}
		if c.Quarantined.Path != c.Destination {
			errs.Add("quarantined.path", "must match destination")
		}
		if c.Quarantined.FilesystemID != c.Entry.FilesystemID {
			errs.Add("quarantined.filesystem_id", "must match original filesystem identity")
		}
	}
	if c.State == CleanupQuarantined && c.Quarantined == nil {
		errs.Add("quarantined", "required in quarantined state")
	}
	return errs.ErrorOrNil()
}

// ValidateInitial ensures a journal entry precedes any filesystem mutation.
func (c *CleanupItem) ValidateInitial() error {
	if err := c.Validate(); err != nil {
		return err
	}
	if c.State != CleanupPrepared {
		return fmt.Errorf("cleanup state: new item must be prepared, got %q", c.State)
	}
	if c.MovedAt != nil {
		return fmt.Errorf("cleanup moved_at: must be unset before move")
	}
	if c.Quarantined != nil {
		return fmt.Errorf("cleanup quarantined: must be unset before move")
	}
	return nil
}
