//go:build linux

package cli

import (
	"os"
	"testing"
)

// Removing an archived session's transcript changes only its project
// directory. The session must not be reported unchanged forever (its old
// archive no longer binds); it is archived again as it now is.
func TestOMPSessionWithRemovedTranscriptIsNotUnchanged(t *testing.T) {
	x := newStateStoreFixture(t)
	session := x.session(t, "-proj", sessionA, categoryIdleAge)
	first := categoryItem(t, x.categories(t, false), session)
	if first.Status != categoryArchived {
		t.Fatalf("session not archived: %+v", first)
	}
	if err := os.Remove(session + ".jsonl"); err != nil {
		t.Fatal(err)
	}
	again := categoryItem(t, x.categories(t, false), session)
	if again.Status != categoryArchived || again.Name == first.Name || again.Companion != "" {
		t.Fatalf("session whose transcript was removed was not archived anew: %+v", again)
	}
}
