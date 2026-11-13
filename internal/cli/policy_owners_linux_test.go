//go:build linux

package cli

import (
	"fmt"
	"strings"
	"testing"

	"github.com/gitmoot/workspace-janitor/internal/config"
)

// A stale item no registration or producer evidence attributes goes to the
// policy owner covering it instead of the coordinator, and only that role
// may reply for it. Ledger evidence still takes precedence, and an item no
// owners entry covers still goes to the coordinator.
func TestStaleReportRoutesToPolicyOwnerInsteadOfCoordinator(t *testing.T) {
	x := newStaleFixture(t)
	ledger := x.scratch(t, "ledger-owned", map[string]string{"README.md": "ledger\n"})
	contested := x.scratch(t, "contested", map[string]string{"README.md": "two roles\n"})
	uncovered := x.scratch(t, "uncovered", map[string]string{"README.md": "nobody\n"})
	for _, path := range []string{x.source, ledger, contested, uncovered} {
		backdate(t, path, categoryIdleAge)
	}
	x.job(t, "job-ledger", "succeeded", "seat-a", ledger)
	x.job(t, "job-contested-a", "succeeded", "seat-a", contested)
	x.job(t, "job-contested-b", "failed", "seat-b", contested)
	x.extra = fmt.Sprintf("owners:\n  - path: %s\n    owner: adspower\n    note: live fleet API\n  - path: %s\n    owner: policy-team\n  - path: %s\n    owner: policy-team\n",
		x.source, ledger, contested)
	x.write(t)
	report := x.stale(t)
	group, entry, ok := staleListed(report, x.source)
	if !ok || group.Owner != "adspower" || group.AddressedTo != "adspower" || entry.Owner != "adspower" {
		t.Fatalf("item with only a policy owner not routed to it: %+v %+v", group, entry)
	}
	if evidence := strings.Join(entry.OwnerEvidence, "\n"); !strings.Contains(evidence, "owners[0] "+x.source) {
		t.Fatalf("policy owner evidence = %q, want the owners entry named", evidence)
	}
	if group, entry, ok := staleListed(report, ledger); !ok || group.Owner != "seat-a" || entry.Owner != "seat-a" {
		t.Fatalf("ledger evidence lost precedence to the policy owner: %+v %+v", group, entry)
	}
	if group, _, ok := staleListed(report, uncovered); !ok || group.Owner != config.UnknownOwner || group.AddressedTo != "coordinator" {
		t.Fatalf("uncovered item not routed to the coordinator: %+v", group)
	}
	// A ledger naming several roles is evidence too: no policy owner breaks
	// the tie, so the coordinator still has to find the owner.
	if group, entry, ok := staleListed(report, contested); !ok || group.Owner != config.UnknownOwner || group.AddressedTo != "coordinator" ||
		!strings.Contains(strings.Join(entry.OwnerEvidence, "\n"), "ambiguous") {
		t.Fatalf("contested ledger attribution replaced by the policy owner: %+v %+v", group, entry)
	}
	if _, _, ok := staleListed(x.stale(t, "--role", "coordinator"), x.source); ok {
		t.Fatal("the coordinator still receives the policy-owned item")
	}
	if _, _, ok := staleListed(x.stale(t, "--role", "adspower"), x.source); !ok {
		t.Fatal("the policy owner's view lacks its item")
	}

	// Routing decides who answers; the answer is still the role's own reply.
	before := replyCount(t, x)
	if code, stderr := x.reply(t, "keep", x.source, "--role", "coordinator"); code == ExitOK || !strings.Contains(stderr, "owned by adspower") {
		t.Fatalf("coordinator replied for a policy-owned item: exit=%d %s", code, stderr)
	}
	if replyCount(t, x) != before {
		t.Fatal("a refused reply was recorded")
	}
	x.mustReply(t, "keep", x.source, "--role", "adspower")
	if replyCount(t, x) != before+1 {
		t.Fatal("the policy owner's keep was not recorded")
	}
}
