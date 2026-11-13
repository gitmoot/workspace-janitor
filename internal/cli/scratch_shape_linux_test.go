//go:build linux

package cli

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/store"
)

// Chrome leaves one com.google.Chrome.XXXXXX lock directory in /tmp per
// process: a SingletonCookie symlink to a random number and a dead
// SingletonSocket. Without regenerable_shapes the socket keeps it forever.
const chromeShapeOptions = "    regenerable_idle: 2h\n    regenerable_shapes: [chrome_singleton_lock]\n"

func newChromeLockFixture(t *testing.T, shapes bool) *scratchFixture {
	t.Helper()
	x := newScratchFixture(t)
	x.regenerable = append(x.regenerable, "com.google.Chrome.*")
	// The fixed member names are waived from the sensitive-name screen.
	x.patterns = []string{"*cookie*", "*socket*"}
	x.options = "    regenerable_idle: 2h\n"
	if shapes {
		x.options = chromeShapeOptions
	}
	x.write(t)
	return x
}

// chromeLock creates name as Chrome does: a SingletonCookie symlink to
// cookie and a SingletonSocket that was listened on and closed, which
// leaves a dead socket file. The returned listener is nil unless listen
// keeps it open.
func (x *scratchFixture) chromeLock(t *testing.T, name, cookie string, listen bool) (string, *net.UnixListener) {
	t.Helper()
	dir := filepath.Join(x.scratch, name)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(cookie, filepath.Join(dir, "SingletonCookie")); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "SingletonSocket")
	if len(socket) >= 108 {
		t.Fatalf("socket path %s exceeds sun_path", socket)
	}
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	listener := l.(*net.UnixListener)
	if listen {
		t.Cleanup(func() { listener.Close() })
		return dir, listener
	}
	listener.SetUnlinkOnClose(false)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return dir, nil
}

// netUnix gives the fixture procfs this host's real Unix socket table.
func (x *scratchFixture) netUnix(t *testing.T) {
	t.Helper()
	table, err := os.ReadFile("/proc/net/unix")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(x.proc, "net"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(x.proc, "net", "unix"), table, 0o644); err != nil {
		t.Fatal(err)
	}
}

// (a) An exact-shape lock directory idle for 3h is deleted without an
// archive, though its socket is not a regular file and both member names
// match protect.name_patterns.
func TestChromeLockDeleted(t *testing.T) {
	x := newChromeLockFixture(t, true)
	dir, _ := x.chromeLock(t, "com.google.Chrome.ab12CD", "3002782319201416646", false)
	x.netUnix(t)
	x.shift(t, 3*time.Hour)
	preview := scratchStatus(t, x.mustCleanup(t, false), "com.google.Chrome.ab12CD")
	if preview.Status != scratchWouldDelete || !strings.Contains(preview.Reason, "chrome_singleton_lock shape") {
		t.Fatalf("preview: %+v", preview)
	}
	report := x.mustCleanup(t, true)
	if item := scratchStatus(t, report, "com.google.Chrome.ab12CD"); item.Status != scratchDeleted || exists(t, dir) || report.Archive != nil {
		t.Fatalf("lock directory: %+v exists=%v archive=%+v", item, exists(t, dir), report.Archive)
	}
	deletions := x.deletions(t, report.RunID)
	if len(deletions) != 1 || deletions[0].Disposition != store.ScratchRegenerable {
		t.Fatalf("deletion receipts: %+v", deletions)
	}
}

// (b) Any deviation from the exact shape is handled exactly as without the
// shape enabled, and kept.
func TestChromeLockDeviationsKept(t *testing.T) {
	x := newChromeLockFixture(t, false)
	extra, _ := x.chromeLock(t, "com.google.Chrome.extra1", "3002782319201416646", false)
	if err := os.WriteFile(filepath.Join(extra, "Default"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	subdir, _ := x.chromeLock(t, "com.google.Chrome.subdr1", "3002782319201416646", false)
	if err := os.Mkdir(filepath.Join(subdir, "d"), 0o700); err != nil {
		t.Fatal(err)
	}
	regular, _ := x.chromeLock(t, "com.google.Chrome.regfl1", "3002782319201416646", false)
	if err := os.Remove(filepath.Join(regular, "SingletonCookie")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(regular, "SingletonCookie"), []byte("3002782319201416646"), 0o600); err != nil {
		t.Fatal(err)
	}
	word, _ := x.chromeLock(t, "com.google.Chrome.word01", "../etc", false)
	signed, _ := x.chromeLock(t, "com.google.Chrome.sign01", "-12", false)
	nosock := x.entry(t, "com.google.Chrome.nosck1", map[string]string{})
	if err := os.Symlink("12", filepath.Join(nosock, "SingletonCookie")); err != nil {
		t.Fatal(err)
	}
	x.netUnix(t)
	x.shift(t, 3*time.Hour)
	deviants := map[string]string{"com.google.Chrome.extra1": extra, "com.google.Chrome.subdr1": subdir, "com.google.Chrome.regfl1": regular,
		"com.google.Chrome.word01": word, "com.google.Chrome.sign01": signed, "com.google.Chrome.nosck1": nosock}
	today := x.mustCleanup(t, false)
	x.options = chromeShapeOptions
	x.write(t)
	shaped := x.mustCleanup(t, false)
	for name := range deviants {
		before, after := scratchStatus(t, today, name), scratchStatus(t, shaped, name)
		if after.Status != scratchKept || after.Status != before.Status || after.Reason != before.Reason {
			t.Errorf("%s: without the shape %+v, with it %+v", name, before, after)
		}
	}
	report := x.mustCleanup(t, true)
	for name, path := range deviants {
		if item := scratchStatus(t, report, name); item.Status != scratchKept || !exists(t, path) {
			t.Errorf("%s acted on: %+v", name, item)
		}
	}
}

// (c) A lock whose socket is listening belongs to a live Chrome and is
// kept; so is every lock when /proc/net/unix cannot be read.
func TestChromeLockListening(t *testing.T) {
	x := newChromeLockFixture(t, true)
	live, _ := x.chromeLock(t, "com.google.Chrome.live01", "3002782319201416646", true)
	dead, _ := x.chromeLock(t, "com.google.Chrome.dead01", "3002782319201416646", false)
	x.shift(t, 3*time.Hour)
	for _, name := range []string{"com.google.Chrome.live01", "com.google.Chrome.dead01"} {
		if item := scratchStatus(t, x.mustCleanup(t, false), name); item.Status != scratchKept || !strings.Contains(item.Reason, "may be listening") {
			t.Fatalf("without /proc/net/unix %s: %+v", name, item)
		}
	}
	x.netUnix(t)
	report := x.mustCleanup(t, true)
	if item := scratchStatus(t, report, "com.google.Chrome.live01"); item.Status != scratchKept || !strings.Contains(item.Reason, "is a listening socket") || !exists(t, live) {
		t.Fatalf("listening lock: %+v", item)
	}
	if item := scratchStatus(t, report, "com.google.Chrome.dead01"); item.Status != scratchDeleted || exists(t, dead) {
		t.Fatalf("dead lock: %+v", item)
	}
}

// (d) A lock changed less than regenerable_idle ago is kept.
func TestChromeLockRecentKept(t *testing.T) {
	x := newChromeLockFixture(t, true)
	dir, _ := x.chromeLock(t, "com.google.Chrome.new001", "3002782319201416646", false)
	x.netUnix(t)
	x.shift(t, time.Hour)
	report := x.mustCleanup(t, true)
	if item := scratchStatus(t, report, "com.google.Chrome.new001"); item.Status != scratchKept || !strings.Contains(item.Reason, "must be unchanged for 2h0m0s") || !exists(t, dir) {
		t.Fatalf("recent lock: %+v", item)
	}
}

// Just before deletion the socket table is read again and the policy is
// reloaded: a lock whose socket started listening, or whose shape was
// withdrawn, mid-run is kept.
func TestChromeLockLate(t *testing.T) {
	for name, test := range map[string]struct {
		want   string
		change func(t *testing.T, x *scratchFixture, dir string)
	}{
		"live": {want: "is a listening socket; its process still holds the lock at deletion time", change: func(t *testing.T, x *scratchFixture, dir string) {
			row := fmt.Sprintf("ffff000000000001: 00000002 00000000 00010000 0001 01 4242 %s\n", filepath.Join(dir, "SingletonSocket"))
			f, err := os.OpenFile(filepath.Join(x.proc, "net", "unix"), os.O_APPEND|os.O_WRONLY, 0)
			if err == nil {
				_, err = f.WriteString(row)
				f.Close()
			}
			if err != nil {
				t.Fatal(err)
			}
		}},
		"off": {want: "regenerable_shapes no longer enables chrome_singleton_lock", change: func(t *testing.T, x *scratchFixture, _ string) {
			x.options = "    regenerable_idle: 2h\n"
			x.write(t)
		}},
	} {
		t.Run(name, func(t *testing.T) {
			x := newChromeLockFixture(t, true)
			dir, _ := x.chromeLock(t, "com.google.Chrome.late01", "3002782319201416646", false)
			x.netUnix(t)
			x.shift(t, 3*time.Hour)
			previous := scratchBeforeDeletion
			t.Cleanup(func() { scratchBeforeDeletion = previous })
			scratchBeforeDeletion = func() { test.change(t, x, dir) }
			report := x.mustCleanup(t, true)
			if item := scratchStatus(t, report, "com.google.Chrome.late01"); item.Status != scratchKept || !strings.Contains(item.Reason, test.want) || !exists(t, dir) {
				t.Fatalf("lock changed mid-run: %+v", item)
			}
		})
	}
}

// (e) Without the regenerable_shapes opt-in the socket keeps the lock, as
// before the shape existed.
func TestChromeLockNeedsOptIn(t *testing.T) {
	x := newChromeLockFixture(t, false)
	dir, _ := x.chromeLock(t, "com.google.Chrome.ab12CD", "3002782319201416646", false)
	x.netUnix(t)
	x.shift(t, 3*time.Hour)
	report := x.mustCleanup(t, true)
	if item := scratchStatus(t, report, "com.google.Chrome.ab12CD"); item.Status != scratchKept || !strings.Contains(item.Reason, "SingletonSocket: unsupported file type") || !exists(t, dir) {
		t.Fatalf("lock without the opt-in: %+v", item)
	}
}

// regenerable_shapes accepts only known shapes, once each.
func TestChromeLockShapeValidation(t *testing.T) {
	for options, want := range map[string]string{
		"    regenerable_shapes: [chrome_lock]\n":                                  `unknown shape "chrome_lock"`,
		"    regenerable_shapes: [chrome_singleton_lock, chrome_singleton_lock]\n": `duplicate shape "chrome_singleton_lock"`,
	} {
		x := newScratchFixture(t)
		x.options = options
		x.write(t)
		out, stderr, code := x.run(t, "--format", "json", "policy", "check")
		if code == ExitOK || !strings.Contains(out+stderr, want) {
			t.Errorf("%q: want %q, got exit=%d %s %s", options, want, code, out, stderr)
		}
	}
}
