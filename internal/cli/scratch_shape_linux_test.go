//go:build linux

package cli

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/store"
	"golang.org/x/sys/unix"
)

// Chrome leaves one com.google.Chrome.XXXXXX lock directory in /tmp per
// process: a SingletonCookie symlink to a random number and a dead
// SingletonSocket. Without regenerable_shapes the socket keeps it forever.
const chromeShapeOptions = "    regenerable_idle: 2h\n    regenerable_shapes: [chrome_singleton_lock]\n"

const chromeCookie = "3002782319201416646"

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

// chromeLockDir creates name with a SingletonCookie symlink to cookie and
// no socket yet.
func (x *scratchFixture) chromeLockDir(t *testing.T, name, cookie string) string {
	t.Helper()
	dir := filepath.Join(x.scratch, name)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(cookie, filepath.Join(dir, "SingletonCookie")); err != nil {
		t.Fatal(err)
	}
	return dir
}

// chromeLock creates name as Chrome does. Its SingletonSocket keeps
// listening for the rest of the test when listen is set; otherwise it was
// listened on and closed, which leaves a dead socket file.
func (x *scratchFixture) chromeLock(t *testing.T, name, cookie string, listen bool) string {
	t.Helper()
	dir := x.chromeLockDir(t, name, cookie)
	listener := listenUnix(t, filepath.Join(dir, "SingletonSocket"))
	if !listen {
		if err := listener.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// listenUnix binds a listening socket to addr, spelled exactly as given,
// until the test ends. Closing it leaves the socket file in place.
func listenUnix(t *testing.T, addr string) *net.UnixListener {
	t.Helper()
	if len(addr) >= 108 {
		t.Fatalf("socket path %s exceeds sun_path", addr)
	}
	l, err := net.Listen("unix", addr)
	if err != nil {
		t.Fatal(err)
	}
	listener := l.(*net.UnixListener)
	listener.SetUnlinkOnClose(false)
	t.Cleanup(func() { listener.Close() })
	return listener
}

// (a) An exact-shape lock directory idle for 3h is deleted without an
// archive, though its socket is not a regular file and both member names
// match protect.name_patterns.
func TestChromeLockDeleted(t *testing.T) {
	x := newChromeLockFixture(t, true)
	dir := x.chromeLock(t, "com.google.Chrome.ab12CD", chromeCookie, false)
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
	extra := x.chromeLock(t, "com.google.Chrome.extra1", chromeCookie, false)
	if err := os.WriteFile(filepath.Join(extra, "Default"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	subdir := x.chromeLock(t, "com.google.Chrome.subdr1", chromeCookie, false)
	if err := os.Mkdir(filepath.Join(subdir, "d"), 0o700); err != nil {
		t.Fatal(err)
	}
	regular := x.chromeLock(t, "com.google.Chrome.regfl1", chromeCookie, false)
	if err := os.Remove(filepath.Join(regular, "SingletonCookie")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(regular, "SingletonCookie"), []byte(chromeCookie), 0o600); err != nil {
		t.Fatal(err)
	}
	word := x.chromeLock(t, "com.google.Chrome.word01", "../etc", false)
	signed := x.chromeLock(t, "com.google.Chrome.sign01", "-12", false)
	nosock := x.chromeLockDir(t, "com.google.Chrome.nosck1", "12")
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
// kept; a dead one beside it is deleted. (An unreadable socket table keeps
// every lock: TestReadUnixListenersFailsClosed.)
func TestChromeLockListening(t *testing.T) {
	x := newChromeLockFixture(t, true)
	live := x.chromeLock(t, "com.google.Chrome.live01", chromeCookie, true)
	dead := x.chromeLock(t, "com.google.Chrome.dead01", chromeCookie, false)
	x.shift(t, 3*time.Hour)
	report := x.mustCleanup(t, true)
	if item := scratchStatus(t, report, "com.google.Chrome.live01"); item.Status != scratchKept || !strings.Contains(item.Reason, "is a listening socket") || !exists(t, live) {
		t.Fatalf("listening lock: %+v", item)
	}
	if item := scratchStatus(t, report, "com.google.Chrome.dead01"); item.Status != scratchDeleted || exists(t, dead) {
		t.Fatalf("dead lock: %+v", item)
	}
}

// A listener is found by its socket file, whatever path it was bound with:
// the kernel keeps the bind path as written, which need not be the
// canonical path of the file.
func TestChromeLockAlias(t *testing.T) {
	for name, bind := range map[string]func(t *testing.T, dir string){
		"dot":   func(t *testing.T, dir string) { listenUnix(t, dir+"/./SingletonSocket") },
		"slash": func(t *testing.T, dir string) { listenUnix(t, dir+"//SingletonSocket") },
		"rel": func(t *testing.T, dir string) {
			wd, err := os.Getwd()
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Chdir(dir); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := os.Chdir(wd); err != nil {
					t.Fatal(err)
				}
			}()
			listenUnix(t, "SingletonSocket")
		},
		"renamed": func(t *testing.T, dir string) {
			listenUnix(t, filepath.Join(dir, "s"))
			if err := os.Rename(filepath.Join(dir, "s"), filepath.Join(dir, "SingletonSocket")); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			x := newChromeLockFixture(t, true)
			dir := x.chromeLockDir(t, "com.google.Chrome.a", chromeCookie)
			bind(t, dir)
			x.shift(t, 3*time.Hour)
			report := x.mustCleanup(t, true)
			if item := scratchStatus(t, report, "com.google.Chrome.a"); item.Status != scratchKept || !strings.Contains(item.Reason, "is a listening socket") || !exists(t, dir) {
				t.Fatalf("lock listening under another spelling: %+v", item)
			}
		})
	}
}

// (d) A lock changed less than regenerable_idle ago is kept.
func TestChromeLockRecentKept(t *testing.T) {
	x := newChromeLockFixture(t, true)
	dir := x.chromeLock(t, "com.google.Chrome.new001", chromeCookie, false)
	x.shift(t, time.Hour)
	report := x.mustCleanup(t, true)
	if item := scratchStatus(t, report, "com.google.Chrome.new001"); item.Status != scratchKept || !strings.Contains(item.Reason, "must be unchanged for 2h0m0s") || !exists(t, dir) {
		t.Fatalf("recent lock: %+v", item)
	}
}

// Just before deletion the listening sockets are read again and the policy
// is reloaded: a lock whose socket started listening, or whose shape was
// withdrawn, mid-run is kept.
func TestChromeLockLate(t *testing.T) {
	for name, test := range map[string]struct {
		want  string
		setup func(t *testing.T, x *scratchFixture, dir string) func()
	}{
		// Bound but not yet listening when observed; listen() leaves the
		// socket file as it was.
		"live": {want: "is a listening socket; its process still holds the lock at deletion time", setup: func(t *testing.T, x *scratchFixture, dir string) func() {
			fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { unix.Close(fd) })
			if err := unix.Bind(fd, &unix.SockaddrUnix{Name: filepath.Join(dir, "SingletonSocket")}); err != nil {
				t.Fatal(err)
			}
			return func() {
				if err := unix.Listen(fd, 1); err != nil {
					t.Fatal(err)
				}
			}
		}},
		"off": {want: "regenerable_shapes no longer enables chrome_singleton_lock", setup: func(t *testing.T, x *scratchFixture, dir string) func() {
			listenUnix(t, filepath.Join(dir, "SingletonSocket")).Close()
			return func() {
				x.options = "    regenerable_idle: 2h\n"
				x.write(t)
			}
		}},
	} {
		t.Run(name, func(t *testing.T) {
			x := newChromeLockFixture(t, true)
			dir := x.chromeLockDir(t, "com.google.Chrome.late01", chromeCookie)
			change := test.setup(t, x, dir)
			x.shift(t, 3*time.Hour)
			previous := scratchBeforeDeletion
			t.Cleanup(func() { scratchBeforeDeletion = previous })
			scratchBeforeDeletion = change
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
	dir := x.chromeLock(t, "com.google.Chrome.ab12CD", chromeCookie, false)
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
