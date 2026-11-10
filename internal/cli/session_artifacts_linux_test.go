//go:build linux

package cli

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/action"
	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
	"github.com/gitmoot/workspace-janitor/internal/store"
)

// artifactFixture is the state-store fixture with an omp_session_artifacts
// category on its OMP sessions root (and, when sessions is set, the
// omp_sessions category too).
type artifactFixture struct {
	*stateStoreFixture
	sessionsCategory bool
	// sessionsRetention and retention are the local_retention of the
	// omp_sessions and omp_session_artifacts categories (default none).
	sessionsRetention, retention string
	// category holds extra lines of the artifacts category, each indented
	// four spaces; extra goes before workspace_archive_categories, and
	// prevention under prevention:.
	category, extra, prevention string
	// protect holds extra lines under protect:, each indented two spaces.
	protect string
}

func newArtifactFixture(t *testing.T) *artifactFixture {
	t.Helper()
	x := &artifactFixture{stateStoreFixture: newStateStoreFixture(t)}
	x.writeArtifacts(t)
	return x
}

func (x *artifactFixture) writeArtifacts(t *testing.T) {
	t.Helper()
	retention := func(r string) string {
		if r == "" {
			return "none"
		}
		return r
	}
	sessions := ""
	if x.sessionsCategory {
		sessions = fmt.Sprintf("  - name: sessions\n    kind: omp_sessions\n    roots: [%s]\n    idle: 1d\n    local_retention: %s\n    archive:\n      directory: %s\n",
			x.sessions, retention(x.sessionsRetention), x.archive)
	}
	x.writePolicy(t, fmt.Sprintf(`roots:
  - path: %s
    max_depth: 2
protect:
  paths: [%s]
%scollectors:
  git: true
  processes: true
  services: true
  proc_root: %s
  systemd_dirs: [%s]
  cron_paths: []
  pm2_dumps: []
retention:
  default: none
  delete_enabled: true
prevention:
  min_free_bytes: 0
  min_free_percent: 0
%slimits:
  command_timeout: 30s
gitmoot:
  home: %s
  database: %s
%sworkspace_archive_categories:
%s  - name: artifacts
    kind: omp_session_artifacts
    roots: [%s]
    idle: 14d
    local_retention: %s
    archive:
      directory: %s
%s`, x.sessions, x.archive, x.protect, x.proc, x.services, x.prevention, x.gitmoot, filepath.Join(x.gitmoot, "gitmoot.db"), x.extra, sessions, x.sessions,
		retention(x.retention), x.archive, x.category))
}

// liveSession creates a session folder with the given files (relative path
// to age) and its own <stem>.jsonl transcript, idle for categoryIdleAge, and
// a process whose environment names the session, as a live OMP seat's does.
// That keeps omp_sessions off the folder; it never keeps its artifacts.
func (x *artifactFixture) liveSession(t *testing.T, project, stem, pid string, files map[string]time.Duration) string {
	t.Helper()
	dir := filepath.Join(x.sessions, project, stem)
	for name, age := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(strings.Repeat(name+"\n", 1+len(name))), 0o644); err != nil {
			t.Fatal(err)
		}
		when := time.Now().Add(-age)
		if err := os.Chtimes(path, when, when); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(dir+".jsonl", []byte(`{"type":"session","id":"`+stem+`"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	backdate(t, dir+".jsonl", categoryIdleAge)
	id := stem[strings.LastIndexByte(stem, '_')+1:]
	x.process(t, pid, []string{"/usr/bin/bun", "omp"}, []string{"HOME=/root", "PI_SESSION_ID=" + id}, "")
	return dir
}

// open makes pid hold path open as descriptor fd.
func (x *artifactFixture) open(t *testing.T, pid, fd, path string) {
	t.Helper()
	if err := os.Symlink(path, filepath.Join(x.proc, pid, "fd", fd)); err != nil {
		t.Fatal(err)
	}
}

func (x *artifactFixture) quarantineArtifacts(t *testing.T) artifactQuarantineReport {
	t.Helper()
	out, stderr, code := x.run(t, "--format", "json", "apply", "--quarantine", "--artifacts", "--dry-run=false", "--confirm")
	if code != ExitOK {
		t.Fatalf("artifact quarantine: exit=%d stderr=%s stdout=%s", code, stderr, out)
	}
	var doc struct {
		Data artifactQuarantineReport `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	return doc.Data
}

// tarMembers maps every member of the batch archive name to its content.
func (x *artifactFixture) tarMembers(t *testing.T, name string) map[string]string {
	t.Helper()
	f, err := os.Open(filepath.Join(x.archive, name+".tar"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out := map[string]string{}
	tr := tar.NewReader(f)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		out[h.Name] = string(data)
	}
}

// contents maps each of files (relative to dir) to its content, or to
// "<absent>".
func contents(t *testing.T, dir string, files ...string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, name := range files {
		data, err := os.ReadFile(filepath.Join(dir, name))
		switch {
		case errors.Is(err, os.ErrNotExist):
			out[name] = "<absent>"
		case err != nil:
			t.Fatal(err)
		default:
			out[name] = string(data)
		}
	}
	return out
}

func reasonsContain(item categoryArchiveItem, fragment string) bool {
	return strings.Contains(strings.Join(item.Reasons, "\n"), fragment)
}

const oldArtifact = 30 * 24 * time.Hour

// Old files of a live session folder, at any depth, go into one verified
// batch tar under their root-relative paths; its quarantine moves them, and
// `janitor restore` puts them back byte for byte, whole or one path at a
// time. A restored, unchanged file is never batched again.
func TestSessionArtifactsArchiveQuarantineAndRestore(t *testing.T) {
	x := newArtifactFixture(t)
	names := []string{"0.bash.log", "sub/1.read.log", "sub/deep/__advisor.jsonl"}
	session := x.liveSession(t, "-proj", sessionA, "4242", map[string]time.Duration{names[0]: oldArtifact, names[1]: oldArtifact, names[2]: oldArtifact})
	want := contents(t, session, names...)
	var wantBytes int64
	for _, data := range want {
		wantBytes += int64(len(data))
	}

	preview := categoryItem(t, x.categories(t, true), session)
	if preview.Status != categoryWouldArchive || preview.Files != 3 || preview.SizeBytes != wantBytes {
		t.Fatalf("dry run did not preview one batch of 3 files and %d bytes: %+v", wantBytes, preview)
	}
	if entries, err := os.ReadDir(x.archive); err != nil || len(entries) != 0 {
		t.Fatalf("dry run wrote archive output: %v %v", entries, err)
	}
	item := categoryItem(t, x.categories(t, false), session)
	if item.Status != categoryArchived || item.CleanupID == "" {
		t.Fatalf("live session's old files not archived: %+v", item)
	}
	members := x.tarMembers(t, item.Name)
	if len(members) != len(names) {
		t.Fatalf("batch tar holds %v, want %v", members, names)
	}
	for _, name := range names {
		if got := members["-proj/"+sessionA+"/"+name]; got != want[name] {
			t.Fatalf("batch tar member %s = %q, want %q", name, got, want[name])
		}
	}

	report := x.quarantineArtifacts(t)
	if len(report.Batches) != 1 || report.Batches[0].Moved != 3 || report.Batches[0].MovedBytes != wantBytes || report.Batches[0].CleanupID != item.CleanupID {
		t.Fatalf("batch quarantine did not move 3 files under %s: %+v", item.CleanupID, report)
	}
	for name, data := range contents(t, session, names...) {
		if data != "<absent>" {
			t.Fatalf("%s still in the session folder after quarantine", name)
		}
	}
	if again := x.quarantineArtifacts(t); len(again.Batches) != 0 {
		t.Fatalf("a settled batch was quarantined again: %+v", again)
	}

	x.data(t, "restore", "--confirm", item.CleanupID, filepath.Join(session, names[1]))
	if got := contents(t, session, names...); got[names[1]] != want[names[1]] || got[names[0]] != "<absent>" {
		t.Fatalf("single-path restore restored the wrong files: %v", got)
	}
	x.data(t, "restore", "--confirm", item.CleanupID)
	if got := contents(t, session, names...); !maps(got, want) {
		t.Fatalf("restored files differ: %v, want %v", got, want)
	}
	again := x.categories(t, true)
	for _, listed := range again.Items {
		if listed.Path == session && listed.Status == categoryWouldArchive {
			t.Fatalf("restored, unchanged files batched again: %+v", listed)
		}
	}
}

func maps(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// The session's own <session>.jsonl lies beside its folder, not in it: old
// as it is, it is never batched, moved or expired.
func TestSessionArtifactsNeverTouchTheSessionTranscript(t *testing.T) {
	x := newArtifactFixture(t)
	session := x.liveSession(t, "-proj", sessionA, "4242", map[string]time.Duration{"0.bash.log": oldArtifact})
	transcript, err := os.ReadFile(session + ".jsonl")
	if err != nil {
		t.Fatal(err)
	}
	report := x.categories(t, false)
	for _, listed := range report.Items {
		if listed.Path == session+".jsonl" {
			t.Fatalf("session transcript treated as a session folder: %+v", listed)
		}
	}
	item := categoryItem(t, report, session)
	for member := range x.tarMembers(t, item.Name) {
		if strings.HasSuffix(member, sessionA+".jsonl") {
			t.Fatalf("session transcript archived as %s", member)
		}
	}
	x.quarantineArtifacts(t)
	if _, _, code := x.run(t, "apply", "--expire", "--dry-run=false", "--confirm"); code != ExitOK {
		t.Fatalf("expiry failed: exit %d", code)
	}
	if got, err := os.ReadFile(session + ".jsonl"); err != nil || string(got) != string(transcript) {
		t.Fatalf("session transcript changed or moved: %v %q", err, got)
	}
}

// A file a process holds open is never batched while its idle siblings are,
// and a file a process opens after archiving stays in place at quarantine
// while its siblings move.
func TestSessionArtifactsOpenFilesStayWhileSiblingsMove(t *testing.T) {
	x := newArtifactFixture(t)
	names := []string{"held.log", "later.log", "free.log"}
	session := x.liveSession(t, "-proj", sessionA, "4242", map[string]time.Duration{names[0]: oldArtifact, names[1]: oldArtifact, names[2]: oldArtifact})
	x.open(t, "4242", "7", filepath.Join(session, "held.log"))
	item := categoryItem(t, x.categories(t, false), session)
	if item.Status != categoryArchived || item.Files != 2 || !reasonsContain(item, "open in a process (pid 4242 fd 7)") {
		t.Fatalf("open file not left out of the batch: %+v", item)
	}
	if _, ok := x.tarMembers(t, item.Name)["-proj/"+sessionA+"/held.log"]; ok {
		t.Fatal("open file archived")
	}
	x.open(t, "4242", "8", filepath.Join(session, "later.log"))
	report := x.quarantineArtifacts(t)
	if len(report.Batches) != 1 || report.Batches[0].Moved != 1 || report.Batches[0].Kept != 1 || !strings.Contains(strings.Join(report.Batches[0].Reasons, "\n"), "pid 4242 fd 8") {
		t.Fatalf("file opened after archiving not kept while its sibling moved: %+v", report)
	}
	got := contents(t, session, names...)
	if got["held.log"] == "<absent>" || got["later.log"] == "<absent>" || got["free.log"] != "<absent>" {
		t.Fatalf("open files moved or idle sibling kept: %v", got)
	}
}

// A process that cannot be inspected keeps every artifact local: selection
// and quarantine both fail closed instead of treating it as holding nothing.
func TestSessionArtifactsUninspectableProcessFailsClosed(t *testing.T) {
	x := newArtifactFixture(t)
	archived := x.liveSession(t, "-proj", sessionA, "4242", map[string]time.Duration{"0.bash.log": oldArtifact})
	categoryItem(t, x.categories(t, false), archived)
	pending := x.liveSession(t, "-other", sessionB, "4343", map[string]time.Duration{"0.bash.log": oldArtifact})
	if err := os.MkdirAll(filepath.Join(x.proc, "5151"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(x.proc, "5151", "fd"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadDir(x.archive)
	if err != nil {
		t.Fatal(err)
	}
	out, _, code := x.run(t, "--format", "json", "archive", "--categories", "--dry-run=false", "--confirm")
	if code == ExitOK || !strings.Contains(out, "could not be inspected") {
		t.Fatalf("uninspectable process did not fail the archive run: exit %d %s", code, out)
	}
	if after, err := os.ReadDir(x.archive); err != nil || len(after) != len(before) {
		t.Fatalf("archive written despite an uninspectable process: %v %v", after, err)
	}
	out, _, code = x.run(t, "--format", "json", "apply", "--quarantine", "--artifacts", "--dry-run=false", "--confirm")
	if code == ExitOK || !strings.Contains(out, "could not be inspected") {
		t.Fatalf("uninspectable process did not fail the quarantine: exit %d %s", code, out)
	}
	for _, dir := range []string{archived, pending} {
		if got := contents(t, dir, "0.bash.log"); got["0.bash.log"] == "<absent>" {
			t.Fatalf("%s moved despite an uninspectable process", dir)
		}
	}
}

// Only files idle for the category's idle, by their own mtime, are batched.
func TestSessionArtifactsYoungFileStays(t *testing.T) {
	x := newArtifactFixture(t)
	session := x.liveSession(t, "-proj", sessionA, "4242", map[string]time.Duration{"old.log": oldArtifact, "young.log": 13 * 24 * time.Hour})
	item := categoryItem(t, x.categories(t, false), session)
	if item.Status != categoryArchived || item.Files != 1 || !reasonsContain(item, "changed within 14d") {
		t.Fatalf("young file not left out: %+v", item)
	}
	x.quarantineArtifacts(t)
	if got := contents(t, session, "old.log", "young.log"); got["young.log"] == "<absent>" || got["old.log"] != "<absent>" {
		t.Fatalf("young file moved or old file kept: %v", got)
	}
}

// A workspace_archive_keep or protect.paths entry inside a session folder
// keeps what it covers out of every batch, and one added after archiving
// keeps the file at quarantine.
func TestSessionArtifactsKeepAndProtectExcludeFiles(t *testing.T) {
	x := newArtifactFixture(t)
	names := []string{"kept/a.log", "protected.log", "later-kept.log", "free.log"}
	ages := map[string]time.Duration{}
	for _, name := range names {
		ages[name] = oldArtifact
	}
	session := x.liveSession(t, "-proj", sessionA, "4242", ages)
	keep := func(path string) string {
		return fmt.Sprintf("  - path: %s\n    owner: seat-b\n    reference: keep-1\n", path)
	}
	x.extra = "workspace_archive_keep:\n" + keep(filepath.Join(session, "kept"))
	x.writeArtifacts(t)
	policy, err := os.ReadFile(filepath.Join(x.paths(t).ConfigDir, "policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	protected := strings.Replace(string(policy), "paths: ["+x.archive+"]", "paths: ["+x.archive+", "+filepath.Join(session, "protected.log")+"]", 1)
	if err := os.WriteFile(filepath.Join(x.paths(t).ConfigDir, "policy.yaml"), []byte(protected), 0o600); err != nil {
		t.Fatal(err)
	}
	item := categoryItem(t, x.categories(t, false), session)
	if item.Status != categoryArchived || item.Files != 2 || !reasonsContain(item, "unresolved KEEP") || !reasonsContain(item, "overlaps protect.paths") {
		t.Fatalf("kept or protected files not left out: %+v", item)
	}
	updated := strings.Replace(protected, "workspace_archive_keep:\n", "workspace_archive_keep:\n"+keep(filepath.Join(session, "later-kept.log")), 1)
	if err := os.WriteFile(filepath.Join(x.paths(t).ConfigDir, "policy.yaml"), []byte(updated), 0o600); err != nil {
		t.Fatal(err)
	}
	report := x.quarantineArtifacts(t)
	if len(report.Batches) != 1 || report.Batches[0].Moved != 1 || report.Batches[0].Kept != 1 {
		t.Fatalf("file kept after archiving was moved: %+v", report)
	}
	got := contents(t, session, names...)
	for _, name := range names[:3] {
		if got[name] == "<absent>" {
			t.Fatalf("%s moved despite KEEP/protection: %v", name, got)
		}
	}
	if got["free.log"] != "<absent>" {
		t.Fatalf("unprotected sibling not moved: %v", got)
	}
}

// A file changed between archive and quarantine (in size and mtime, or in
// contents alone with its mtime put back) stays in place and is reported;
// its unchanged siblings still move.
func TestSessionArtifactsChangedAfterArchiveStayLocal(t *testing.T) {
	x := newArtifactFixture(t)
	names := []string{"grown.log", "rewritten.log", "same.log"}
	session := x.liveSession(t, "-proj", sessionA, "4242", map[string]time.Duration{names[0]: oldArtifact, names[1]: oldArtifact, names[2]: oldArtifact})
	item := categoryItem(t, x.categories(t, false), session)
	if item.Files != 3 {
		t.Fatalf("batch: %+v", item)
	}
	grown := filepath.Join(session, "grown.log")
	f, err := os.OpenFile(grown, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("more\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	rewritten := filepath.Join(session, "rewritten.log")
	info, err := os.Stat(rewritten)
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(rewritten)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rewritten, []byte(strings.Repeat("X", len(original))), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(rewritten, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	report := x.quarantineArtifacts(t)
	if len(report.Batches) != 1 || report.Batches[0].Moved != 1 || report.Batches[0].Kept != 2 || report.Batches[0].Status != artifactQuarantined {
		t.Fatalf("changed files not kept while the batch settles: %+v", report)
	}
	got := contents(t, session, names...)
	if got["grown.log"] == "<absent>" || got["rewritten.log"] != strings.Repeat("X", len(original)) || got["same.log"] != "<absent>" {
		t.Fatalf("changed files moved or unchanged sibling kept: %v", got)
	}
}

// max_files_per_batch and max_bytes_per_item bound each session folder's
// batch, and max_items_per_cycle bounds the batches; the rest waits for a
// later cycle.
func TestSessionArtifactsBatchCaps(t *testing.T) {
	x := newArtifactFixture(t)
	a := x.liveSession(t, "-a", sessionA, "4242", map[string]time.Duration{"1.log": oldArtifact, "2.log": oldArtifact, "3.log": oldArtifact})
	b := x.liveSession(t, "-b", sessionB, "4343", map[string]time.Duration{"1.log": oldArtifact + time.Hour})
	x.category = "    max_files_per_batch: 2\n    max_items_per_cycle: 1\n"
	x.writeArtifacts(t)
	report := x.categories(t, false)
	first, second := categoryItem(t, report, a), categoryItem(t, report, b)
	if second.Status != categoryArchived || second.Files != 1 {
		t.Fatalf("the longest-idle batch was not archived first: %+v", second)
	}
	if first.Status != categoryDeferred || !reasonsContain(first, "max_items_per_cycle 1") {
		t.Fatalf("second batch not deferred by max_items_per_cycle: %+v", first)
	}
	x.category = "    max_files_per_batch: 2\n"
	x.writeArtifacts(t)
	first = categoryItem(t, x.categories(t, false), a)
	if first.Status != categoryArchived || first.Files != 2 || !reasonsContain(first, "1 file(s) kept: beyond this batch's max_files_per_batch 2") {
		t.Fatalf("max_files_per_batch not honoured: %+v", first)
	}
	if members := x.tarMembers(t, first.Name); len(members) != 2 {
		t.Fatalf("batch tar holds %d files, want 2", len(members))
	}
	third := categoryItem(t, x.categories(t, true), a)
	if third.Status != categoryWouldArchive || third.Files != 1 || !reasonsContain(third, "already archived") {
		t.Fatalf("the deferred file was not batched next while archived ones wait: %+v", third)
	}
	size := int64(len(strings.Repeat("1.log\n", 6)))
	x.category = fmt.Sprintf("    max_bytes_per_item: %d\n", size)
	x.writeArtifacts(t)
	x.quarantineArtifacts(t)
	c := x.liveSession(t, "-c", sessionC, "4444", map[string]time.Duration{"1.log": oldArtifact, "2.log": oldArtifact})
	capped := categoryItem(t, x.categories(t, true), c)
	if capped.Files != 1 || capped.SizeBytes != size || !reasonsContain(capped, "max_bytes_per_item") {
		t.Fatalf("max_bytes_per_item not honoured per batch: %+v", capped)
	}
}

// A session folder omp_sessions archives whole in the same run is never
// batched file by file; a live one (named by a process) still is.
func TestSessionArtifactsLeaveWholeSessionsToOMPSessions(t *testing.T) {
	x := newArtifactFixture(t)
	x.sessionsCategory = true
	x.writeArtifacts(t)
	live := x.liveSession(t, "-proj", sessionA, "4242", map[string]time.Duration{"0.bash.log": oldArtifact})
	idle := x.session(t, "-other", sessionC, categoryIdleAge)
	report := x.categories(t, false)
	whole := categoryItem(t, report, idle)
	if whole.Kind != "omp_sessions" || whole.Status != categoryArchived {
		t.Fatalf("idle session not archived whole: %+v", whole)
	}
	for _, item := range report.Items {
		if item.Path == idle && item.Kind == "omp_session_artifacts" && item.Status != categoryRefused {
			t.Fatalf("session archived whole was also batched: %+v", item)
		}
	}
	var batched bool
	for _, item := range report.Items {
		batched = batched || item.Path == live && item.Kind == "omp_session_artifacts" && item.Status == categoryArchived
	}
	if !batched {
		t.Fatalf("live session's old files not batched: %+v", report.Items)
	}
}

// A session folder that omp_sessions archived whole after its files were
// batched waits for that whole-session quarantine; the batch never moves
// files out of a folder whose archive binds it as a whole.
func TestSessionArtifactsBatchWaitsForAWholeSessionArchive(t *testing.T) {
	x := newArtifactFixture(t)
	x.sessionsCategory, x.sessionsRetention = true, "30d"
	x.writeArtifacts(t)
	session := x.liveSession(t, "-proj", sessionA, "4242", map[string]time.Duration{"0.bash.log": oldArtifact})
	backdate(t, session, oldArtifact)
	if item := categoryItem(t, x.categories(t, false), session); item.Kind != "omp_sessions" || item.Status != categoryRefused {
		t.Fatalf("live session archived whole: %+v", item)
	}
	if err := os.RemoveAll(filepath.Join(x.proc, "4242")); err != nil {
		t.Fatal(err)
	}
	if item := categoryItem(t, x.categories(t, false), session); item.Kind != "omp_sessions" || item.Status != categoryArchived {
		t.Fatalf("ended session not archived whole: %+v", item)
	}
	report := x.quarantineArtifacts(t)
	if len(report.Batches) != 1 || report.Batches[0].Status != artifactWaiting || report.Batches[0].Moved != 0 {
		t.Fatalf("batch moved files out of a session archived whole: %+v", report)
	}
	if got := contents(t, session, "0.bash.log"); got["0.bash.log"] == "<absent>" {
		t.Fatal("file moved out of a session archived whole")
	}
}

// artifactReceipts lists the cleanup receipts of id by original base name.
func (x *artifactFixture) artifactReceipts(t *testing.T, id string) map[string]string {
	t.Helper()
	var receipts []struct {
		Source      string `json:"source"`
		Destination string `json:"destination"`
	}
	data := x.data(t, "restore", id) // a dry run lists the receipts
	if err := json.Unmarshal(data["items"], &receipts); err != nil {
		t.Fatalf("receipts: %v %s", err, data["items"])
	}
	out := map[string]string{}
	for _, r := range receipts {
		out[filepath.Base(r.Source)] = r.Destination
	}
	return out
}

// Expiry deletes a quarantined artifact only while its batch archive still
// verifies, the copy is still the archived file, policy does not keep its
// original path and no process uses it.
func TestSessionArtifactsExpiry(t *testing.T) {
	setup := func(t *testing.T) (*artifactFixture, string, categoryArchiveItem, map[string]string) {
		x := newArtifactFixture(t)
		ages := map[string]time.Duration{}
		for _, name := range []string{"open.log", "tampered.log", "kept.log", "free.log"} {
			ages[name] = oldArtifact
		}
		session := x.liveSession(t, "-proj", sessionA, "4242", ages)
		item := categoryItem(t, x.categories(t, false), session)
		x.quarantineArtifacts(t)
		receipts := x.artifactReceipts(t, item.CleanupID)
		if len(receipts) != 4 {
			t.Fatalf("receipts: %v", receipts)
		}
		return x, session, item, receipts
	}
	t.Run("guards on each copy", func(t *testing.T) {
		x, session, _, receipts := setup(t)
		x.open(t, "4242", "9", receipts["open.log"])
		if err := os.WriteFile(receipts["tampered.log"], []byte("not what was archived\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		x.extra = fmt.Sprintf("workspace_archive_keep:\n  - path: %s\n    owner: seat-b\n    reference: keep-1\n", filepath.Join(session, "kept.log"))
		x.writeArtifacts(t)
		if _, _, code := x.run(t, "apply", "--expire", "--dry-run=false", "--confirm"); code == ExitOK {
			t.Fatal("expiry refused nothing")
		}
		for name, destination := range receipts {
			_, err := os.Lstat(destination)
			if name != "free.log" && err != nil {
				t.Fatalf("%s copy deleted despite its guard: %v", name, err)
			}
			if name == "free.log" && !os.IsNotExist(err) {
				t.Fatalf("unguarded verified copy not deleted: %v", err)
			}
		}
	})
	t.Run("archive no longer verifies", func(t *testing.T) {
		x, _, item, receipts := setup(t)
		tarPath := filepath.Join(x.archive, item.Name+".tar")
		data, err := os.ReadFile(tarPath)
		if err != nil {
			t.Fatal(err)
		}
		i := strings.Index(string(data), "free.log\nfree.log")
		if i < 0 {
			t.Fatal("member content not found in the tar")
		}
		data[i] = 'F'
		if err := os.WriteFile(tarPath, data, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, _, code := x.run(t, "apply", "--expire", "--dry-run=false", "--confirm"); code == ExitOK {
			t.Fatal("expiry with a corrupt batch archive succeeded")
		}
		for name, destination := range receipts {
			if _, err := os.Lstat(destination); err != nil {
				t.Fatalf("%s deleted although its batch archive no longer verifies: %v", name, err)
			}
		}
	})
}

// With local_retention, a batch is archived now and moved only once the
// retention measured from archive creation has elapsed.
func TestSessionArtifactsLocalRetentionDelaysQuarantine(t *testing.T) {
	x := newArtifactFixture(t)
	x.retention = "30d"
	x.writeArtifacts(t)
	session := x.liveSession(t, "-proj", sessionA, "4242", map[string]time.Duration{"0.bash.log": oldArtifact})
	categoryItem(t, x.categories(t, false), session)
	report := x.quarantineArtifacts(t)
	if len(report.Batches) != 1 || report.Batches[0].Status != artifactWaiting || report.Batches[0].Moved != 0 {
		t.Fatalf("batch moved before its local retention: %+v", report)
	}
	if got := contents(t, session, "0.bash.log"); got["0.bash.log"] == "<absent>" {
		t.Fatal("file moved before its local retention")
	}
}

// Symlinks, hard-linked files and other non-regular entries are never
// units; the regular files beside them are.
func TestSessionArtifactsSkipLinksAndSpecialFiles(t *testing.T) {
	x := newArtifactFixture(t)
	session := x.liveSession(t, "-proj", sessionA, "4242", map[string]time.Duration{"plain.log": oldArtifact, "linked.log": oldArtifact})
	outside := filepath.Join(x.home, "outside.log")
	if err := os.WriteFile(outside, []byte("outside\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	backdate(t, outside, oldArtifact)
	if err := os.Symlink(outside, filepath.Join(session, "link.log")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(session, "linked.log"), filepath.Join(x.home, "second-name.log")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(session, "pipe"), 0o600); err != nil {
		t.Fatal(err)
	}
	item := categoryItem(t, x.categories(t, false), session)
	if item.Status != categoryArchived || item.Files != 1 || !reasonsContain(item, "symlink") || !reasonsContain(item, "hard-linked file") || !reasonsContain(item, "not a regular file") {
		t.Fatalf("links and special files not left out: %+v", item)
	}
	if members := x.tarMembers(t, item.Name); len(members) != 1 || members["-proj/"+sessionA+"/plain.log"] == "" {
		t.Fatalf("batch tar holds %v", members)
	}
	x.quarantineArtifacts(t)
	for _, name := range []string{"link.log", "linked.log", "pipe"} {
		if _, err := os.Lstat(filepath.Join(session, name)); err != nil {
			t.Fatalf("%s moved: %v", name, err)
		}
	}
	if data, err := os.ReadFile(outside); err != nil || string(data) != "outside\n" {
		t.Fatalf("symlink target changed: %v", err)
	}
}

// The daily cycle archives a live session's old files and, with
// auto_quarantine and auto_expire, moves and expires them in the same cycle,
// leaving the session's own transcript and its young files alone.
func TestCycleArchivesQuarantinesAndExpiresSessionArtifacts(t *testing.T) {
	x := newArtifactFixture(t)
	x.prevention = "  auto_quarantine: true\n  auto_expire: true\n"
	x.writeArtifacts(t)
	session := x.liveSession(t, "-proj", sessionA, "4242", map[string]time.Duration{"old.log": oldArtifact, "young.log": time.Hour})
	out, stderr, code := x.run(t, "cycle")
	if code != ExitOK {
		t.Fatalf("cycle: exit=%d %s %s", code, out, stderr)
	}
	var report struct {
		CategoryArchives   *categoryArchiveReport `json:"category_archives"`
		ArtifactQuarantine string                 `json:"artifact_quarantine"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("cycle output: %v\n%s", err, out)
	}
	if report.CategoryArchives == nil || report.CategoryArchives.Archived != 1 || !strings.Contains(report.ArtifactQuarantine, "moved 1") {
		t.Fatalf("cycle report = %s", out)
	}
	got := contents(t, session, "old.log", "young.log", "../"+sessionA+".jsonl")
	if got["old.log"] != "<absent>" || got["young.log"] == "<absent>" || got["../"+sessionA+".jsonl"] == "<absent>" {
		t.Fatalf("cycle moved the wrong files: %v", got)
	}
	var left []string
	err := filepath.WalkDir(x.paths(t).QuarantineDir, func(path string, entry os.DirEntry, err error) error {
		if err == nil && entry.Name() == "item" {
			left = append(left, path)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Fatalf("expired artifact still quarantined: %v", left)
	}
}

// A batch whose tar no longer verifies moves nothing at quarantine and is
// retried; nothing is settled on a corrupt archive.
func TestSessionArtifactsCorruptArchiveMovesNothing(t *testing.T) {
	x := newArtifactFixture(t)
	session := x.liveSession(t, "-proj", sessionA, "4242", map[string]time.Duration{"a.log": oldArtifact, "b.log": oldArtifact})
	item := categoryItem(t, x.categories(t, false), session)
	tarPath := filepath.Join(x.archive, item.Name+".tar")
	data, err := os.ReadFile(tarPath)
	if err != nil {
		t.Fatal(err)
	}
	i := strings.Index(string(data), "a.log\na.log")
	if i < 0 {
		t.Fatal("member content not found in the tar")
	}
	data[i] = 'A'
	if err := os.WriteFile(tarPath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	out, _, code := x.run(t, "--format", "json", "apply", "--quarantine", "--artifacts", "--dry-run=false", "--confirm")
	if code == ExitOK || !strings.Contains(out, "does not verify") {
		t.Fatalf("quarantine of a corrupt batch did not fail: exit %d %s", code, out)
	}
	if got := contents(t, session, "a.log", "b.log"); got["a.log"] == "<absent>" || got["b.log"] == "<absent>" {
		t.Fatalf("files moved on a corrupt batch archive: %v", got)
	}
}

// A file that changes after its contents were verified, while the batch's
// live-process pass runs, is re-checked just before its rename and stays.
func TestSessionArtifactsChangeDuringQuarantineStaysLocal(t *testing.T) {
	x := newArtifactFixture(t)
	session := x.liveSession(t, "-proj", sessionA, "4242", map[string]time.Duration{"racy.log": oldArtifact, "calm.log": oldArtifact})
	categoryItem(t, x.categories(t, false), session)
	// The procfs pass reads this maps FIFO after every file was verified;
	// the writer changes racy.log while the reader waits on it.
	maps := filepath.Join(x.proc, "4242", "maps")
	if err := syscall.Mkfifo(maps, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		w, err := os.OpenFile(maps, os.O_WRONLY, 0)
		if err == nil {
			f, openErr := os.OpenFile(filepath.Join(session, "racy.log"), os.O_APPEND|os.O_WRONLY, 0)
			if err = openErr; err == nil {
				_, err = f.WriteString("late write\n")
				f.Close()
			}
			w.Close()
		}
		done <- err
	}()
	report := x.quarantineArtifacts(t)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if len(report.Batches) != 1 || report.Batches[0].Moved != 1 || !strings.Contains(strings.Join(report.Batches[0].Reasons, "\n"), "changed after it was verified") {
		t.Fatalf("file changed during quarantine not kept: %+v", report)
	}
	if got := contents(t, session, "racy.log", "calm.log"); got["racy.log"] == "<absent>" || got["calm.log"] != "<absent>" {
		t.Fatalf("changed file moved or calm sibling kept: %v", got)
	}
}

// A batch whose category no longer holds it (here its kind changed) moves
// nothing and keeps its quarantined files: neither quarantine nor expiry has
// authority.
func TestSessionArtifactsNeedTheirCategory(t *testing.T) {
	x := newArtifactFixture(t)
	session := x.liveSession(t, "-proj", sessionA, "4242", map[string]time.Duration{"a.log": oldArtifact})
	item := categoryItem(t, x.categories(t, false), session)
	config := filepath.Join(x.paths(t).ConfigDir, "policy.yaml")
	held, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	withdrawn := []byte(strings.Replace(string(held), "kind: omp_session_artifacts", "kind: omp_sessions", 1))
	if err := os.WriteFile(config, withdrawn, 0o600); err != nil {
		t.Fatal(err)
	}
	if report := x.quarantineArtifacts(t); len(report.Batches) != 1 || report.Batches[0].Status != artifactWaiting {
		t.Fatalf("batch of a changed category quarantined: %+v", report)
	}
	if got := contents(t, session, "a.log"); got["a.log"] == "<absent>" {
		t.Fatal("file moved without category authority")
	}
	if err := os.WriteFile(config, held, 0o600); err != nil {
		t.Fatal(err)
	}
	x.quarantineArtifacts(t)
	receipts := x.artifactReceipts(t, item.CleanupID)
	if err := os.WriteFile(config, withdrawn, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, _, code := x.run(t, "apply", "--expire", "--dry-run=false", "--confirm"); code == ExitOK || !strings.Contains(out, "no expiry authority: its category kind changed") {
		t.Fatalf("expiry without category authority not refused for that reason: exit %d %s", code, out)
	}
	if _, err := os.Lstat(receipts["a.log"]); err != nil {
		t.Fatalf("quarantined file deleted without category authority: %v", err)
	}
}

// pauseScan makes pid's maps a FIFO, so the next procfs pass blocks on it
// until change has run: a write that lands while a live-process scan runs.
func (x *artifactFixture) pauseScan(t *testing.T, pid string, change func() error) <-chan error {
	t.Helper()
	maps := filepath.Join(x.proc, pid, "maps")
	if err := syscall.Mkfifo(maps, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		w, err := os.OpenFile(maps, os.O_WRONLY, 0)
		if err == nil {
			err = change()
			w.Close()
		}
		done <- err
	}()
	return done
}

// An append to a quarantined copy that lands during expiry's process scan,
// after the copy was verified against the archive, keeps the copy: it holds
// bytes that were never archived.
func TestSessionArtifactsExpiryRechecksTheCopyAfterTheProcessScan(t *testing.T) {
	x := newArtifactFixture(t)
	session := x.liveSession(t, "-proj", sessionA, "4242", map[string]time.Duration{"a.log": oldArtifact})
	item := categoryItem(t, x.categories(t, false), session)
	x.quarantineArtifacts(t)
	copy := x.artifactReceipts(t, item.CleanupID)["a.log"]
	done := x.pauseScan(t, "4242", func() error {
		f, err := os.OpenFile(copy, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = f.WriteString("never archived\n")
		return err
	})
	out, _, code := x.run(t, "apply", "--expire", "--dry-run=false", "--confirm")
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if code == ExitOK {
		t.Fatalf("expiry of a copy appended to during the scan succeeded: %s", out)
	}
	if data, err := os.ReadFile(copy); err != nil || !strings.HasSuffix(string(data), "never archived\n") {
		t.Fatalf("copy with unarchived bytes deleted: %v", err)
	}
}

// protect.name_patterns added after selection keep a file at every later
// boundary: the archive preflight, the quarantine and the expiry.
func TestSessionArtifactsCurrentNamePatternsAtEveryBoundary(t *testing.T) {
	setup := func(t *testing.T) (*artifactFixture, string, categoryArchiveItem) {
		x := newArtifactFixture(t)
		session := x.liveSession(t, "-proj", sessionA, "4242", map[string]time.Duration{"review.log": oldArtifact, "free.log": oldArtifact})
		return x, session, categoryItem(t, x.categories(t, false), session)
	}
	protect := func(x *artifactFixture) {
		x.protect = "  name_patterns: [review.log]\n"
		x.writeArtifacts(t)
	}
	t.Run("preflight", func(t *testing.T) {
		x := newArtifactFixture(t)
		session := x.liveSession(t, "-proj", sessionA, "4242", map[string]time.Duration{"review.log": oldArtifact})
		protect(x)
		policy, err := config.LoadPolicy(x.paths(t))
		if err != nil {
			t.Fatal(err)
		}
		category, _ := policy.WorkspaceArchiveCategory("artifacts")
		if err := artifactPreflight(x.paths(t), category, x.sessions, []string{filepath.Join(session, "review.log")}); err == nil || !strings.Contains(err.Error(), "protected name") {
			t.Fatalf("preflight accepted a file protect.name_patterns now names: %v", err)
		}
	})
	t.Run("quarantine", func(t *testing.T) {
		x, session, _ := setup(t)
		protect(x)
		report := x.quarantineArtifacts(t)
		if len(report.Batches) != 1 || report.Batches[0].Moved != 1 || report.Batches[0].Kept != 1 {
			t.Fatalf("protected name not kept at quarantine: %+v", report)
		}
		if got := contents(t, session, "review.log", "free.log"); got["review.log"] == "<absent>" || got["free.log"] != "<absent>" {
			t.Fatalf("wrong files moved: %v", got)
		}
	})
	t.Run("expiry", func(t *testing.T) {
		x, _, item := setup(t)
		x.quarantineArtifacts(t)
		receipts := x.artifactReceipts(t, item.CleanupID)
		protect(x)
		if _, _, code := x.run(t, "apply", "--expire", "--dry-run=false", "--confirm"); code == ExitOK {
			t.Fatal("expiry refused nothing")
		}
		if _, err := os.Lstat(receipts["review.log"]); err != nil {
			t.Fatalf("copy of a protected name deleted: %v", err)
		}
		if _, err := os.Lstat(receipts["free.log"]); !os.IsNotExist(err) {
			t.Fatalf("unprotected copy not deleted: %v", err)
		}
	})
}

// Metadata the batch tar records but cannot carry differently (mode), or
// does not hold at all (extended attributes), changing after archiving keeps
// the file in place at quarantine and its copy at expiry.
func TestSessionArtifactsMetadataTheArchiveCannotPreserve(t *testing.T) {
	setxattr := func(t *testing.T, path string) {
		t.Helper()
		if err := syscall.Setxattr(path, "user.janitor-test", []byte("x"), 0); err != nil {
			t.Skipf("user extended attributes unsupported here: %v", err)
		}
	}
	t.Run("quarantine", func(t *testing.T) {
		x := newArtifactFixture(t)
		session := x.liveSession(t, "-proj", sessionA, "4242", map[string]time.Duration{"mode.log": oldArtifact, "xattr.log": oldArtifact, "free.log": oldArtifact})
		categoryItem(t, x.categories(t, false), session)
		if err := os.Chmod(filepath.Join(session, "mode.log"), 0o600); err != nil {
			t.Fatal(err)
		}
		setxattr(t, filepath.Join(session, "xattr.log"))
		report := x.quarantineArtifacts(t)
		reasons := strings.Join(report.Batches[0].Reasons, "\n")
		if report.Batches[0].Moved != 1 || !strings.Contains(reasons, "mode or ownership") || !strings.Contains(reasons, "extended attributes") {
			t.Fatalf("changed metadata not kept: %+v", report)
		}
		if got := contents(t, session, "mode.log", "xattr.log", "free.log"); got["mode.log"] == "<absent>" || got["xattr.log"] == "<absent>" || got["free.log"] != "<absent>" {
			t.Fatalf("wrong files moved: %v", got)
		}
	})
	t.Run("expiry", func(t *testing.T) {
		x := newArtifactFixture(t)
		session := x.liveSession(t, "-proj", sessionA, "4242", map[string]time.Duration{"mode.log": oldArtifact, "xattr.log": oldArtifact})
		item := categoryItem(t, x.categories(t, false), session)
		x.quarantineArtifacts(t)
		receipts := x.artifactReceipts(t, item.CleanupID)
		if err := os.Chmod(receipts["mode.log"], 0o600); err != nil {
			t.Fatal(err)
		}
		setxattr(t, receipts["xattr.log"])
		if _, _, code := x.run(t, "apply", "--expire", "--dry-run=false", "--confirm"); code == ExitOK {
			t.Fatal("expiry refused nothing")
		}
		for name, copy := range receipts {
			if _, err := os.Lstat(copy); err != nil {
				t.Fatalf("%s copy deleted although the archive cannot restore it as it is: %v", name, err)
			}
		}
	})
}

// An equal-length rewrite that restores the mtime, landing during the
// quarantine's process scan after the contents were verified, keeps the
// file: the final check compares the full verified state, ctime included.
func TestSessionArtifactsSameLengthRewriteDuringQuarantineStaysLocal(t *testing.T) {
	x := newArtifactFixture(t)
	session := x.liveSession(t, "-proj", sessionA, "4242", map[string]time.Duration{"racy.log": oldArtifact, "calm.log": oldArtifact})
	categoryItem(t, x.categories(t, false), session)
	racy := filepath.Join(session, "racy.log")
	done := x.pauseScan(t, "4242", func() error {
		info, err := os.Stat(racy)
		if err != nil {
			return err
		}
		if err := os.WriteFile(racy, []byte(strings.Repeat("Z", int(info.Size()))), 0o644); err != nil {
			return err
		}
		return os.Chtimes(racy, info.ModTime(), info.ModTime())
	})
	report := x.quarantineArtifacts(t)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if len(report.Batches) != 1 || report.Batches[0].Moved != 1 || !strings.Contains(strings.Join(report.Batches[0].Reasons, "\n"), "changed after it was verified") {
		t.Fatalf("rewrite during quarantine not kept: %+v", report)
	}
	if got := contents(t, session, "racy.log", "calm.log"); !strings.HasPrefix(got["racy.log"], "ZZ") || got["calm.log"] != "<absent>" {
		t.Fatalf("rewritten file moved or calm sibling kept: %v", got)
	}
}

// A local_retention raised after quarantine holds the copies until it has
// elapsed since the batch was archived, as for workspace archives.
func TestSessionArtifactsExpiryAppliesTheCurrentLocalRetention(t *testing.T) {
	x := newArtifactFixture(t)
	session := x.liveSession(t, "-proj", sessionA, "4242", map[string]time.Duration{"a.log": oldArtifact})
	item := categoryItem(t, x.categories(t, false), session)
	x.quarantineArtifacts(t)
	copy := x.artifactReceipts(t, item.CleanupID)["a.log"]
	x.retention = "90d"
	x.writeArtifacts(t)
	if out, _, code := x.run(t, "apply", "--expire", "--dry-run=false", "--confirm"); code == ExitOK || !strings.Contains(out, "local retention") {
		t.Fatalf("expiry ignored the raised local_retention: exit %d %s", code, out)
	}
	if _, err := os.Lstat(copy); err != nil {
		t.Fatalf("copy deleted inside the raised local retention: %v", err)
	}
}

// A file renamed into its receipt whose state write then failed (a lock
// held too long, a crash) leaves its receipt prepared. The next scheduled
// artifact quarantine finishes that move from the receipt: it is journaled
// as quarantined, the rest of the batch moves, and the batch settles.
func TestSessionArtifactsNextRunFinishesAMoveItCouldNotJournal(t *testing.T) {
	x := newArtifactFixture(t)
	session := x.liveSession(t, "-proj", sessionA, "4242", map[string]time.Duration{"a.log": oldArtifact, "b.log": oldArtifact})
	item := categoryItem(t, x.categories(t, false), session)
	ctx := context.Background()
	paths := x.paths(t)
	receipts := func() []core.CleanupItem {
		t.Helper()
		db, err := store.Open(ctx, paths.DatabaseFile)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		var items []core.CleanupItem
		if err := db.Read(ctx, func(tx *store.Tx) error {
			items, err = tx.CleanupItems(ctx, item.CleanupID)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return items
	}

	db, err := store.Open(ctx, paths.DatabaseFile)
	if err != nil {
		t.Fatal(err)
	}
	var batch store.ArtifactBatch
	var files []store.ArtifactFile
	if err := db.Read(ctx, func(tx *store.Tx) error {
		batches, err := tx.ArtifactBatches(ctx)
		if err != nil {
			return err
		}
		for _, b := range batches {
			if b.Name == item.Name {
				batch = b
			}
		}
		files, err = tx.ArtifactBatchFiles(ctx, item.Name)
		return err
	}); err != nil || len(files) != 2 {
		t.Fatalf("batch files: %v %v", files, err)
	}
	var st syscall.Stat_t
	if err := syscall.Lstat(files[0].Path, &st); err != nil {
		t.Fatal(err)
	}
	interrupted := artifactCleanupItem(config.Policy{Retention: config.RetentionPolicy{Default: core.RetentionNone}}, batch, files[0],
		core.FilesystemID{Device: st.Dev, Inode: st.Ino}, time.Now().UTC())
	journal, cancel := context.WithCancel(ctx)
	defer cancel()
	// The state write after the rename fails: its context ends just before.
	engine := &action.Engine{DB: db, QuarantineDir: paths.QuarantineDir}
	if _, err := engine.QuarantineArtifact(journal, interrupted, func() error { cancel(); return nil }); err == nil {
		t.Fatal("receipt write with an ended context succeeded")
	}
	db.Close()
	if _, err := os.Lstat(files[0].Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("file not renamed before its state write failed: %v", err)
	}
	if items := receipts(); len(items) != 1 || items[0].State != core.CleanupPrepared {
		t.Fatalf("interrupted move left %+v, want one prepared receipt", items)
	}

	report := x.quarantineArtifacts(t)
	if len(report.Batches) != 1 || report.Batches[0].Status != artifactQuarantined || report.Batches[0].Moved != 2 || report.Batches[0].Kept != 0 {
		t.Fatalf("next run did not finish the interrupted batch: %+v", report)
	}
	items := receipts()
	if len(items) != 2 {
		t.Fatalf("receipts after the next run: %+v", items)
	}
	for _, it := range items {
		if it.State != core.CleanupQuarantined || it.MovedAt == nil {
			t.Fatalf("%s receipt is %s after the next run", it.Source, it.State)
		}
	}
	if got := contents(t, session, "a.log", "b.log"); got["a.log"] != "<absent>" || got["b.log"] != "<absent>" {
		t.Fatalf("files left in the session folder: %v", got)
	}
}
