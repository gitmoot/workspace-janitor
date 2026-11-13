//go:build linux

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/config"
)

// kindResult decodes one entry of the public cycle report's cache_trims.
type kindResult struct {
	Status      string   `json:"status"`
	Kind        string   `json:"kind"`
	SizeBefore  *int64   `json:"size_before_bytes"`
	SizeAfter   *int64   `json:"size_after_bytes"`
	Reclaimed   *int64   `json:"reclaimed_bytes"`
	ActiveUsers []string `json:"active_users"`
	Error       string   `json:"error"`
	// docker-images only.
	EventsCoveredSince string `json:"events_covered_since"`
	Images             []struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	} `json:"images"`
}

// fakeTool writes an executable that logs `name|argv|GOMODCACHE=...` to the
// fixture's call log and then runs body.
func (x *trimFixture) fakeTool(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(x.home, "bin", name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nprintf '%s|%s|GOMODCACHE=%s\\n' \"" + name + "\" \"$*\" \"$GOMODCACHE\" >> " + x.log + "\n" + body
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

// cycleTrims runs `janitor cycle` with the given cache_trims entries and
// returns the reported trims and the exit code.
func (x *trimFixture) cycleTrims(t *testing.T, trims string) ([]kindResult, ExitCode) {
	t.Helper()
	x.writePolicy(t, fmt.Sprintf("roots:\n  - path: %s\ncollectors:\n  deep_size: false\n  git: false\n  processes: false\n  services: false\n  proc_root: %s\nprevention:\n  min_free_percent: 0\n  cache_trims:\n%s", x.root, x.proc, trims))
	out, stderr, code := x.run(t, "cycle")
	var report struct {
		CacheTrims []kindResult `json:"cache_trims"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil || len(report.CacheTrims) != 1 {
		t.Fatalf("cycle report without one cache trim (exit %d): %s %s", code, out, stderr)
	}
	return report.CacheTrims, code
}

// fakeImage is one image of the fake Docker daemon.
type fakeImage struct {
	id       string // 64 hex digits
	tags     []string
	created  time.Time
	lastTag  time.Time
	size     int64
	sha256ID string
}

// image returns a fake image whose ID is the hex digit repeated.
func image(digit string, age time.Duration, size int64, tags ...string) fakeImage {
	id := strings.Repeat(digit, 64)
	return fakeImage{id: id, sha256ID: "sha256:" + id, tags: tags, created: time.Now().Add(-age), size: size}
}

// fakeDocker is a Docker daemon holding images, with its state in
// <home>/dockerd: per image images/<id>.tags (one tag per line), .created,
// .lasttag, .size and optionally .parent (the ID of its parent image);
// reclaimable, the reclaimable image bytes `docker system df` reports
// (initially the sum of all image sizes); containers, the image of each
// container as `docker container ls --format {{.Image}}` prints it;
// ancestor-<id>, the containers the daemon reports for --filter
// ancestor=<id> (a container that appeared after the trim listed the
// containers); events, the container create events in min_age;
// history, the time of every event the daemon still holds (by default one
// from 2020, so the history covers min_age); events-fail, which makes
// `docker events` fail; inspect-fail, which makes `docker image inspect`
// fail; and hook-ancestor and hook-resolve, shell scripts run once, after
// the first container query for an image and after the first `image inspect
// --format {{.Id}} <ref>` (another client acting meanwhile).
// `docker rmi` behaves like Docker's: by ID it refuses an image with several
// tags, by tag it untags, and an image left without tags is deleted, its size
// leaving reclaimable; unless --no-prune is given, its untagged parent is
// deleted with it.
func (x *trimFixture) fakeDocker(t *testing.T, images ...fakeImage) string {
	t.Helper()
	state := filepath.Join(x.home, "dockerd")
	if err := os.MkdirAll(filepath.Join(state, "images"), 0o700); err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, image := range images {
		total += image.size
		lastTag := "0001-01-01T00:00:00Z"
		if !image.lastTag.IsZero() {
			lastTag = image.lastTag.UTC().Format(time.RFC3339Nano)
		}
		tags := ""
		for _, tag := range image.tags {
			tags += tag + "\n"
		}
		x.dockerState(t, "images/"+image.id+".tags", tags)
		x.dockerState(t, "images/"+image.id+".created", image.created.Format(time.RFC3339Nano))
		x.dockerState(t, "images/"+image.id+".lasttag", lastTag)
		x.dockerState(t, "images/"+image.id+".size", fmt.Sprint(image.size))
	}
	x.dockerState(t, "reclaimable", fmt.Sprint(total))
	x.dockerState(t, "history", "1577836800000000000\n")
	return x.fakeTool(t, "docker", `S=`+state+`
tags() { grep -c . "$S/images/$1.tags"; }
hook() { if [ -f "$S/hook-$1" ]; then sh "$S/hook-$1"; rm -f "$S/hook-$1"; fi; }
case "$1" in
info) echo /var/lib/docker ;;
system)
  printf '{"Active":"1","Reclaimable":"%sB (80%%)","Size":"24.16GB","TotalCount":"3","Type":"Images"}\n' "$(cat $S/reclaimable)"
  printf '{"Active":"2","Reclaimable":"9GB (99%%)","Size":"9GB","TotalCount":"2","Type":"Containers"}\n' ;;
image)
  case "$2" in
  ls) for f in $S/images/*.size; do if [ -f "$f" ]; then echo "sha256:$(basename "$f" .size)"; fi; done ;;
  inspect)
    if [ -f $S/inspect-fail ]; then echo "permission denied while trying to connect to the Docker daemon socket" >&2; exit 1; fi
    if [ "$3" = --format ]; then
      case "$5" in
      sha256:*) id=${5#sha256:} ;;
      *) f=$(grep -lxF "$5" $S/images/*.tags) || { echo "Error: No such image: $5" >&2; exit 1; }; id=$(basename "$f" .tags) ;;
      esac
      [ -f "$S/images/$id.size" ] || { echo "Error: No such image: $5" >&2; exit 1; }
      echo "sha256:$id"; hook resolve; exit 0
    fi
    shift 2; printf '['; sep=''
    for ref in "$@"; do
      id=${ref#sha256:}; [ -f "$S/images/$id.size" ] || { echo "Error: No such image: $ref" >&2; exit 1; }
      printf '%s{"Id":"sha256:%s","RepoTags":[' "$sep" "$id"; tsep=''
      while read -r tag; do printf '%s"%s"' "$tsep" "$tag"; tsep=','; done < "$S/images/$id.tags"
      printf '],"RepoDigests":[],"Created":"%s","Size":%s,"Metadata":{"LastTagTime":"%s"}}' \
        "$(cat $S/images/$id.created)" "$(cat $S/images/$id.size)" "$(cat $S/images/$id.lasttag)"
      sep=','
    done; echo ']' ;;
  esac ;;
container)
  case "$*" in
  *ancestor=sha256:*) id="${*##*ancestor=sha256:}"; if [ -f "$S/ancestor-$id" ]; then cat "$S/ancestor-$id"; fi; hook ancestor ;;
  *) if [ -f $S/containers ]; then cat $S/containers; fi ;;
  esac ;;
events)
  if [ -f $S/events-fail ]; then echo "Error response from daemon: events unavailable" >&2; exit 1; fi
  case "$*" in
  *TimeNano*) cat $S/history ;;
  *) if [ -f $S/events ]; then cat $S/events; fi ;;
  esac ;;
rmi)
  prune=yes; if [ "$2" = --no-prune ]; then prune=no; shift; fi
  case "$2" in
  sha256:*) id=${2#sha256:}
    [ -f "$S/images/$id.size" ] || { echo "Error: No such image: $2" >&2; exit 1; }
    if [ "$(tags $id)" -gt 1 ]; then
      echo "Error response from daemon: conflict: unable to delete $id (must be forced) - image is referenced in multiple repositories" >&2; exit 1
    fi
    : > "$S/images/$id.tags" ;;
  *) f=$(grep -lxF "$2" $S/images/*.tags) || { echo "Error: No such image: $2" >&2; exit 1; }
    id=$(basename "$f" .tags); grep -vxF "$2" "$f" > "$f.new"; mv "$f.new" "$f"; echo "Untagged: $2" ;;
  esac
  gone=; if [ "$(tags $id)" -eq 0 ]; then gone=$id; fi
  while [ -n "$gone" ]; do
    echo $(( $(cat $S/reclaimable) - $(cat $S/images/$gone.size) )) > $S/reclaimable
    parent=; if [ $prune = yes ] && [ -f "$S/images/$gone.parent" ]; then parent=$(cat "$S/images/$gone.parent"); fi
    rm "$S/images/$gone".*; echo "Deleted: sha256:$gone"
    gone=; if [ -n "$parent" ] && [ "$(tags $parent)" -eq 0 ]; then gone=$parent; fi
  done ;;
esac
`)
}

// imageExists reports whether the fake daemon still holds image.
func (x *trimFixture) imageExists(t *testing.T, image fakeImage) bool {
	t.Helper()
	_, err := os.Stat(filepath.Join(x.home, "dockerd", "images", image.id+".size"))
	return err == nil
}

// dockerState writes a file of the fake daemon's state.
func (x *trimFixture) dockerState(t *testing.T, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(x.home, "dockerd", name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// removals lists every Docker call that removes anything.
func (x *trimFixture) removals(t *testing.T) []string {
	t.Helper()
	var got []string
	for _, call := range x.calls(t) {
		if strings.HasPrefix(call, "docker|rmi ") || strings.Contains(call, "prune") || strings.HasPrefix(call, "docker|image rm") {
			got = append(got, strings.TrimSuffix(strings.TrimPrefix(call, "docker|"), "|GOMODCACHE="))
		}
	}
	return got
}

func rmis(images ...fakeImage) []string {
	var want []string
	for _, image := range images {
		want = append(want, "rmi --no-prune "+image.sha256ID)
	}
	return want
}

func dockerImagesTrim(binary, extra string) string {
	return fmt.Sprintf("    - kind: docker-images\n      binary: %s\n      min_age: 168h\n%s", binary, extra)
}

// createEvent is a container create event as `docker events --format json`
// prints it.
func createEvent(image string) string {
	return `{"Type":"container","Action":"create","Actor":{"ID":"c0ffee","Attributes":{"image":"` + image +
		`","name":"frosty_cohen"}},"scope":"local","time":1794585020,"timeNano":1794585020183426362}` + "\n"
}

const day = 24 * time.Hour

// docker-images removes, with `docker rmi --no-prune <id>` and nothing else,
// only an image that is old, unused by any container (running or stopped)
// and not re-tagged within min_age, and reports it.
func TestDockerImagesTrimRemovesOnlyOldUnusedImages(t *testing.T) {
	x := newTrimFixture(t)
	old := image("a", 30*day, 1_000_000_000, "old-tool:1")
	young := image("b", 2*day, 1_000_000_000, "young:1")
	used := image("c", 30*day, 1_000_000_000, "used:latest")
	retagged := image("d", 30*day, 1_000_000_000, "retagged:1")
	retagged.lastTag = time.Now().Add(-day)
	docker := x.fakeDocker(t, old, young, used, retagged)
	x.dockerState(t, "containers", "docker.io/library/used\n")
	trims, code := x.cycleTrims(t, dockerImagesTrim(docker, ""))
	trim := trims[0]
	if got, want := x.removals(t), rmis(old); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("removals %q, want %q", got, want)
	}
	if code != ExitOK || trim.Status != "trimmed" || len(trim.Images) != 1 || trim.Images[0].ID != old.sha256ID ||
		trim.Images[0].Status != "removed" || trim.Reclaimed == nil || *trim.Reclaimed != 1_000_000_000 {
		t.Fatalf("removal not reported: exit %d %+v", code, trim)
	}
}

// Issue #205: an image used only by short-lived containers (docker run --rm)
// has no container between uses; a container created from it within min_age,
// by the daemon's event history, keeps it.
func TestDockerImagesTrimKeepsImagesOfRecentShortLivedContainers(t *testing.T) {
	x := newTrimFixture(t)
	worker := image("a", 11*day, 82_000_000, "phobos-workspace-mcp:789730452b9c")
	stale := image("b", 30*day, 1_000_000_000, "stale:1")
	docker := x.fakeDocker(t, worker, stale)
	x.dockerState(t, "events", createEvent(worker.sha256ID))
	trims, code := x.cycleTrims(t, dockerImagesTrim(docker, ""))
	if got, want := x.removals(t), rmis(stale); strings.Join(got, "\n") != strings.Join(want, "\n") || code != ExitOK {
		t.Fatalf("removals %q, want %q (exit %d %+v)", got, want, code, trims[0])
	}
}

// An image matching a keep pattern is never removed, however old and unused.
func TestDockerImagesTrimNeverRemovesKeptImages(t *testing.T) {
	x := newTrimFixture(t)
	worker := image("a", 30*day, 82_000_000, "phobos-workspace-mcp:789730452b9c")
	rollback := image("b", 30*day, 2_000_000_000, "openwa-location:4f2a9c1", "openwa-location:rollback")
	stale := image("c", 30*day, 1_000_000_000, "stale:1")
	docker := x.fakeDocker(t, worker, rollback, stale)
	keep := "      keep:\n        - 'phobos-workspace-mcp:*'\n        - 'openwa-location:*'\n"
	trims, code := x.cycleTrims(t, dockerImagesTrim(docker, keep))
	if got, want := x.removals(t), rmis(stale); strings.Join(got, "\n") != strings.Join(want, "\n") || code != ExitOK {
		t.Fatalf("removals %q, want %q (exit %d %+v)", got, want, code, trims[0])
	}
}

// Without an event history that can be read, parsed and shown to reach back
// to min_age, recent use cannot be ruled out: the whole trim is refused and
// reported, and nothing is removed.
func TestDockerImagesTrimRefusedWithoutEventHistory(t *testing.T) {
	for name, tc := range map[string]struct {
		file, content, reason string
		covered               bool
	}{
		"unreadable":            {"events-fail", "", "events unavailable", false},
		"unparsable":            {"events", "{not json\n", "unparsable", false},
		"not a create event":    {"events", `{"Type":"container","Action":"destroy","Actor":{"Attributes":{"image":"x"}}}` + "\n", "unexpected event", false},
		"short of min_age":      {"history", fmt.Sprint(time.Now().Add(-90*time.Second).UnixNano()) + "\n", "covers only since", true},
		"empty after a restart": {"history", "", "history is empty", false},
	} {
		t.Run(name, func(t *testing.T) {
			x := newTrimFixture(t)
			docker := x.fakeDocker(t, image("a", 30*day, 1_000_000_000, "stale:1"))
			x.dockerState(t, tc.file, tc.content)
			trims, code := x.cycleTrims(t, dockerImagesTrim(docker, ""))
			trim := trims[0]
			if code == ExitOK || trim.Status != "failed" || !strings.Contains(trim.Error, "recent use cannot be ruled out") ||
				!strings.Contains(trim.Error, tc.reason) || (trim.EventsCoveredSince != "") != tc.covered {
				t.Fatalf("trim not refused as reported: exit %d %+v", code, trim)
			}
			if got := x.removals(t); len(got) != 0 {
				t.Fatalf("removed without event history: %q", got)
			}
		})
	}
}

// A container created from a candidate after the trim listed the containers
// keeps it: the trim asks the daemon again immediately before each rmi.
func TestDockerImagesTrimKeepsImageAContainerNowUses(t *testing.T) {
	x := newTrimFixture(t)
	raced := image("a", 30*day, 1_000_000_000, "raced:1")
	stale := image("b", 20*day, 1_000_000_000, "stale:1")
	docker := x.fakeDocker(t, raced, stale)
	x.dockerState(t, "ancestor-"+raced.id, "5e1f0c0ffee\n")
	trims, code := x.cycleTrims(t, dockerImagesTrim(docker, ""))
	trim := trims[0]
	if got, want := x.removals(t), rmis(stale); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("removals %q, want %q", got, want)
	}
	if code != ExitOK || len(trim.Images) != 2 || trim.Images[0].Status != "kept_in_use" || trim.Images[1].Status != "removed" {
		t.Fatalf("kept image not reported: exit %d %+v", code, trim)
	}
}

// With max_bytes the trim removes candidates oldest first only until Docker
// reports the reclaimable image space at or under the bound, and at or
// under it removes nothing.
func TestDockerImagesTrimStopsAtItsBound(t *testing.T) {
	x := newTrimFixture(t)
	oldest := image("a", 40*day, 1_000_000_000, "oldest:1")
	older := image("b", 30*day, 1_000_000_000, "older:1")
	old := image("c", 20*day, 1_000_000_000, "old:1")
	docker := x.fakeDocker(t, old, oldest, older)
	bound := "      max_bytes: 1500000000\n"
	trims, code := x.cycleTrims(t, dockerImagesTrim(docker, bound))
	trim := trims[0]
	if got, want := x.removals(t), rmis(oldest, older); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("removals %q, want %q", got, want)
	}
	if code != ExitOK || trim.Status != "trimmed" || *trim.SizeBefore != 3_000_000_000 || *trim.SizeAfter != 1_000_000_000 ||
		len(trim.Images) != 3 || trim.Images[2].Status != "not_needed" {
		t.Fatalf("bounded trim not reported: exit %d %+v", code, trim)
	}
	before := len(x.calls(t))
	if trims, _ := x.cycleTrims(t, dockerImagesTrim(docker, bound)); trims[0].Status != "under_bound" {
		t.Fatalf("docker-images at its bound: %+v", trims[0])
	}
	if got := x.removals(t); len(got) != 2 || len(x.calls(t)) != before+2 {
		t.Fatalf("under its bound the trim did more than measure: %q", x.calls(t)[before:])
	}
}

// Review #207 P1: `docker rmi` deletes untagged parent images unless told
// not to. The parent here was run within min_age, so it is no candidate;
// removing its child must not take it along.
func TestDockerImagesTrimNeverPrunesParents(t *testing.T) {
	x := newTrimFixture(t)
	parent := image("a", 30*day, 1_000_000_000)
	child := image("b", 20*day, 1_000_000_000, "child:1")
	docker := x.fakeDocker(t, parent, child)
	x.dockerState(t, "images/"+child.id+".parent", parent.id)
	x.dockerState(t, "events", createEvent(parent.sha256ID))
	trims, code := x.cycleTrims(t, dockerImagesTrim(docker, ""))
	if got, want := x.removals(t), rmis(child); strings.Join(got, "\n") != strings.Join(want, "\n") || code != ExitOK {
		t.Fatalf("removals %q, want %q (exit %d %+v)", got, want, code, trims[0])
	}
	if !x.imageExists(t, parent) || x.imageExists(t, child) {
		t.Fatalf("parent pruned with its child, or child kept: %+v", trims[0])
	}
}

// Review #207 round 3 (F2): a create event that names a tag cannot say which
// image the tag named then. app:latest ran A within min_age and has since
// moved to B; A survives only as backup:rollback, in another repository.
// Nothing can tie A to the event, so the whole trim is refused.
func TestReview207HistoricalCrossRepositoryTag(t *testing.T) {
	x := newTrimFixture(t)
	ran := image("a", 30*day, 1_000_000_000, "backup:rollback")
	current := image("b", 20*day, 1_000_000_000, "app:latest")
	stale := image("c", 30*day, 1_000_000_000, "stale:1")
	docker := x.fakeDocker(t, ran, current, stale)
	x.dockerState(t, "events", createEvent("app:latest"))
	trims, code := x.cycleTrims(t, dockerImagesTrim(docker, ""))
	trim := trims[0]
	if got := x.removals(t); len(got) != 0 || !x.imageExists(t, ran) {
		t.Fatalf("removed although a recent event names a tag: %q", got)
	}
	if code == ExitOK || trim.Status != "failed" ||
		!strings.Contains(trim.Error, "recent create event names a tag; image identity at that time is unknown") {
		t.Fatalf("trim not refused as reported: exit %d %+v", code, trim)
	}
}

// moveTagHook makes the fake daemon move tag from one image to another when
// the named hook fires, as `docker tag` by another client would.
func (x *trimFixture) moveTagHook(t *testing.T, hook, tag string, from, to fakeImage) {
	t.Helper()
	dir := filepath.Join(x.home, "dockerd", "images")
	x.dockerState(t, "hook-"+hook, fmt.Sprintf("f=%s/%s.tags\ngrep -vxF '%s' \"$f\" > \"$f.new\"; mv \"$f.new\" \"$f\"\necho '%s' >> %s/%s.tags\n",
		dir, from.id, tag, tag, dir, to.id))
}

// Review #207 round 3 (F4): a removal by tag cannot be bound to an image, so
// an eligible image with several tags (which Docker will not remove by ID
// without --force) is kept, reported as kept_multiple_tags, and the trim
// does not fail. Here another client moves app:old from candidate A to a
// young image B whenever a tag is resolved; no tag is ever removed, so B
// survives.
func TestReview207MovedCandidateTagAfterResolve(t *testing.T) {
	x := newTrimFixture(t)
	candidate := image("a", 30*day, 1_000_000_000, "app:old", "app:rollback")
	young := image("b", 2*day, 1_000_000_000)
	docker := x.fakeDocker(t, candidate, young)
	x.moveTagHook(t, "resolve", "app:old", candidate, young)
	trims, code := x.cycleTrims(t, dockerImagesTrim(docker, ""))
	trim := trims[0]
	if got := x.removals(t); len(got) != 0 {
		t.Fatalf("an image with several tags was acted on: %q", got)
	}
	if !x.imageExists(t, young) || !x.imageExists(t, candidate) || code != ExitOK || trim.Status != "trimmed" ||
		len(trim.Images) != 1 || trim.Images[0].Status != "kept_multiple_tags" {
		t.Fatalf("image with several tags not kept as reported: exit %d %+v", code, trim)
	}
}

// An image query that fails is an error that fails the trim, never an answer:
// here `docker image inspect` fails right before the removal.
func TestDockerImagesTrimFailsWhenAnInspectionFails(t *testing.T) {
	x := newTrimFixture(t)
	stale := image("a", 30*day, 1_000_000_000, "stale:1")
	docker := x.fakeDocker(t, stale)
	x.dockerState(t, "hook-ancestor", "touch "+filepath.Join(x.home, "dockerd", "inspect-fail")+"\n")
	trims, code := x.cycleTrims(t, dockerImagesTrim(docker, ""))
	trim := trims[0]
	if got := x.removals(t); len(got) != 0 {
		t.Fatalf("removed after a failed inspection: %q", got)
	}
	if code == ExitOK || trim.Status != "failed" || !strings.Contains(trim.Error, "permission denied") {
		t.Fatalf("failed inspection not reported as a failed trim: exit %d %+v", code, trim)
	}
}

// An image build or pull postpones the image removal; other Docker clients
// do not.
func TestDockerImagesTrimWaitsForBuildsAndPulls(t *testing.T) {
	for name, tc := range map[string]struct {
		argv []string
		busy bool
	}{
		"docker pull":         {[]string{"/usr/bin/docker", "pull", "nginx:1.27"}, true},
		"docker image pull":   {[]string{"docker", "image", "pull", "nginx"}, true},
		"docker compose pull": {[]string{"/usr/bin/docker", "compose", "-f", "c.yml", "pull"}, true},
		"docker-compose pull": {[]string{"/usr/local/bin/docker-compose", "pull"}, true},
		"buildx build":        {[]string{"/usr/bin/docker", "buildx", "build", "-t", "app", "."}, true},
		"docker run":          {[]string{"/usr/bin/docker", "run", "--rm", "alpine"}, false},
		"docker compose up":   {[]string{"/usr/bin/docker", "compose", "up", "-d"}, false},
	} {
		t.Run(name, func(t *testing.T) {
			x := newTrimFixture(t)
			docker := x.fakeDocker(t, image("a", 30*day, 1_000_000_000, "stale:1"))
			x.process(t, "200", tc.argv...)
			trim := func() kindResult { trims, _ := x.cycleTrims(t, dockerImagesTrim(docker, "")); return trims[0] }()
			removed := len(x.removals(t)) != 0
			if tc.busy && (trim.Status != "skipped_in_use" || len(trim.ActiveUsers) == 0 || removed) {
				t.Fatalf("images removed during %s: %+v %v", name, trim, x.calls(t))
			}
			if !tc.busy && (trim.Status != "trimmed" || !removed) {
				t.Fatalf("%s blocked the image removal: %+v", name, trim)
			}
		})
	}
}

// A docker-images trim is checked against the data root the daemon
// reports, like docker-builder: the refusal is reported as a failed trim and
// Docker runs nothing but the data-root query.
func TestDockerImagesTrimRefusedWhenItsDataRootIsArchiveOnly(t *testing.T) {
	x := newTrimFixture(t)
	relocated := filepath.Join(x.root, "docker-data")
	if err := os.MkdirAll(relocated, 0o700); err != nil {
		t.Fatal(err)
	}
	docker := x.fakeTool(t, "docker", "if [ \"$1\" = info ]; then echo "+relocated+"; fi\n")
	x.writePolicy(t, fmt.Sprintf("roots:\n  - path: %s\n    archive_only: true\ncollectors:\n  deep_size: false\n  git: false\n  processes: false\n  services: false\n  proc_root: %s\nprevention:\n  min_free_percent: 0\n  cache_trims:\n%s", x.root, x.proc, dockerImagesTrim(docker, "")))
	out, _, code := x.run(t, "cycle")
	var report struct {
		CacheTrims []kindResult `json:"cache_trims"`
	}
	_ = json.Unmarshal([]byte(out), &report)
	if code == ExitOK || len(report.CacheTrims) != 1 || report.CacheTrims[0].Status != "failed" ||
		!strings.Contains(report.CacheTrims[0].Error, "archive_only") {
		t.Fatalf("archive_only data root not reported as a refused trim (exit %d): %s", code, out)
	}
	for _, call := range x.calls(t) {
		if !strings.HasPrefix(call, "docker|info ") {
			t.Fatalf("docker ran more than its data-root query for an archive_only data root: %v", x.calls(t))
		}
	}
}

// Review #186 P1: the docker-images archive_only guard checks the root that
// containerd's config.toml really sets. Any valid TOML spelling of the
// top-level root (a quoted key, a literal string containing '#') must be
// read exactly, and a config that cannot be parsed or sets no usable root
// must refuse the trim, never fall back to the default. Each case runs the
// guard's containerd step: resolve the root, then check it against the
// archive_only roots.
func TestDockerImagesGuardReadsContainerdRootAsTOML(t *testing.T) {
	dir := t.TempDir()
	protected := filepath.Join(dir, "srv", "protected#state")
	policy := &config.Policy{Roots: []config.Root{{Path: protected, ArchiveOnly: true}}}
	inside := filepath.Join(protected, "containerd")
	for name, tc := range map[string]struct {
		body    string
		refused bool
	}{
		"quoted key":                {`"root" = "` + inside + `"` + "\n", true},
		"literal string with #":     {"version = 2\nroot = '" + inside + "' # relocated\n", true},
		"malformed TOML":            {"this is not toml\n", true},
		"root not a string":         {"root = 5\n", true},
		"empty root":                {"root = \"\"\n", true},
		"relative root":             {"root = \"containerd\"\n", true},
		"root outside":              {"root = \"" + filepath.Join(dir, "srv", "containerd") + "\"\n", false},
		"no root":                   {"disabled_plugins = [\"cri\"]\n", false},
		"root only inside a table":  {"[plugins.cri]\nroot = \"" + inside + "\"\n", false},
		"missing file (no content)": {"", false},
	} {
		t.Run(name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "config.toml")
			if tc.body != "" {
				if err := os.WriteFile(file, []byte(tc.body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			root, err := containerdRoot(file)
			refused := err != nil
			if !refused {
				in, resolveErr := config.ResolvesIntoArchiveOnlyRoot(policy, root)
				refused = resolveErr != nil || in
			}
			if refused != tc.refused {
				t.Fatalf("config %q: root %q, err %v; refused = %v, want %v", tc.body, root, err, refused, tc.refused)
			}
		})
	}
}

// goModFixture is a trim fixture whose module cache is <home>/modhome/go/pkg/mod,
// the default for HOME=<home>/modhome, filled over its bound.
func goModFixture(t *testing.T) (*trimFixture, string, string) {
	t.Helper()
	x := newTrimFixture(t)
	modcache := filepath.Join(x.home, "modhome", "go", "pkg", "mod")
	if err := os.MkdirAll(filepath.Join(modcache, "example.com", "m@v1.0.0"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(modcache, "example.com", "m@v1.0.0", "big.go"), make([]byte, 1<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	gobin := x.fakeTool(t, "go", "rm -rf \"$GOMODCACHE\"\n")
	trim := fmt.Sprintf("    - kind: go-mod\n      path: %s\n      binary: %s\n      max_bytes: 65536\n", modcache, gobin)
	return x, modcache, trim
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Without users the module cache is cleaned with the official command for
// exactly that GOMODCACHE.
func TestGoModTrimCleansAnUnusedModuleCache(t *testing.T) {
	x, modcache, trim := goModFixture(t)
	trims, code := x.cycleTrims(t, trim)
	if code != ExitOK || trims[0].Status != "trimmed" || trims[0].Reclaimed == nil || *trims[0].Reclaimed < 1<<20 {
		t.Fatalf("go-mod not trimmed: exit %d %+v", code, trims[0])
	}
	if got, want := strings.Join(x.calls(t), "\n"), "go|clean -modcache|GOMODCACHE="+modcache; got != want {
		t.Fatalf("go commands %q, want %q", got, want)
	}
}

// A go command or gopls whose module cache resolves to the trimmed one, by
// any of Go's sources, blocks the trim; so does one whose cache cannot be
// determined.
func TestGoModTrimWaitsForProcessesUsingThisModCache(t *testing.T) {
	for _, name := range []string{"explicit GOMODCACHE", "first GOPATH entry", "default HOME/go", "env file GOMODCACHE",
		"env file GOPATH", "GOROOT go.env GOPATH", "env-file GOMODCACHE over process GOPATH", "no HOME", "relative GOENV",
		"empty GOPATH entry", "toolchain run from the cache"} {
		t.Run(name, func(t *testing.T) {
			x, modcache, trim := goModFixture(t)
			gopath := filepath.Dir(filepath.Dir(modcache))
			user := filepath.Join(x.home, "user")
			env := []string{"HOME=" + user}
			argv := []string{"/usr/local/bin/gopls", "serve"}
			switch name {
			case "explicit GOMODCACHE":
				env = append(env, "GOMODCACHE="+modcache)
			case "first GOPATH entry":
				env = append(env, "GOPATH="+gopath+":"+filepath.Join(x.home, "second"))
				argv = []string{"/usr/bin/go", "build", "./..."}
			case "default HOME/go":
				env = []string{"HOME=" + filepath.Join(x.home, "modhome")}
			case "env file GOMODCACHE":
				writeFile(t, filepath.Join(user, ".config", "go", "env"), "GOMODCACHE="+modcache+"\n")
			case "env file GOPATH":
				writeFile(t, filepath.Join(user, ".config", "go", "env"), "GOPATH="+gopath+"\n")
			case "GOROOT go.env GOPATH":
				writeFile(t, filepath.Join(x.home, "goroot", "go.env"), "GOPATH="+gopath+"\n")
				argv = []string{"/usr/bin/go", "mod", "download"}
			case "env-file GOMODCACHE over process GOPATH":
				// GOMODCACHE from any source wins over a GOPATH-derived default.
				other := filepath.Join(x.home, "other")
				writeFile(t, filepath.Join(user, ".config", "go", "env"), "GOMODCACHE="+modcache+"\n")
				env = append(env, "GOPATH="+other)
			case "no HOME":
				env = []string{"PATH=/usr/bin"}
			case "relative GOENV":
				env = append(env, "GOENV=goenv")
			case "empty GOPATH entry":
				env = append(env, "GOPATH=:"+gopath)
			case "toolchain run from the cache":
				// A process with another module cache that executes a
				// toolchain Go downloaded into this one.
				env = append(env, "GOMODCACHE="+filepath.Join(x.home, "other"))
				argv = []string{"/usr/bin/sleep", "60"}
			}
			x.processEnv(t, "100", env, argv...)
			if name == "toolchain run from the cache" {
				exe := filepath.Join(x.proc, "100", "exe")
				if err := os.Remove(exe); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(modcache, "golang.org", "toolchain@v0.0.1-go1.25.0.linux-amd64", "bin", "go"), exe); err != nil {
					t.Fatal(err)
				}
			}
			trims, _ := x.cycleTrims(t, trim)
			if trims[0].Status != "skipped_in_use" || len(trims[0].ActiveUsers) == 0 {
				t.Fatalf("module cache trimmed although %s uses it: %+v", name, trims[0])
			}
			if calls := x.calls(t); len(calls) != 0 {
				t.Fatalf("go clean ran: %v", calls)
			}
		})
	}
}

// Go processes and gopls whose module cache is elsewhere do not block it.
func TestGoModTrimIgnoresProcessesWithAnotherModCache(t *testing.T) {
	x, modcache, trim := goModFixture(t)
	other := filepath.Join(x.home, "other")
	user := filepath.Join(x.home, "user")
	writeFile(t, filepath.Join(user, ".config", "go", "env"), "GOMODCACHE="+modcache+"\n")
	// The process GOMODCACHE wins over the env file naming this cache.
	x.processEnv(t, "100", []string{"HOME=" + user, "GOMODCACHE=" + other}, "/usr/local/bin/gopls")
	// GOPATH elsewhere moves the default module cache with it.
	x.processEnv(t, "101", []string{"HOME=" + filepath.Join(x.home, "h101"), "GOPATH=" + other}, "/usr/bin/go", "build", "./...")
	// Another HOME's default module cache.
	x.processEnv(t, "102", []string{"HOME=" + other}, "/usr/bin/go", "test", "./...")
	// The env file's GOMODCACHE wins over HOME's default.
	writeFile(t, filepath.Join(x.home, ".config", "go", "env"), "GOMODCACHE="+other+"\n")
	x.processEnv(t, "103", []string{"HOME=" + x.home}, "/usr/bin/go", "run", ".")
	trims, code := x.cycleTrims(t, trim)
	if code != ExitOK || trims[0].Status != "trimmed" {
		t.Fatalf("go-mod blocked by processes using other module caches: %+v", trims[0])
	}
}

// pnpm-store prunes the store with pnpm's own command and waits while any
// pnpm runs, however pnpm was installed.
func TestPnpmStoreTrimWaitsForPnpm(t *testing.T) {
	for name, argv := range map[string][]string{
		"none":            nil,
		"pnpm executable": {"/root/.local/share/pnpm/pnpm", "install"},
		"node script":     {"node", "/root/.nvm/versions/node/v22.23.2/bin/pnpm", "run", "build"},
		"corepack":        {"/usr/bin/node", "/usr/lib/node_modules/corepack/dist/pnpm.js", "add", "x"},
		"pnpx":            {"node", "/usr/local/bin/pnpx", "create-vite"},
	} {
		t.Run(name, func(t *testing.T) {
			x := newTrimFixture(t)
			store := filepath.Join(x.home, "pnpm-store", "v11")
			writeFile(t, filepath.Join(store, "files", "ab", "blob"), string(make([]byte, 1<<20)))
			pnpm := x.fakeTool(t, "pnpm", "if [ \"$2\" = path ]; then echo \"$4\"; fi\nif [ \"$2\" = prune ]; then rm -rf \"$4\"/files; fi\n")
			if argv != nil {
				x.process(t, "300", argv...)
			}
			trims, code := x.cycleTrims(t, fmt.Sprintf("    - kind: pnpm-store\n      path: %s\n      binary: %s\n      max_bytes: 65536\n", store, pnpm))
			var pruned bool
			for _, call := range x.calls(t) {
				pruned = pruned || strings.HasPrefix(call, "pnpm|store prune")
			}
			if argv != nil {
				if trims[0].Status != "skipped_in_use" || pruned {
					t.Fatalf("store pruned while %s runs: %+v %v", name, trims[0], x.calls(t))
				}
				return
			}
			if code != ExitOK || trims[0].Status != "trimmed" || trims[0].Reclaimed == nil || *trims[0].Reclaimed < 1<<20 {
				t.Fatalf("unused store not pruned: exit %d %+v", code, trims[0])
			}
			if got := x.calls(t); got[len(got)-1] != "pnpm|store prune --store-dir "+store+"|GOMODCACHE=" {
				t.Fatalf("pnpm commands: %v", got)
			}
		})
	}
}

// pnpm appends its layout version to a --store-dir that lacks it; a path
// pnpm would not prune itself fails instead of being measured forever.
func TestPnpmStoreTrimRefusesAStoreDirPnpmWouldNotPrune(t *testing.T) {
	x := newTrimFixture(t)
	store := filepath.Join(x.home, "pnpm-store")
	writeFile(t, filepath.Join(store, "v10", "files", "ab", "blob"), string(make([]byte, 1<<20)))
	pnpm := x.fakeTool(t, "pnpm", "if [ \"$2\" = path ]; then echo \"$4/v11\"; fi\n")
	trims, code := x.cycleTrims(t, fmt.Sprintf("    - kind: pnpm-store\n      path: %s\n      binary: %s\n      max_bytes: 65536\n", store, pnpm))
	if code == ExitOK || trims[0].Status != "failed" || !strings.Contains(trims[0].Error, "v11") {
		t.Fatalf("mismatched pnpm store accepted: exit %d %+v", code, trims[0])
	}
	for _, call := range x.calls(t) {
		if strings.Contains(call, "prune") {
			t.Fatalf("pnpm pruned another store: %v", x.calls(t))
		}
	}
}
