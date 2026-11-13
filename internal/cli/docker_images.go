package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/config"
)

// Outcomes of one docker-images candidate.
const (
	imageRemoved    = "removed"
	imageRmiFailed  = "failed"
	imageInUse      = "kept_in_use"
	imageNotNeeded  = "not_needed"
	imagePostponed  = "postponed"
	imageNotReached = "not_reached"
	imageTagMoved   = "tag_moved"
	imageChanged    = "changed"
)

// dockerImageOutcome reports one candidate image of a docker-images trim:
// what it was, every `docker rmi` run for it, and what happened to it.
type dockerImageOutcome struct {
	ID         string     `json:"id"`
	Tags       []string   `json:"tags,omitempty"`
	SizeBytes  int64      `json:"size_bytes"`
	Status     string     `json:"status"`
	Commands   [][]string `json:"commands,omitempty"`
	Untagged   []string   `json:"untagged,omitempty"`
	Containers []string   `json:"containers,omitempty"`
	Output     string     `json:"output,omitempty"`
	Error      string     `json:"error,omitempty"`
}

// dockerImage is what the trim reads from `docker image inspect`.
type dockerImage struct {
	ID          string   `json:"Id"`
	RepoTags    []string `json:"RepoTags"`
	RepoDigests []string `json:"RepoDigests"`
	Created     string   `json:"Created"`
	Size        int64    `json:"Size"`
	Metadata    struct {
		LastTagTime string `json:"LastTagTime"`
	} `json:"Metadata"`
}

// trimDockerImages removes old images nobody uses, one non-forced `docker
// rmi --no-prune` at a time. A candidate is an image that no container
// (running or stopped) references, that was neither created nor last tagged
// within min_age, that matches no keep pattern, and that no container may
// have been created from within min_age according to the daemon's event
// history. A history that cannot be read, parsed, or shown to reach back to
// min_age refuses the whole trim. Candidates go oldest first; the run stops
// once the reclaimable image space is at or under max_bytes (if set).
// Immediately before each rmi the trim re-checks that no image build or pull
// runs and no container references the image.
func trimDockerImages(ctx context.Context, procRoot string, trim config.CacheTrim, report cacheTrimReport) cacheTrimReport {
	fail := func(err error) cacheTrimReport {
		report.Status, report.Error = cacheTrimFailed, err.Error()
		return report
	}
	reclaimable, err := dockerReclaimableImageBytes(ctx, trim.Binary)
	if err != nil {
		return fail(err)
	}
	before := reclaimable
	report.SizeBefore = &before
	if trim.MaxBytes > 0 && reclaimable <= trim.MaxBytes {
		report.Status = cacheUnderBound
		return report
	}
	if users := cacheUsers(procRoot, trim); len(users) != 0 {
		report.Status, report.ActiveUsers = cacheInUse, users
		return report
	}
	now := time.Now()
	cutoff := now.Add(-trim.MinAge.Duration())
	images, err := dockerImages(ctx, trim.Binary)
	if err != nil {
		return fail(err)
	}
	resolve := imageResolver(images)
	inUse := map[string]bool{}
	refs, err := dockerOutput(ctx, trim.Binary, "container", "ls", "--all", "--no-trunc", "--format", "{{.Image}}")
	if err != nil {
		return fail(err)
	}
	for _, ref := range nonEmptyLines(refs) {
		for _, id := range resolve(ref) {
			inUse[id] = true
		}
	}
	recent, coveredSince, err := recentlyCreatedFrom(ctx, trim.Binary, cutoff, now)
	if !coveredSince.IsZero() {
		report.EventsCoveredSince = coveredSince.UTC().Format(time.RFC3339)
	}
	if err != nil {
		return fail(fmt.Errorf("refusing every image removal: recent use cannot be ruled out: %w", err))
	}
	for _, ref := range recent {
		for _, id := range imagesPossiblyRunAs(images, ref) {
			inUse[id] = true
		}
	}
	type candidate struct {
		image dockerImage
		at    time.Time
	}
	var candidates []candidate
	for _, image := range images {
		if inUse[image.ID] || keptByPattern(image, trim.Keep) {
			continue
		}
		at, known := imageLastTouched(image)
		if !known || !at.Before(cutoff) {
			continue
		}
		candidates = append(candidates, candidate{image, at})
	}
	sort.Slice(candidates, func(i, j int) bool {
		if !candidates[i].at.Equal(candidates[j].at) {
			return candidates[i].at.Before(candidates[j].at)
		}
		return candidates[i].image.ID < candidates[j].image.ID
	})
	report.Images = make([]dockerImageOutcome, len(candidates))
	for i, c := range candidates {
		report.Images[i] = dockerImageOutcome{ID: c.image.ID, Tags: c.image.RepoTags, SizeBytes: c.image.Size, Status: imageNotReached}
	}
	report.FreeBefore = freeBytes(trimFilesystem(trim))
	var removed int
	var failures []string
	var stopErr error
	for i := range report.Images {
		outcome := &report.Images[i]
		if trim.MaxBytes > 0 && reclaimable <= trim.MaxBytes {
			for j := i; j < len(report.Images); j++ {
				report.Images[j].Status = imageNotNeeded
			}
			break
		}
		users, err := removeImage(ctx, procRoot, trim, outcome)
		if err != nil {
			stopErr = err
			break
		}
		if len(users) != 0 {
			report.ActiveUsers = users
			for j := i + 1; j < len(report.Images); j++ {
				report.Images[j].Status = imagePostponed
			}
			break
		}
		switch outcome.Status {
		case imageRmiFailed:
			failures = append(failures, outcome.ID+": "+outcome.Error)
		case imageRemoved:
			removed++
			if trim.MaxBytes > 0 {
				if reclaimable, err = dockerReclaimableImageBytes(ctx, trim.Binary); err != nil {
					stopErr = err
				}
			}
		}
		if stopErr != nil {
			break
		}
	}
	report.FreeAfter = freeBytes(trimFilesystem(trim))
	if size, err := dockerReclaimableImageBytes(ctx, trim.Binary); err == nil {
		report.SizeAfter = &size
		reclaimed := max(*report.SizeBefore-size, 0)
		report.Reclaimed = &reclaimed
	}
	switch {
	case stopErr != nil || len(failures) != 0:
		var msgs []string
		if stopErr != nil {
			msgs = append(msgs, "stopped: "+stopErr.Error())
		}
		if len(failures) != 0 {
			msgs = append(msgs, fmt.Sprintf("docker rmi failed for %d image(s): %s", len(failures), strings.Join(failures, "; ")))
		}
		report.Status, report.Error = cacheTrimFailed, truncate(strings.Join(msgs, "; "), 2000)
	case removed == 0 && len(report.ActiveUsers) != 0:
		report.Status = cacheInUse
	default:
		report.Status = cacheTrimmed
	}
	return report
}

// removeImage removes one candidate with non-forced `docker rmi --no-prune`,
// so Docker removes nothing else: by default rmi also deletes untagged parent
// images, which were never checked. The image itself is always removed by ID,
// which cannot name another image. Docker refuses to remove an image with
// several tags by ID without --force, so such an image first loses its extra
// tags (all but the last in sorted order), one `docker rmi --no-prune
// <repo:tag>` each.
//
// A tag can move to another image at any time (`docker tag`, a build or a
// pull), so every step is bound to the candidate's identity. Before the first
// step the candidate must still hold exactly the tags the candidate list
// read. Before each step removeImage checks again that no image build or
// pull runs and that no container uses the image, and before untagging it
// resolves the tag: one that names another image now stops the image's
// removal (tag_moved). After each step it compares every image's tags with
// those before: the candidate must hold exactly the tags expected (or be gone
// after the final removal), and no other image may have lost a tag or
// disappeared. Docker offers no untag-only operation, so a tag moved between
// resolving and untagging can still reach another image; that is detected,
// reported and stops the whole trim.
//
// A failed step stops the image's removal, leaving its remaining tags. It
// returns the processes that postponed the removal, and an error that stops
// the trim: Docker could not be asked, or a step changed another image.
func removeImage(ctx context.Context, procRoot string, trim config.CacheTrim, outcome *dockerImageOutcome) ([]string, error) {
	images, err := dockerImages(ctx, trim.Binary)
	if err != nil {
		return nil, err
	}
	before := imageTagSets(images)
	remaining := append([]string(nil), outcome.Tags...)
	sort.Strings(remaining)
	if current, ok := before[outcome.ID]; !ok || !sameStrings(current, remaining) {
		outcome.Status, outcome.Error = imageChanged, "image or its tags changed since the candidate list was read"
		return nil, nil
	}
	for {
		if users := cacheUsers(procRoot, trim); len(users) != 0 {
			outcome.Status = imagePostponed
			return users, nil
		}
		// A container created since the candidate list was read keeps the
		// image; the daemon matches it by image ID.
		out, err := dockerOutput(ctx, trim.Binary, "container", "ls", "--all", "--quiet", "--no-trunc",
			"--filter", "ancestor="+outcome.ID)
		if err != nil {
			return nil, err
		}
		if containers := nonEmptyLines(out); len(containers) != 0 {
			outcome.Status, outcome.Containers = imageInUse, containers
			return nil, nil
		}
		ref, expect := outcome.ID, []string(nil)
		if len(remaining) > 1 {
			ref, expect = remaining[0], remaining[1:]
			out, err := dockerOutput(ctx, trim.Binary, "image", "inspect", "--format", "{{.Id}}", ref)
			if err != nil {
				outcome.Status, outcome.Error = imageTagMoved, fmt.Sprintf("tag moved: %s cannot be resolved: %v", ref, err)
				return nil, nil
			}
			if now := strings.TrimSpace(string(out)); now != outcome.ID {
				outcome.Status, outcome.Error = imageTagMoved, fmt.Sprintf("tag moved: %s now names %s", ref, now)
				return nil, nil
			}
		}
		args := []string{"rmi", "--no-prune", ref}
		outcome.Commands = append(outcome.Commands, append([]string{trim.Binary}, args...))
		out, err = dockerCombined(ctx, trim.Binary, args...)
		outcome.Output = boundedOutput([]byte(outcome.Output + "\n" + string(out)))
		if err != nil {
			outcome.Status, outcome.Error = imageRmiFailed, fmt.Sprintf("%s: %v", ref, err)
			return nil, nil
		}
		if ref != outcome.ID {
			outcome.Untagged = append(outcome.Untagged, ref)
		}
		images, err := dockerImages(ctx, trim.Binary)
		if err != nil {
			return nil, err
		}
		after := imageTagSets(images)
		if problem := unexpectedImageChange(before, after, outcome.ID, expect, ref == outcome.ID); problem != "" {
			outcome.Status, outcome.Error = imageRmiFailed, fmt.Sprintf("after docker rmi --no-prune %s: %s", ref, problem)
			return nil, fmt.Errorf("%s: %s", outcome.ID, outcome.Error)
		}
		if ref == outcome.ID {
			outcome.Status = imageRemoved
			return nil, nil
		}
		before, remaining = after, expect
	}
}

// imageTagSets maps each image ID to its sorted tags.
func imageTagSets(images []dockerImage) map[string][]string {
	sets := make(map[string][]string, len(images))
	for _, image := range images {
		tags := append([]string{}, image.RepoTags...)
		sort.Strings(tags)
		sets[image.ID] = tags
	}
	return sets
}

// unexpectedImageChange says how a removal step changed more than it should
// have, or "" when it did not: the candidate id must be gone (deleted) or
// hold exactly the tags expect, and no other image may have lost a tag or
// disappeared. Images that appeared or gained tags are someone else's work
// and do not matter.
func unexpectedImageChange(before, after map[string][]string, id string, expect []string, deleted bool) string {
	current, exists := after[id]
	switch {
	case deleted && exists:
		return "the image still exists"
	case !deleted && !exists:
		return "the image was deleted, not only untagged"
	case !deleted && !sameStrings(current, expect):
		return fmt.Sprintf("the image holds tags %q, expected %q", current, expect)
	}
	var problems []string
	for other, tags := range before {
		if other == id {
			continue
		}
		now, ok := after[other]
		if !ok {
			problems = append(problems, fmt.Sprintf("image %s %q disappeared", other, tags))
			continue
		}
		for _, tag := range tags {
			if !containsString(now, tag) {
				problems = append(problems, fmt.Sprintf("image %s lost tag %s", other, tag))
			}
		}
	}
	sort.Strings(problems)
	return strings.Join(problems, "; ")
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// imagesPossiblyRunAs returns the IDs of every local image a container
// created from ref (as a create event records it) may have run. An image ID
// (sha256:<hex>) names exactly that image. Any other reference is a tag or
// digest that may have named another image then: tags move on every build,
// tag or pull, and Docker keeps no tag history, so resolving ref against
// today's tags could protect the new image and remove the one that ran. Such
// a reference protects every image with a tag or digest in its repository,
// and every untagged image, which is what a moved tag leaves behind and
// whose past tags cannot be known. A bare hex string is treated as both.
func imagesPossiblyRunAs(images []dockerImage, ref string) []string {
	var ids []string
	hex, isID := strings.CutPrefix(ref, "sha256:")
	isID = isID && isLowerHex(hex)
	if isLowerHex(hex) {
		for _, image := range images {
			if strings.HasPrefix(strings.TrimPrefix(image.ID, "sha256:"), hex) {
				ids = append(ids, image.ID)
			}
		}
	}
	if isID {
		return ids
	}
	repo := imageRepository(ref)
	for _, image := range images {
		if len(image.RepoTags) == 0 {
			ids = append(ids, image.ID)
			continue
		}
		for _, other := range append(append([]string(nil), image.RepoTags...), image.RepoDigests...) {
			if imageRepository(other) == repo {
				ids = append(ids, image.ID)
				break
			}
		}
	}
	return ids
}

// imageRepository is the repository of an image reference in Docker's short
// form, without tag or digest.
func imageRepository(ref string) string {
	normalized := normalizeImageRef(ref)
	if name, _, ok := strings.Cut(normalized, "@"); ok {
		return name
	}
	return normalized[:strings.LastIndex(normalized, ":")]
}

// dockerImages lists every top-level image with the details the candidate
// selection needs.
func dockerImages(ctx context.Context, binary string) ([]dockerImage, error) {
	out, err := dockerOutput(ctx, binary, "image", "ls", "--no-trunc", "--format", "{{.ID}}")
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var ids []string
	for _, id := range nonEmptyLines(out) {
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return nil, nil
	}
	out, err = dockerOutput(ctx, binary, append([]string{"image", "inspect"}, ids...)...)
	if err != nil {
		return nil, err
	}
	var images []dockerImage
	if err := json.Unmarshal(out, &images); err != nil {
		return nil, fmt.Errorf("docker image inspect: %w", err)
	}
	for _, image := range images {
		if !strings.HasPrefix(image.ID, "sha256:") {
			return nil, fmt.Errorf("docker image inspect: unexpected image ID %q", image.ID)
		}
	}
	return images, nil
}

// recentlyCreatedFrom returns the image of every container created between
// since and until, from the daemon's event history, and the time that history
// reaches back to. The daemon keeps only its most recent events in memory
// (256) and loses them when it restarts, so the history must be shown to
// cover since: its oldest event must be no later than since. A history that
// cannot be read or parsed, or does not reach back that far, is an error.
func recentlyCreatedFrom(ctx context.Context, binary string, since, until time.Time) ([]string, time.Time, error) {
	sinceArg, untilArg := strconv.FormatInt(since.Unix(), 10), strconv.FormatInt(until.Unix(), 10)
	out, err := dockerOutput(ctx, binary, "events", "--since", sinceArg, "--until", untilArg,
		"--filter", "type=container", "--filter", "event=create", "--format", "json")
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("docker event history unreadable: %w", err)
	}
	var images []string
	for _, line := range nonEmptyLines(out) {
		var event struct {
			Type, Action string
			Actor        struct{ Attributes map[string]string }
		}
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			return nil, time.Time{}, fmt.Errorf("docker event history unparsable: %w", err)
		}
		image := event.Actor.Attributes["image"]
		if event.Type != "container" || event.Action != "create" || image == "" {
			return nil, time.Time{}, fmt.Errorf("docker event history unparsable: unexpected event %s", truncate(line, 200))
		}
		images = append(images, image)
	}
	// Read the extent after the creates: the history only drops its oldest
	// events, so one that still reaches since now reached it before.
	out, err = dockerOutput(ctx, binary, "events", "--since", "1", "--until", untilArg, "--format", "{{.TimeNano}}")
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("docker event history unreadable: %w", err)
	}
	var oldest time.Time
	for _, line := range nonEmptyLines(out) {
		nanos, err := strconv.ParseInt(line, 10, 64)
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("docker event history unparsable: event time %q", truncate(line, 40))
		}
		if at := time.Unix(0, nanos); oldest.IsZero() || at.Before(oldest) {
			oldest = at
		}
	}
	if oldest.IsZero() {
		return nil, oldest, fmt.Errorf("docker event history is empty, so it does not reach back to %s (min_age)", since.UTC().Format(time.RFC3339))
	}
	if oldest.After(since) {
		return nil, oldest, fmt.Errorf("docker event history covers only since %s, not since %s (min_age): the daemon keeps only its last 256 events and none from before it restarted",
			oldest.UTC().Format(time.RFC3339), since.UTC().Format(time.RFC3339))
	}
	return images, oldest, nil
}

// imageLastTouched is the later of the image's creation and its last tag
// time. An image whose creation time is unknown is never a candidate.
func imageLastTouched(image dockerImage) (time.Time, bool) {
	created, err := time.Parse(time.RFC3339Nano, image.Created)
	if err != nil || created.IsZero() || created.Year() <= 1 {
		return time.Time{}, false
	}
	if tagged, err := time.Parse(time.RFC3339Nano, image.Metadata.LastTagTime); err == nil && tagged.After(created) {
		return tagged, true
	}
	return created, true
}

// keptByPattern reports whether any tag of image matches a keep pattern.
// Patterns and tags are compared in Docker's short form (nginx:1.27, not
// docker.io/library/nginx:1.27).
func keptByPattern(image dockerImage, keep []string) bool {
	for _, tag := range image.RepoTags {
		normalized := normalizeImageRef(tag)
		for _, pattern := range keep {
			if ok, _ := path.Match(normalizeImageRef(pattern), normalized); ok {
				return true
			}
		}
	}
	return false
}

// imageResolver maps an image reference as `docker container ls` prints it
// (a name with or without tag, name@digest, a full or short image ID) to the
// IDs of the local images it may mean. The daemon prints a container's image
// ID instead of its reference once that reference names another image, so
// today's tags resolve a container exactly. It errs towards more images: a
// hex string matches both a name and every ID it prefixes.
func imageResolver(images []dockerImage) func(string) []string {
	byRef := map[string][]string{}
	for _, image := range images {
		byRef[image.ID] = append(byRef[image.ID], image.ID)
		for _, ref := range append(append([]string(nil), image.RepoTags...), image.RepoDigests...) {
			key := normalizeImageRef(ref)
			byRef[key] = append(byRef[key], image.ID)
		}
	}
	return func(ref string) []string {
		ids := append([]string(nil), byRef[normalizeImageRef(ref)]...)
		ids = append(ids, byRef[ref]...)
		hex := strings.TrimPrefix(ref, "sha256:")
		if isLowerHex(hex) {
			for _, image := range images {
				if strings.HasPrefix(strings.TrimPrefix(image.ID, "sha256:"), hex) {
					ids = append(ids, image.ID)
				}
			}
		}
		return ids
	}
}

// normalizeImageRef writes a reference in Docker's short form: no docker.io
// registry or library/ namespace, and :latest when neither tag nor digest is
// given.
func normalizeImageRef(ref string) string {
	name, digest, hasDigest := strings.Cut(ref, "@")
	tag := ""
	if i := strings.LastIndex(name, ":"); i > strings.LastIndex(name, "/") {
		name, tag = name[:i], name[i+1:]
	}
	if domain, rest, ok := strings.Cut(name, "/"); ok && (domain == "docker.io" || domain == "index.docker.io") {
		name = rest
	}
	if rest, ok := strings.CutPrefix(name, "library/"); ok && !strings.Contains(rest, "/") {
		name = rest
	}
	switch {
	case hasDigest:
		return name + "@" + digest
	case tag == "":
		return name + ":latest"
	default:
		return name + ":" + tag
	}
}

func isLowerHex(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func nonEmptyLines(out []byte) []string {
	var lines []string
	for _, line := range strings.Split(string(out), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// dockerOutput runs a read-only Docker command and returns its stdout; a
// failure or timeout is an error carrying Docker's message.
func dockerOutput(ctx context.Context, binary string, args ...string) ([]byte, error) {
	runCtx, cancel := context.WithTimeout(ctx, cacheTrimTimeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, binary, args...)
	cmd.Env = dockerEnv()
	cmd.Dir = "/"
	out, err := cmd.Output()
	if err != nil {
		return nil, dockerError(runCtx, args, err)
	}
	return out, nil
}

// dockerCombined runs a Docker command and returns its combined output.
func dockerCombined(ctx context.Context, binary string, args ...string) ([]byte, error) {
	runCtx, cancel := context.WithTimeout(ctx, cacheTrimTimeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, binary, args...)
	cmd.Env = dockerEnv()
	cmd.Dir = "/"
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, dockerError(runCtx, args, err)
	}
	return out, nil
}

func dockerError(runCtx context.Context, args []string, err error) error {
	name := "docker " + args[0]
	if len(args) > 1 && !strings.HasPrefix(args[1], "-") && !strings.HasPrefix(args[1], "sha256:") {
		name += " " + args[1]
	}
	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("%s: timed out after %s", name, cacheTrimTimeout)
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) && len(exit.Stderr) != 0 {
		return fmt.Errorf("%s: %w: %s", name, err, boundedOutput(exit.Stderr))
	}
	return fmt.Errorf("%s: %w", name, err)
}
