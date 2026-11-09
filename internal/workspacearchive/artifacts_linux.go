//go:build linux

package workspacearchive

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
	"golang.org/x/sys/unix"
)

type artifactState = state

// ArtifactRoot is one open omp_session_artifacts root (an
// ".../.omp/agent/sessions" directory). Every session folder and file is
// resolved beneath this descriptor, never by path.
type ArtifactRoot struct {
	path string
	dir  *os.File
	st   state
}

// OpenArtifactRoot opens path without following symlinks on the way.
func OpenArtifactRoot(path string) (*ArtifactRoot, error) {
	dir, err := openDirectory(path)
	if err != nil {
		return nil, fmt.Errorf("session artifact root: %w", err)
	}
	st, err := fstate(dir)
	if err != nil {
		dir.Close()
		return nil, err
	}
	return &ArtifactRoot{path: path, dir: dir, st: st}, nil
}

// Close releases the root descriptor.
func (r *ArtifactRoot) Close() { r.dir.Close() }

// Sessions lists the session folders "<project>/<session>": real,
// non-dot-named directories two levels down, sorted. Everything else at
// those two levels (the sessions' own "<session>.jsonl" transcripts, other
// files, symlinks) is never walked. A listing above limit is an error, so
// no folder is selected from a partial view.
func (r *ArtifactRoot) Sessions(limit int) ([]string, error) {
	projects, err := readNames(r.dir, limit)
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", r.path, err)
	}
	var out []string
	for _, project := range projects {
		if strings.HasPrefix(project, ".") {
			continue
		}
		dir, ok, err := r.subdirectory(r.dir, project)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		names, err := readNames(dir, limit)
		if err == nil {
			for _, name := range names {
				if strings.HasPrefix(name, ".") {
					continue
				}
				var st state
				if st, err = statxAt(int(dir.Fd()), name, 0); err != nil {
					break
				}
				if st.kind() == unix.S_IFDIR && st.id.Device == r.st.id.Device && st.mountID == r.st.mountID {
					out = append(out, project+"/"+name)
				}
			}
		}
		dir.Close()
		if err != nil {
			return nil, fmt.Errorf("list %s: %w", filepath.Join(r.path, project), err)
		}
	}
	return out, nil
}

// subdirectory opens name, a child of dir, if it is a real directory on the
// root's mount.
func (r *ArtifactRoot) subdirectory(dir *os.File, name string) (*os.File, bool, error) {
	st, err := statxAt(int(dir.Fd()), name, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, false, nil
		}
		return nil, false, err
	}
	if st.kind() != unix.S_IFDIR || st.id.Device != r.st.id.Device || st.mountID != r.st.mountID {
		return nil, false, nil
	}
	child, err := openChild(dir, name, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return nil, false, err
	}
	if opened, err := fstate(child); err != nil || opened.id != st.id {
		child.Close()
		return nil, false, fmt.Errorf("%s changed while being opened", name)
	}
	return child, true, nil
}

// ObserveSession walks one session folder ("<project>/<session>") without
// reading file contents and returns every regular file inside it, at any
// depth, with its identity, size and mtime. Symlinks (never followed), other
// file types, hard-linked files, secret-like names (built-in screen and
// patterns), files with extended attributes and anything across a mount
// boundary are returned as skips. More than limit entries is an error.
func (r *ArtifactRoot) ObserveSession(ctx context.Context, session string, patterns []string, limit int) ([]ArtifactFile, []ArtifactSkip, error) {
	if !validMemberPath(session) || strings.Count(session, "/") != 1 {
		return nil, nil, fmt.Errorf("invalid session folder %q", session)
	}
	if limit <= 0 {
		limit = defaultMaxEntries
	}
	dir, err := openBeneath(r.dir, session, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW)
	if err != nil {
		return nil, nil, err
	}
	defer dir.Close()
	st, err := fstate(dir)
	if err != nil {
		return nil, nil, err
	}
	if st.id.Device != r.st.id.Device || st.mountID != r.st.mountID {
		return nil, nil, fmt.Errorf("%s crosses a mount boundary", session)
	}
	o := &artifactWalk{ctx: ctx, root: r, patterns: patterns, limit: limit}
	if err := o.walk(dir, session, 0); err != nil {
		return nil, nil, err
	}
	return o.files, o.skips, nil
}

type artifactWalk struct {
	ctx      context.Context
	root     *ArtifactRoot
	patterns []string
	limit    int
	seen     int
	files    []ArtifactFile
	skips    []ArtifactSkip
}

func (o *artifactWalk) walk(dir *os.File, rel string, depth int) error {
	if depth > maxTreeDepth {
		return fmt.Errorf("%s exceeds the %d-level depth bound", rel, maxTreeDepth)
	}
	names, err := readNames(dir, o.limit)
	if err != nil {
		return fmt.Errorf("list %s: %w", rel, err)
	}
	for _, name := range names {
		if err := o.ctx.Err(); err != nil {
			return err
		}
		if o.seen++; o.seen > o.limit {
			return fmt.Errorf("session folder holds more than %d entries; none of it is selected from a partial walk", o.limit)
		}
		path := rel + "/" + name
		st, err := statxAt(int(dir.Fd()), name, 0)
		if err != nil {
			if errors.Is(err, unix.ENOENT) {
				continue // removed meanwhile: nothing to archive
			}
			return fmt.Errorf("stat %s: %w", path, err)
		}
		if st.id.Device != o.root.st.id.Device || st.mountID != o.root.st.mountID {
			o.skip(path, "crosses a mount boundary")
			continue
		}
		switch st.kind() {
		case unix.S_IFDIR:
			child, err := openChild(dir, name, unix.O_RDONLY|unix.O_DIRECTORY)
			if err != nil {
				return err
			}
			opened, err := fstate(child)
			if err == nil && opened.id != st.id {
				err = fmt.Errorf("%s changed while being inspected", path)
			}
			if err == nil {
				err = o.walk(child, path, depth+1)
			}
			child.Close()
			if err != nil {
				return err
			}
		case unix.S_IFREG:
			switch {
			case st.nlink != 1:
				o.skip(path, "hard-linked file")
			case secretLike(name, filepath.Join(o.root.path, rel), o.patterns):
				o.skip(path, "sensitive name")
			case hasXattrs(unix.Llistxattr(fmt.Sprintf("%s/%s", descriptorPath(dir), name), nil)):
				o.skip(path, "extended attributes are unsupported")
			default:
				o.files = append(o.files, ArtifactFile{Path: path, Identity: st.id, Size: st.size, ModifiedNS: st.mtimeNS, st: st})
			}
		case unix.S_IFLNK:
			o.skip(path, "symlink")
		default:
			o.skip(path, "not a regular file")
		}
	}
	return nil
}

func (o *artifactWalk) skip(path, reason string) {
	o.skips = append(o.skips, ArtifactSkip{Path: path, Reason: reason})
}

// artifactOutputs names one batch's archive files.
func artifactOutputs(name string) (tarName, manifestName string) {
	return name + ".tar", name + ".manifest.json"
}

// CreateBatch writes one tar of files (all inside one session folder) into
// dest, named name, with a manifest holding every file's metadata, identity
// and SHA-256. It re-reads the whole tar and compares it, re-checks that no
// file changed, and publishes without replacing anything. It never modifies
// the session folder. preflight runs before any work and again before
// publication.
func (r *ArtifactRoot) CreateBatch(ctx context.Context, dest config.WorkspaceArchiveCategoryDestination, name, session string, files []ArtifactFile, preflight func() error) (ArtifactManifest, *Binding, error) {
	var m ArtifactManifest
	if len(files) == 0 {
		return m, nil, errors.New("artifact batch needs at least one file")
	}
	if preflight == nil {
		return m, nil, errors.New("artifact batch creation requires a fresh policy preflight")
	}
	if name == "" || filepath.Base(name) != name || strings.HasPrefix(name, ".") {
		return m, nil, fmt.Errorf("invalid artifact batch name %q", name)
	}
	if err := preflight(); err != nil {
		return m, nil, err
	}
	if core.PathsOverlap(r.path, dest.Directory) {
		return m, nil, errors.New("archive directory must be outside the session artifact root")
	}
	in := &inspected{source: r.dir}
	var err error
	if in.root, err = openDirectory(dest.Directory); err != nil {
		return m, nil, fmt.Errorf("archive directory: %w", err)
	}
	defer in.root.Close()
	if in.rootSt, err = fstate(in.root); err != nil {
		return m, nil, err
	}
	if in.mountSource, in.fstype, err = checkMount(scratchRule(dest), in.rootSt); err != nil {
		return m, nil, err
	}
	seen := make(map[string]bool, len(files))
	for _, f := range files {
		if f.st.kind() != unix.S_IFREG || !validMemberPath(f.Path) || !strings.HasPrefix(f.Path, session+"/") || seen[f.Path] {
			return m, nil, fmt.Errorf("%s is not an observed file of session folder %s", f.Path, session)
		}
		seen[f.Path] = true
		in.inv.members = append(in.inv.members, regularMember(f.Path, f.st))
		in.inv.states = append(in.inv.states, f.st)
		in.inv.contentBytes += f.st.size
	}
	tarName, manifestName := artifactOutputs(name)
	for _, output := range []string{tarName, manifestName} {
		exists, err := childExists(in.root, output)
		if err != nil {
			return m, nil, err
		}
		if exists {
			return m, nil, fmt.Errorf("archive output %s already exists; refusing to reuse or replace it", filepath.Join(dest.Directory, output))
		}
	}
	overhead := uint64(len(in.inv.members))*1536 + (1 << 20)
	if err = requireSpace(in.root, uint64(in.inv.contentBytes)+overhead); err != nil {
		return m, nil, err
	}
	stagePath, err := os.MkdirTemp(descriptorPath(in.root), ".partial-artifacts-")
	if err != nil {
		return m, nil, err
	}
	defer os.RemoveAll(stagePath) // only this newly allocated private staging directory
	stage, err := openChild(in.root, filepath.Base(stagePath), unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return m, nil, err
	}
	defer stage.Close()
	tarFile, err := createChild(stage, "content.tar")
	if err != nil {
		return m, nil, err
	}
	defer tarFile.Close()
	members := in.inv.members
	streamSHA, tarBytes, err := writeTar(ctx, in, tarFile, members)
	if err != nil {
		return m, nil, err
	}
	if err = tarFile.Sync(); err != nil {
		return m, nil, err
	}
	readback, err := verifyTar(ctx, tarFile, tarLayout{members: members}, tarBytes)
	if err != nil {
		return m, nil, err
	}
	if readback != streamSHA {
		return m, nil, errors.New("archive readback SHA-256 differs from the written stream; nothing is moved")
	}
	if err = preflight(); err != nil {
		return m, nil, err
	}
	if st, err := fstate(in.root); err != nil || st.id != in.rootSt.id || st.mountID != in.rootSt.mountID {
		return m, nil, errors.New("archive directory identity or mount changed")
	}
	if err = in.inv.unchanged(r.dir); err != nil {
		return m, nil, err
	}
	m = ArtifactManifest{
		Version: ArtifactManifestVersion, Name: name, Root: r.path, Session: session,
		ArchiveDirectory: in.rootSt.id, MountSource: in.mountSource, FSType: in.fstype,
		TarFile: tarName, TarBytes: tarBytes, StreamSHA256: streamSHA, ReadbackSHA256: readback,
		ContentBytes: in.inv.contentBytes, CreatedAt: time.Now().UTC(),
	}
	m.Members = make([]ArtifactMember, len(members))
	for i := range members {
		m.Members[i] = ArtifactMember{Member: members[i], Identity: in.inv.states[i].id}
	}
	m.VerifiedAt = time.Now().UTC()
	data, err := json.Marshal(m)
	if err != nil {
		return m, nil, err
	}
	if len(data) > maxManifestBytes {
		return m, nil, errors.New("artifact batch manifest exceeds its size bound; nothing is moved")
	}
	manifest, err := createChild(stage, "manifest.json")
	if err != nil {
		return m, nil, err
	}
	_, err = manifest.Write(data)
	if err == nil {
		err = manifest.Sync()
	}
	if closeErr := manifest.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return m, nil, err
	}
	if err = stage.Sync(); err != nil {
		return m, nil, err
	}
	// The manifest is published last: an interrupted publication leaves no
	// receipt, and the already published tar refuses any rerun of this name.
	for _, item := range []struct{ from, to string }{{"content.tar", tarName}, {"manifest.json", manifestName}} {
		if err = publishNoReplace(int(stage.Fd()), item.from, int(in.root.Fd()), item.to); err != nil {
			return m, nil, fmt.Errorf("publish %s: %w; nothing is moved", item.to, err)
		}
	}
	if err = in.root.Sync(); err != nil {
		return m, nil, err
	}
	sum := sha256.Sum256(data)
	binding := &Binding{Manifest: filepath.Join(dest.Directory, manifestName), ManifestSHA256: hex.EncodeToString(sum[:])}
	if _, err = CheckArtifacts(ctx, dest, *binding); err != nil {
		return m, nil, fmt.Errorf("published artifact batch failed read-back; nothing is moved: %w", err)
	}
	return m, binding, nil
}

func validArtifactManifest(m ArtifactManifest, name string) error {
	tarName, _ := artifactOutputs(name)
	if m.Version != ArtifactManifestVersion || m.Name != name || m.TarFile != tarName {
		return errors.New("artifact batch manifest does not belong to this batch")
	}
	if m.StreamSHA256 == "" || m.StreamSHA256 != m.ReadbackSHA256 || m.TarBytes <= 0 {
		return errors.New("artifact batch manifest lacks a matching stream and readback checksum")
	}
	if m.CreatedAt.IsZero() || m.VerifiedAt.Before(m.CreatedAt) || m.VerifiedAt.After(time.Now().UTC()) {
		return errors.New("artifact batch manifest verification time is invalid")
	}
	if !core.IsCanonicalPath(m.Root) || !validMemberPath(m.Session) || strings.Count(m.Session, "/") != 1 || len(m.Members) == 0 {
		return errors.New("artifact batch manifest names no session folder or files")
	}
	seen := make(map[string]bool, len(m.Members))
	var content int64
	for _, member := range m.Members {
		if !validMemberPath(member.Path) || !strings.HasPrefix(member.Path, m.Session+"/") || seen[member.Path] || !validFile(member.Member) || member.Identity.Zero() {
			return fmt.Errorf("artifact batch manifest member %q is invalid", member.Path)
		}
		seen[member.Path] = true
		content += member.Size
	}
	if content != m.ContentBytes {
		return errors.New("artifact batch manifest content size differs from its members")
	}
	return nil
}

// loadArtifacts opens a pinned artifact batch manifest and its tar after
// checking the destination mount expectations.
func loadArtifacts(ctx context.Context, dest config.WorkspaceArchiveCategoryDestination, binding Binding) (ArtifactManifest, *os.File, *os.File, error) {
	var m ArtifactManifest
	if binding.Manifest == "" || binding.ManifestSHA256 == "" || filepath.Dir(binding.Manifest) != dest.Directory ||
		!strings.HasSuffix(binding.Manifest, ".manifest.json") {
		return m, nil, nil, errors.New("no exact artifact batch manifest is pinned in the archive directory")
	}
	root, err := openDirectory(dest.Directory)
	if err != nil {
		return m, nil, nil, fmt.Errorf("archive directory: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			root.Close()
		}
	}()
	rootSt, err := fstate(root)
	if err != nil {
		return m, nil, nil, err
	}
	if _, _, err = checkMount(scratchRule(dest), rootSt); err != nil {
		return m, nil, nil, err
	}
	manifest, _, err := openRegularChild(root, filepath.Base(binding.Manifest))
	if err != nil {
		return m, nil, nil, err
	}
	data, err := io.ReadAll(contextReader{ctx, io.LimitReader(manifest, maxManifestBytes+1)})
	manifest.Close()
	if err != nil {
		return m, nil, nil, err
	}
	if len(data) > maxManifestBytes {
		return m, nil, nil, errors.New("oversized artifact batch manifest")
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != binding.ManifestSHA256 {
		return m, nil, nil, errors.New("artifact batch manifest checksum mismatch")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&m); err != nil {
		return m, nil, nil, err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return m, nil, nil, errors.New("trailing artifact batch manifest data")
	}
	if err = validArtifactManifest(m, strings.TrimSuffix(filepath.Base(binding.Manifest), ".manifest.json")); err != nil {
		return m, nil, nil, err
	}
	tarFile, _, err := openRegularChild(root, m.TarFile)
	if err != nil {
		return m, nil, nil, err
	}
	ok = true
	return m, root, tarFile, nil
}

// CheckArtifacts re-reads the whole published tar of binding and compares
// the stream hash, member list, metadata and every file's SHA-256 with the
// manifest.
func CheckArtifacts(ctx context.Context, dest config.WorkspaceArchiveCategoryDestination, binding Binding) (ArtifactManifest, error) {
	m, root, tarFile, err := loadArtifacts(ctx, dest, binding)
	if err != nil {
		return m, err
	}
	defer root.Close()
	defer tarFile.Close()
	members := make([]Member, len(m.Members))
	for i := range m.Members {
		members[i] = m.Members[i].Member
	}
	readback, err := verifyTar(ctx, tarFile, tarLayout{members: members}, m.TarBytes)
	if err != nil {
		return m, err
	}
	if readback != m.StreamSHA256 {
		return m, errors.New("artifact batch tar checksum differs from its manifest")
	}
	return m, nil
}

// VerifyFile checks that the file member names below the root is still
// exactly what was archived: a single-link regular file with the archived
// identity, size and mtime, whose contents hash to the archived SHA-256.
func (r *ArtifactRoot) VerifyFile(ctx context.Context, member ArtifactMember) error {
	if !validMemberPath(member.Path) {
		return fmt.Errorf("invalid artifact path %q", member.Path)
	}
	f, err := openBeneath(r.dir, member.Path, unix.O_PATH|unix.O_NOFOLLOW)
	if err != nil {
		return err
	}
	st, err := fstate(f)
	f.Close()
	if err != nil {
		return err
	}
	if st.kind() != unix.S_IFREG {
		return errors.New("no longer a regular file")
	}
	f, err = openBeneath(r.dir, member.Path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK)
	if err != nil {
		return err
	}
	defer f.Close()
	return verifyArtifact(ctx, f, member)
}

// VerifyArtifactCopy is VerifyFile for a quarantined copy at the absolute
// path, which is walked without following any symlink.
func VerifyArtifactCopy(ctx context.Context, path string, member ArtifactMember) error {
	f, err := openPath(path, unix.O_PATH)
	if err != nil {
		return err
	}
	st, err := fstate(f)
	f.Close()
	if err != nil {
		return err
	}
	if st.kind() != unix.S_IFREG {
		return errors.New("no longer a regular file")
	}
	f, err = openPath(path, unix.O_RDONLY)
	if err != nil {
		return err
	}
	defer f.Close()
	return verifyArtifact(ctx, f, member)
}

func verifyArtifact(ctx context.Context, f *os.File, member ArtifactMember) error {
	before, err := fstate(f)
	if err != nil {
		return err
	}
	if before.kind() != unix.S_IFREG || before.nlink != 1 || before.id != member.Identity || before.size != member.Size || before.mtimeNS != member.ModifiedNS {
		return errors.New("its identity, size or mtime differs from the archived file")
	}
	sum, err := hashRegular(ctx, f, member.Size, member.Path)
	if err != nil {
		return err
	}
	if sum != member.SHA256 {
		return errors.New("its contents differ from the archived file")
	}
	if after, err := fstate(f); err != nil || after != before {
		return errors.New("it changed while being verified")
	}
	return nil
}

// OpenFiles makes one pass over procfs and returns, for every path in paths
// that some process holds as an open descriptor, mapped file, executable,
// cwd or root, one example reference. Any process that cannot be inspected,
// or an unreadable procfs, is an error: then no file can be shown unused.
func OpenFiles(ctx context.Context, procRoot string, paths []string) (map[string]string, error) {
	want := make(map[string]bool, len(paths))
	for _, path := range paths {
		want[path] = true
	}
	used := map[string]string{}
	unknown, err := processReferences(ctx, procRoot, nil, func(pid, label, target string) bool {
		if want[target] {
			if _, seen := used[target]; !seen {
				used[target] = fmt.Sprintf("pid %s %s", pid, label)
			}
		}
		return false
	})
	if err != nil {
		return nil, err
	}
	if unknown > 0 {
		return nil, fmt.Errorf("%d process(es) could not be inspected; no session artifact can be shown unused", unknown)
	}
	return used, nil
}

// Same is VerifyFile without reading contents: the file is still a
// single-link regular file with the archived identity, size and mtime. It is
// the cheap re-check made immediately before a verified file moves.
func (r *ArtifactRoot) Same(member ArtifactMember) error {
	if !validMemberPath(member.Path) {
		return fmt.Errorf("invalid artifact path %q", member.Path)
	}
	st, err := statBeneath(r.dir, member.Path)
	if err != nil {
		return err
	}
	if st.kind() != unix.S_IFREG || st.nlink != 1 || st.id != member.Identity || st.size != member.Size || st.mtimeNS != member.ModifiedNS {
		return errors.New("it changed after it was verified")
	}
	return nil
}
