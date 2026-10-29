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
	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

// ScratchDir is one open scratch directory (for example /tmp). Every entry is
// resolved beneath this descriptor, never by path.
type ScratchDir struct {
	path string
	dir  *os.File
	st   state
}

// OpenScratch opens path without following symlinks on the way.
func OpenScratch(path string) (*ScratchDir, error) {
	dir, err := openDirectory(path)
	if err != nil {
		return nil, fmt.Errorf("scratch directory: %w", err)
	}
	st, err := fstate(dir)
	if err != nil {
		dir.Close()
		return nil, err
	}
	return &ScratchDir{path: path, dir: dir, st: st}, nil
}

// Close releases the directory descriptor.
func (s *ScratchDir) Close() { s.dir.Close() }

// Names lists the depth-1 entries, sorted, within limit.
func (s *ScratchDir) Names(limit int) ([]string, error) {
	return readNames(s.dir, limit)
}

// Observe records one depth-1 entry without reading file contents: every
// member's identity and metadata, its size and newest change, and the
// screens (sensitive names anywhere inside, sockets, fifos and other
// unsupported types, mount crossings, extended attributes, outbound Git
// pointers). An error means the entry could not be observed; callers keep it.
func (s *ScratchDir) Observe(ctx context.Context, name string, patterns []string, limit int) (ScratchEntry, error) {
	entry := ScratchEntry{Name: name}
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name {
		return entry, fmt.Errorf("invalid scratch entry name %q", name)
	}
	if limit <= 0 {
		limit = defaultMaxEntries
	}
	w := &walker{ctx: ctx, source: s.path, rootState: s.st, patterns: patterns, max: limit, screen: true}
	if err := w.visit(s.dir, ".", name, 0); err != nil {
		return entry, err
	}
	if len(w.inv.members) == 0 {
		// Nothing recorded: a mount crossing or unsupported type at the top.
		entry.Refusal = strings.Join(w.refusals, "; ")
		if entry.Refusal == "" {
			entry.Refusal = "entry could not be recorded"
		}
		return entry, nil
	}
	top := w.inv.states[0]
	entry.Type, entry.Identity = w.inv.members[0].Type, top.id
	for i, st := range w.inv.states {
		entry.NewestNS = max(entry.NewestNS, st.mtimeNS, st.ctimeNS)
		if w.inv.members[i].Type == TypeFile {
			entry.SizeBytes += st.size
		}
	}
	entry.Members = len(w.inv.members)
	if len(w.secrets) > 0 {
		entry.Sensitive = w.secrets[0]
	}
	if len(w.refusals) > 0 {
		entry.Refusal = strings.Join(w.refusals, "; ")
	}
	if w.inv.worktreeAdmin != "" {
		entry.Refusal = "a linked Git worktree's history lives outside the scratch entry"
	}
	entry.inv = w.inv
	return entry, nil
}

// Unchanged reports whether every member of entry still has the identity,
// type, size, ownership, mode, mtime and ctime it was observed with. A new or
// removed child changes its directory's times, so it is caught too.
func (s *ScratchDir) Unchanged(entry ScratchEntry) error {
	if len(entry.inv.members) == 0 {
		return fmt.Errorf("%s was never observed", entry.Name)
	}
	if err := entry.inv.unchanged(s.dir); err != nil {
		return fmt.Errorf("%s changed since it was observed", entry.Name)
	}
	return nil
}

// ScratchReferences returns, for every depth-1 entry of dir that a process
// uses (cwd, root, executable, open descriptor or mapped file), one example
// reference. Any process that cannot be inspected is an error: nothing in
// dir can then be shown unused.
func ScratchReferences(ctx context.Context, procRoot, dir string) (map[string]string, error) {
	used := map[string]string{}
	unknown, err := processReferences(ctx, procRoot, func(pid, label, target string) bool {
		if !core.PathWithin(target, dir) || target == dir {
			return false
		}
		rel := strings.TrimPrefix(target, dir+"/")
		if dir == "/" {
			rel = strings.TrimPrefix(target, "/")
		}
		name, _, _ := strings.Cut(rel, "/")
		if _, seen := used[name]; !seen {
			used[name] = fmt.Sprintf("pid %s %s", pid, label)
		}
		return false
	})
	if err != nil {
		return nil, err
	}
	if unknown > 0 {
		return nil, fmt.Errorf("%d process(es) could not be inspected; no entry of %s can be shown unused", unknown, dir)
	}
	return used, nil
}

func scratchRule(dest config.WorkspaceArchiveCategoryDestination) config.WorkspaceArchiveRule {
	return config.WorkspaceArchiveRule{Archive: config.WorkspaceArchiveDestination{
		Directory: dest.Directory, ExpectMountSource: dest.ExpectMountSource, ExpectFSType: dest.ExpectFSType}}
}

// CreateScratch writes one tar of entries into dest, with a manifest holding
// every member's metadata and every file's SHA-256, re-reads the whole tar
// and compares it, re-checks that no entry changed, and publishes without
// replacing anything. It never modifies the scratch directory. preflight
// runs before any work and again before publication.
func (s *ScratchDir) CreateScratch(ctx context.Context, dest config.WorkspaceArchiveCategoryDestination, runID string, entries []ScratchEntry, preflight func() error) (ScratchManifest, *Binding, error) {
	var m ScratchManifest
	if len(entries) == 0 {
		return m, nil, errors.New("scratch archive needs at least one entry")
	}
	if preflight == nil {
		return m, nil, errors.New("scratch archive creation requires a fresh policy preflight")
	}
	if err := preflight(); err != nil {
		return m, nil, err
	}
	if core.PathsOverlap(s.path, dest.Directory) {
		return m, nil, errors.New("archive directory must be outside the scratch directory")
	}
	rule := scratchRule(dest)
	in := &inspected{source: s.dir}
	var err error
	if in.root, err = openDirectory(dest.Directory); err != nil {
		return m, nil, fmt.Errorf("archive directory: %w", err)
	}
	defer in.root.Close()
	if in.rootSt, err = fstate(in.root); err != nil {
		return m, nil, err
	}
	if in.mountSource, in.fstype, err = checkMount(rule, in.rootSt); err != nil {
		return m, nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if len(entry.inv.members) == 0 || entry.Refusal != "" || entry.Sensitive != "" {
			return m, nil, fmt.Errorf("%s is not archivable", entry.Name)
		}
		in.inv.members = append(in.inv.members, entry.inv.members...)
		in.inv.states = append(in.inv.states, entry.inv.states...)
		in.inv.contentBytes += entry.inv.contentBytes
		names = append(names, entry.Name)
	}
	base := ScratchArchiveName(runID)
	tarName, manifestName := base+".tar", base+".manifest.json"
	for _, name := range []string{tarName, manifestName} {
		exists, err := childExists(in.root, name)
		if err != nil {
			return m, nil, err
		}
		if exists {
			return m, nil, fmt.Errorf("archive output %s already exists; refusing to reuse or replace it", filepath.Join(dest.Directory, name))
		}
	}
	overhead := uint64(len(in.inv.members))*1536 + (1 << 20)
	if err = requireSpace(in.root, uint64(in.inv.contentBytes)+overhead); err != nil {
		return m, nil, err
	}
	stagePath, err := os.MkdirTemp(descriptorPath(in.root), ".partial-scratch-")
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
	readback, err := verifyTar(ctx, tarFile, members, tarBytes)
	if err != nil {
		return m, nil, err
	}
	if readback != streamSHA {
		return m, nil, errors.New("archive readback SHA-256 differs from the written stream; nothing is deleted")
	}
	if err = preflight(); err != nil {
		return m, nil, err
	}
	if st, err := fstate(in.root); err != nil || st.id != in.rootSt.id || st.mountID != in.rootSt.mountID {
		return m, nil, errors.New("archive directory identity or mount changed")
	}
	if err = in.inv.unchanged(s.dir); err != nil {
		return m, nil, err
	}
	m = ScratchManifest{
		Version: ScratchManifestVersion, RunID: runID, ScratchDirectory: s.path, Entries: names,
		ArchiveDirectory: in.rootSt.id, MountSource: in.mountSource, FSType: in.fstype,
		TarFile: tarName, TarBytes: tarBytes, StreamSHA256: streamSHA, ReadbackSHA256: readback,
		ContentBytes: in.inv.contentBytes, Members: members, CreatedAt: time.Now().UTC(),
	}
	m.VerifiedAt = time.Now().UTC()
	data, err := json.Marshal(m)
	if err != nil {
		return m, nil, err
	}
	if len(data) > maxManifestBytes {
		return m, nil, errors.New("scratch archive manifest exceeds its size bound; nothing is deleted")
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
	// receipt, and the already published tar refuses any rerun of this run.
	for _, item := range []struct{ from, to string }{{"content.tar", tarName}, {"manifest.json", manifestName}} {
		if err = publishNoReplace(int(stage.Fd()), item.from, int(in.root.Fd()), item.to); err != nil {
			return m, nil, fmt.Errorf("publish %s: %w; nothing is deleted", item.to, err)
		}
	}
	if err = in.root.Sync(); err != nil {
		return m, nil, err
	}
	sum := sha256.Sum256(data)
	binding := &Binding{Manifest: filepath.Join(dest.Directory, manifestName), ManifestSHA256: hex.EncodeToString(sum[:])}
	if _, err = CheckScratch(ctx, dest, *binding); err != nil {
		return m, nil, fmt.Errorf("published scratch archive failed read-back; nothing is deleted: %w", err)
	}
	return m, binding, nil
}

func validScratchManifest(m ScratchManifest, runID string) error {
	if m.Version != ScratchManifestVersion || (runID != "" && m.RunID != runID) || m.TarFile != ScratchArchiveName(m.RunID)+".tar" {
		return errors.New("scratch archive manifest does not belong to this run")
	}
	if m.StreamSHA256 == "" || m.StreamSHA256 != m.ReadbackSHA256 || m.TarBytes <= 0 {
		return errors.New("scratch archive manifest lacks a matching stream and readback checksum")
	}
	if m.CreatedAt.IsZero() || m.VerifiedAt.Before(m.CreatedAt) || m.VerifiedAt.After(time.Now().UTC()) {
		return errors.New("scratch archive manifest verification time is invalid")
	}
	if len(m.Entries) == 0 || len(m.Members) == 0 {
		return errors.New("scratch archive manifest lists no entries")
	}
	entries := make(map[string]bool, len(m.Entries))
	for _, entry := range m.Entries {
		if !validMemberPath(entry) || strings.Contains(entry, "/") || entries[entry] {
			return fmt.Errorf("scratch archive manifest entry %q is invalid", entry)
		}
		entries[entry] = true
	}
	dirs := map[string]bool{}
	seen := make(map[string]bool, len(m.Members))
	for _, member := range m.Members {
		if !validMemberPath(member.Path) || seen[member.Path] || member.Mode&^07777 != 0 || member.Size < 0 {
			return fmt.Errorf("scratch archive manifest member %q is invalid", member.Path)
		}
		top, _, nested := strings.Cut(member.Path, "/")
		if !entries[top] || nested && !dirs[filepath.Dir(member.Path)] {
			return fmt.Errorf("scratch archive manifest member %q is outside its entries or precedes its directory", member.Path)
		}
		switch member.Type {
		case TypeDirectory, TypeSymlink:
			if member.Size != 0 {
				return fmt.Errorf("scratch archive manifest member %q has a size", member.Path)
			}
		case TypeFile:
			if len(member.SHA256) != 64 {
				return fmt.Errorf("scratch archive manifest member %q lacks a checksum", member.Path)
			}
		default:
			return fmt.Errorf("scratch archive manifest member %q has unknown type %q", member.Path, member.Type)
		}
		seen[member.Path] = true
		dirs[member.Path] = member.Type == TypeDirectory
	}
	return nil
}

// loadScratch opens a pinned scratch manifest and its tar after checking the
// destination mount expectations.
func loadScratch(ctx context.Context, dest config.WorkspaceArchiveCategoryDestination, binding Binding) (ScratchManifest, *os.File, *os.File, error) {
	var m ScratchManifest
	if binding.Manifest == "" || binding.ManifestSHA256 == "" || filepath.Dir(binding.Manifest) != dest.Directory {
		return m, nil, nil, errors.New("no exact scratch archive manifest is pinned in the archive directory")
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
		return m, nil, nil, errors.New("oversized scratch archive manifest")
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != binding.ManifestSHA256 {
		return m, nil, nil, errors.New("scratch archive manifest checksum mismatch")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&m); err != nil {
		return m, nil, nil, err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return m, nil, nil, errors.New("trailing scratch archive manifest data")
	}
	if err = validScratchManifest(m, strings.TrimSuffix(strings.TrimPrefix(filepath.Base(binding.Manifest), "scratch-"), ".manifest.json")); err != nil {
		return m, nil, nil, err
	}
	tarFile, _, err := openRegularChild(root, m.TarFile)
	if err != nil {
		return m, nil, nil, err
	}
	ok = true
	return m, root, tarFile, nil
}

// CheckScratch re-reads the whole published tar of binding and compares the
// stream hash, member list, metadata and every file's SHA-256 with the
// manifest.
func CheckScratch(ctx context.Context, dest config.WorkspaceArchiveCategoryDestination, binding Binding) (ScratchManifest, error) {
	m, root, tarFile, err := loadScratch(ctx, dest, binding)
	if err != nil {
		return m, err
	}
	defer root.Close()
	defer tarFile.Close()
	readback, err := verifyTar(ctx, tarFile, m.Members, m.TarBytes)
	if err != nil {
		return m, err
	}
	if readback != m.StreamSHA256 {
		return m, errors.New("scratch archive tar checksum differs from its manifest")
	}
	return m, nil
}

// RestoreScratch extracts one archived entry to destination, which must not
// exist, verifying the whole tar and every restored file on the way. It never
// overwrites anything and never modifies the archive.
func RestoreScratch(ctx context.Context, dest config.WorkspaceArchiveCategoryDestination, binding Binding, entry, destination string) (ScratchManifest, error) {
	if !core.IsCanonicalPath(destination) || destination == "/" {
		return ScratchManifest{}, errors.New("restore destination must be a canonical absolute path")
	}
	if core.PathsOverlap(destination, dest.Directory) {
		return ScratchManifest{}, errors.New("restore must not modify the archive directory")
	}
	m, root, tarFile, err := loadScratch(ctx, dest, binding)
	if err != nil {
		return m, err
	}
	defer root.Close()
	defer tarFile.Close()
	found := false
	for _, name := range m.Entries {
		found = found || name == entry
	}
	if !found {
		return m, fmt.Errorf("run %s archived no entry %q", m.RunID, entry)
	}
	var selected []Member
	for _, member := range m.Members {
		if member.Path == entry || strings.HasPrefix(member.Path, entry+"/") {
			selected = append(selected, member)
		}
	}
	var content int64
	for _, member := range selected {
		content += member.Size
	}
	parent, err := openDirectory(filepath.Dir(destination))
	if err != nil {
		return m, err
	}
	defer parent.Close()
	base := filepath.Base(destination)
	if exists, err := childExists(parent, base); err != nil || exists {
		return m, fmt.Errorf("restore destination %s must not exist", destination)
	}
	if err = requireSpace(parent, uint64(content)+uint64(len(selected))*4096+(1<<20)); err != nil {
		return m, err
	}
	stageName := ".partial-restore-" + uuid.NewString()
	if err = unix.Mkdirat(int(parent.Fd()), stageName, 0700); err != nil {
		return m, err
	}
	defer os.RemoveAll(filepath.Join(descriptorPath(parent), stageName)) // only our private staging tree
	stage, err := openChild(parent, stageName, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return m, err
	}
	defer stage.Close()
	readback, err := readTar(ctx, tarFile, m.Members, m.TarBytes, func(member Member, content io.Reader) error {
		if member.Path != entry && !strings.HasPrefix(member.Path, entry+"/") {
			_, err := io.Copy(io.Discard, content)
			return err
		}
		return extractMember(stage, member, content)
	})
	if err != nil {
		return m, err
	}
	if readback != m.StreamSHA256 {
		return m, errors.New("scratch archive tar checksum differs from its manifest; restore discarded")
	}
	// Directory times last and deepest first: creating children changes them.
	for i := len(selected) - 1; i >= 0; i-- {
		member := selected[i]
		if member.Type != TypeDirectory {
			continue
		}
		dir, err := openBeneath(stage, member.Path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW)
		if err != nil {
			return m, err
		}
		err = setMetadata(dir, member)
		dir.Close()
		if err != nil {
			return m, err
		}
	}
	if err = verifyScratchRestore(ctx, stage, entry, selected); err != nil {
		return m, fmt.Errorf("restored %s failed verification; nothing was published: %w", entry, err)
	}
	if err = unix.Syncfs(int(stage.Fd())); err != nil {
		return m, err
	}
	if err = unix.Renameat2(int(stage.Fd()), entry, int(parent.Fd()), base, unix.RENAME_NOREPLACE); err != nil {
		return m, err
	}
	// Moving a directory to a new parent rewrites its ".." entry; restore
	// its recorded times afterwards.
	if top := selected[0]; top.Type == TypeDirectory {
		dir, err := openChild(parent, base, unix.O_RDONLY|unix.O_DIRECTORY)
		if err == nil {
			err = setMetadata(dir, top)
			dir.Close()
		}
		if err != nil {
			return m, fmt.Errorf("restored %s at %s, but its directory metadata could not be set: %w", entry, destination, err)
		}
	}
	return m, parent.Sync()
}

// verifyScratchRestore re-walks the staged entry, hashing every file, and
// compares it member by member with the manifest.
func verifyScratchRestore(ctx context.Context, stage *os.File, entry string, want []Member) error {
	st, err := fstate(stage)
	if err != nil {
		return err
	}
	w := &walker{ctx: ctx, source: descriptorPath(stage), rootState: st, max: len(want), hash: true}
	if err := w.visit(stage, ".", entry, 0); err != nil {
		return err
	}
	if len(w.refusals) > 0 {
		return errors.New(w.refusals[0])
	}
	if len(w.inv.members) != len(want) {
		return fmt.Errorf("restored %d members, manifest records %d", len(w.inv.members), len(want))
	}
	for i := range want {
		if w.inv.members[i] != want[i] {
			return fmt.Errorf("restored member %s differs from the manifest", want[i].Path)
		}
	}
	return nil
}

type scratchInventory = inventory
