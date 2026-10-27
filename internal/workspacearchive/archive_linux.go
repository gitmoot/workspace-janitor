//go:build linux

package workspacearchive

import (
	"archive/tar"
	"bufio"
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
	"time"

	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

// maxManifestBytes bounds the member list held in memory (about 600 bytes
// per member at the default 200000-entry bound).
const maxManifestBytes = 128 << 20

// inspected holds the open, verified source and destination of one archive.
type inspected struct {
	source, root        *os.File
	sourceState, rootSt state
	inv                 inventory
	mountSource, fstype string
}

func (in *inspected) close() {
	if in.source != nil {
		in.source.Close()
	}
	if in.root != nil {
		in.root.Close()
	}
}

func (s Scope) limit() int {
	if s.MaxEntries <= 0 {
		return defaultMaxEntries
	}
	return s.MaxEntries
}

// Inspect runs every refusal check without writing anything: secret-like
// names, unsupported members, mount crossings, destination mount
// expectations, live process references and external dependents.
func Inspect(ctx context.Context, rule config.WorkspaceArchiveRule, scope Scope) (Inspection, error) {
	in, err := inspect(ctx, rule, scope)
	if err != nil {
		return Inspection{}, err
	}
	defer in.close()
	return Inspection{Source: in.sourceState.id, Members: len(in.inv.members), ContentBytes: in.inv.contentBytes, LinkedWorktree: in.inv.worktreeAdmin != "", MountSource: in.mountSource, FSType: in.fstype}, nil
}

func inspect(ctx context.Context, rule config.WorkspaceArchiveRule, scope Scope) (*inspected, error) {
	if core.PathsOverlap(rule.Path, rule.Archive.Directory) {
		return nil, errors.New("archive directory must be outside the archived workspace")
	}
	if len(scope.SearchRoots) == 0 {
		return nil, errors.New("external dependent scan requires at least one search root")
	}
	in := &inspected{}
	ok := false
	defer func() {
		if !ok {
			in.close()
		}
	}()
	var err error
	if in.root, err = openDirectory(rule.Archive.Directory); err != nil {
		return nil, fmt.Errorf("archive directory: %w", err)
	}
	if in.rootSt, err = fstate(in.root); err != nil {
		return nil, err
	}
	if in.mountSource, in.fstype, err = checkMount(rule, in.rootSt); err != nil {
		return nil, err
	}
	if in.source, err = openDirectory(rule.Path); err != nil {
		return nil, fmt.Errorf("workspace: %w", err)
	}
	walk, err := scanTree(ctx, in.source, rule.Path, scope.SensitiveNames, scope.limit(), false, true)
	if err != nil {
		return nil, err
	}
	if err = walk.err(); err != nil {
		return nil, err
	}
	in.sourceState, in.inv = walk.rootState, walk.inv
	if in.sourceState.id == in.rootSt.id {
		return nil, errors.New("archive directory and workspace are the same directory")
	}
	if err = liveReferences(ctx, scope.ProcRoot, rule.Path); err != nil {
		return nil, err
	}
	if err = externalDependents(ctx, rule.Path, scope.SearchRoots, scope.limit()); err != nil {
		return nil, err
	}
	ok = true
	return in, nil
}

// fresh repeats the live checks immediately before publication.
func (in *inspected) fresh(ctx context.Context, rule config.WorkspaceArchiveRule, scope Scope) error {
	st, err := fstate(in.root)
	if err != nil || st.id != in.rootSt.id || st.mountID != in.rootSt.mountID {
		return errors.New("archive directory identity or mount changed")
	}
	if _, _, err := checkMount(rule, st); err != nil {
		return err
	}
	if err := in.inv.unchanged(in.source); err != nil {
		return err
	}
	if err := liveReferences(ctx, scope.ProcRoot, rule.Path); err != nil {
		return err
	}
	return externalDependents(ctx, rule.Path, scope.SearchRoots, scope.limit())
}

// Create writes <name>.tar, <name>.manifest.json and, for a linked worktree,
// <name>.bundle into the archive directory. Nothing is replaced: any existing
// output refuses the run, and partial output from an interrupted run is never
// reused. The source is never modified or removed. preflight must recheck the
// caller's policy authority; it runs before any work and again before
// publication.
func Create(ctx context.Context, rule config.WorkspaceArchiveRule, scope Scope, preflight func() error) (Manifest, *Binding, error) {
	var m Manifest
	if preflight == nil {
		return m, nil, errors.New("workspace archive creation requires a fresh policy preflight")
	}
	if rule.Archive.Manifest != "" || rule.Archive.ManifestSHA256 != "" {
		return m, nil, errors.New("an archive manifest is already pinned; verify or restore it instead of creating another")
	}
	if err := preflight(); err != nil {
		return m, nil, err
	}
	in, err := inspect(ctx, rule, scope)
	if err != nil {
		return m, nil, err
	}
	defer in.close()
	finals := []string{TarName(rule), ManifestName(rule), BundleName(rule)}
	for _, name := range finals {
		exists, err := childExists(in.root, name)
		if err != nil {
			return m, nil, err
		}
		if exists {
			return m, nil, fmt.Errorf("archive output %s already exists; refusing to reuse or replace it", filepath.Join(rule.Archive.Directory, name))
		}
	}
	overhead := uint64(len(in.inv.members))*1536 + (1 << 20)
	if err = requireSpace(in.root, uint64(in.inv.contentBytes)+overhead); err != nil {
		return m, nil, err
	}
	stagePath, err := os.MkdirTemp(descriptorPath(in.root), ".partial-workspace-")
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
		return m, nil, errors.New("archive readback SHA-256 differs from the written stream; original retained")
	}
	var bundle *Bundle
	var bundleFile *os.File
	if in.inv.worktreeAdmin != "" {
		if bundle, bundleFile, err = createBundle(ctx, rule.Path, in.inv.worktreeAdmin, in.root, stage); err != nil {
			return m, nil, err
		}
		defer bundleFile.Close()
		bundle.File = BundleName(rule)
	}
	if err = preflight(); err != nil {
		return m, nil, err
	}
	if err = in.fresh(ctx, rule, scope); err != nil {
		return m, nil, err
	}
	m = Manifest{
		Version: ManifestVersion, Name: rule.Name, SourcePath: rule.Path, Source: in.sourceState.id,
		RuleSHA256: RuleHash(rule), Rule: archiveRule(rule), ArchiveDirectory: in.rootSt.id,
		MountSource: in.mountSource, FSType: in.fstype, TarFile: TarName(rule), TarBytes: tarBytes,
		StreamSHA256: streamSHA, ReadbackSHA256: readback, ContentBytes: in.inv.contentBytes,
		Members: members, Bundle: bundle, CreatedAt: time.Now().UTC(),
	}
	m.VerifiedAt = time.Now().UTC()
	data, err := json.Marshal(m)
	if err != nil {
		return m, nil, err
	}
	if len(data) > maxManifestBytes {
		return m, nil, errors.New("archive manifest exceeds its size bound; retain the original")
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
	// receipt, and the already published names refuse any rerun.
	publish := []struct{ from, to string }{{"content.tar", TarName(rule)}}
	if bundle != nil {
		publish = append(publish, struct{ from, to string }{"history.bundle", BundleName(rule)})
	}
	publish = append(publish, struct{ from, to string }{"manifest.json", ManifestName(rule)})
	for _, item := range publish {
		if err = unix.Renameat2(int(stage.Fd()), item.from, int(in.root.Fd()), item.to, unix.RENAME_NOREPLACE); err != nil {
			return m, nil, fmt.Errorf("publish %s: %w; inspect any already published outputs before retrying", item.to, err)
		}
	}
	if err = in.root.Sync(); err != nil {
		return m, nil, err
	}
	sum := sha256.Sum256(data)
	binding := &Binding{Manifest: config.WorkspaceArchiveManifestPath(rule), ManifestSHA256: hex.EncodeToString(sum[:])}
	rule.Archive.Manifest, rule.Archive.ManifestSHA256 = binding.Manifest, binding.ManifestSHA256
	if _, _, err = Check(ctx, rule, true); err != nil {
		return m, nil, fmt.Errorf("published archive failed read-back; original retained: %w", err)
	}
	return m, binding, nil
}

func header(m Member) *tar.Header {
	h := &tar.Header{Name: m.Path, Mode: int64(m.Mode), Uid: int(m.UID), Gid: int(m.GID), ModTime: time.Unix(0, m.ModifiedNS), Format: tar.FormatPAX}
	switch m.Type {
	case TypeDirectory:
		h.Typeflag = tar.TypeDir
		if m.Path == "." {
			h.Name = "./"
		} else {
			h.Name += "/"
		}
	case TypeSymlink:
		h.Typeflag, h.Linkname = tar.TypeSymlink, m.Linkname
	default:
		h.Typeflag, h.Size = tar.TypeReg, m.Size
	}
	return h
}

func headerMatches(h *tar.Header, m Member) bool {
	want := header(m)
	return h.Name == want.Name && h.Typeflag == want.Typeflag && h.Linkname == want.Linkname && h.Size == want.Size &&
		h.Mode == want.Mode && h.Uid == want.Uid && h.Gid == want.Gid && h.ModTime.UnixNano() == m.ModifiedNS
}

// writeTar streams the tree into out, hashing every byte written and every
// regular file read. Each file must keep its recorded identity and metadata.
func writeTar(ctx context.Context, in *inspected, out *os.File, members []Member) (string, int64, error) {
	stream, count := sha256.New(), &countingWriter{}
	buffered := bufio.NewWriterSize(io.MultiWriter(spaceWriter{in.root, 0, out}, stream, count), 1<<20)
	tw := tar.NewWriter(buffered)
	for i := range members {
		m := &members[i]
		if err := ctx.Err(); err != nil {
			return "", 0, err
		}
		if err := tw.WriteHeader(header(*m)); err != nil {
			return "", 0, fmt.Errorf("archive %s: %w", m.Path, err)
		}
		if m.Type != TypeFile {
			continue
		}
		if err := copyMember(ctx, in, tw, m, in.inv.states[i]); err != nil {
			return "", 0, err
		}
	}
	if err := tw.Close(); err != nil {
		return "", 0, err
	}
	if err := buffered.Flush(); err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(stream.Sum(nil)), count.n, nil
}

func copyMember(ctx context.Context, in *inspected, tw io.Writer, m *Member, recorded state) error {
	f, err := openBeneath(in.source, m.Path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK)
	if err != nil {
		return err
	}
	defer f.Close()
	if before, err := fstate(f); err != nil || before != recorded {
		return fmt.Errorf("%s changed before it was archived; original retained", m.Path)
	}
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(tw, hash), contextReader{ctx, io.LimitReader(f, m.Size)})
	if err != nil {
		return fmt.Errorf("archive %s: %w", m.Path, err)
	}
	if after, err := fstate(f); err != nil || after != recorded || n != m.Size {
		return fmt.Errorf("%s changed while being archived; original retained", m.Path)
	}
	m.SHA256 = hex.EncodeToString(hash.Sum(nil))
	return nil
}

// verifyTar re-reads the archive file once: it hashes every byte and checks
// that the member list, metadata and file contents equal the manifest.
func verifyTar(ctx context.Context, file *os.File, members []Member, size int64) (string, error) {
	return readTar(ctx, file, members, size, nil)
}

// readTar is the single bounded pass shared by verification and restore.
// extract, when set, receives each verified member with its content reader.
func readTar(ctx context.Context, file *os.File, members []Member, size int64, extract func(Member, io.Reader) error) (string, error) {
	st, err := fstate(file)
	if err != nil || st.size != size || st.kind() != unix.S_IFREG {
		return "", errors.New("archive tar size or type differs from its manifest")
	}
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	hash, count := sha256.New(), &countingWriter{}
	stream := io.TeeReader(contextReader{ctx, io.LimitReader(file, size+1)}, io.MultiWriter(hash, count))
	tr := tar.NewReader(stream)
	for _, m := range members {
		h, err := tr.Next()
		if err != nil {
			return "", fmt.Errorf("archive ends before member %s: %w", m.Path, err)
		}
		if !headerMatches(h, m) {
			return "", fmt.Errorf("archive member %s differs from the manifest", m.Path)
		}
		if extract != nil {
			content := sha256.New()
			if err := extract(m, io.TeeReader(tr, content)); err != nil {
				return "", err
			}
			if m.Type == TypeFile && hex.EncodeToString(content.Sum(nil)) != m.SHA256 {
				return "", fmt.Errorf("restored member %s checksum differs", m.Path)
			}
			continue
		}
		if m.Type == TypeFile {
			content := sha256.New()
			n, err := io.Copy(content, tr)
			if err != nil || n != m.Size || hex.EncodeToString(content.Sum(nil)) != m.SHA256 {
				return "", fmt.Errorf("archive member %s content differs from the manifest", m.Path)
			}
		}
	}
	if _, err := tr.Next(); !errors.Is(err, io.EOF) {
		return "", errors.New("archive holds members absent from the manifest")
	}
	if _, err := io.Copy(io.Discard, stream); err != nil {
		return "", err
	}
	if count.n != size {
		return "", errors.New("archive tar length differs from its manifest")
	}
	if after, err := fstate(file); err != nil || after != st {
		return "", errors.New("archive tar changed while being read")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func validManifest(m Manifest, rule config.WorkspaceArchiveRule) error {
	if m.Version != ManifestVersion || m.Name != rule.Name || m.SourcePath != rule.Path || m.TarFile != TarName(rule) {
		return errors.New("archive manifest does not belong to this workspace rule")
	}
	if m.RuleSHA256 != RuleHash(rule) || RuleHash(m.Rule) != m.RuleSHA256 {
		return errors.New("archive manifest owner/release record does not match its policy binding")
	}
	if m.StreamSHA256 == "" || m.StreamSHA256 != m.ReadbackSHA256 || m.TarBytes <= 0 {
		return errors.New("archive manifest lacks a matching stream and readback checksum")
	}
	now := time.Now().UTC()
	if m.CreatedAt.IsZero() || m.VerifiedAt.Before(m.CreatedAt) || m.VerifiedAt.After(now) {
		return errors.New("archive manifest verification time is invalid")
	}
	if len(m.Members) == 0 || m.Members[0].Path != "." || m.Members[0].Type != TypeDirectory {
		return errors.New("archive manifest lacks its root directory")
	}
	dirs := map[string]bool{".": true}
	seen := make(map[string]bool, len(m.Members))
	for _, member := range m.Members[1:] {
		if !validMemberPath(member.Path) || seen[member.Path] || member.Mode&^07777 != 0 || member.Size < 0 {
			return fmt.Errorf("archive manifest member %q is invalid", member.Path)
		}
		if !dirs[filepath.Dir(member.Path)] {
			return fmt.Errorf("archive manifest member %q precedes its directory", member.Path)
		}
		switch member.Type {
		case TypeDirectory, TypeSymlink:
			if member.Size != 0 {
				return fmt.Errorf("archive manifest member %q has a size", member.Path)
			}
		case TypeFile:
			if len(member.SHA256) != 64 {
				return fmt.Errorf("archive manifest member %q lacks a checksum", member.Path)
			}
		default:
			return fmt.Errorf("archive manifest member %q has unknown type %q", member.Path, member.Type)
		}
		seen[member.Path] = true
		dirs[member.Path] = member.Type == TypeDirectory
	}
	if m.Bundle != nil && (m.Bundle.File != BundleName(rule) || len(m.Bundle.SHA256) != 64 || len(m.Bundle.Head) < 40) {
		return errors.New("archive manifest history bundle record is invalid")
	}
	return nil
}

// load opens the pinned manifest and tar after checking the destination
// mount expectations. The archive directory may have been remounted since
// creation; its identity is reported, not required.
func load(ctx context.Context, rule config.WorkspaceArchiveRule) (Manifest, *os.File, *os.File, error) {
	var m Manifest
	if rule.Archive.Manifest == "" || rule.Archive.ManifestSHA256 == "" {
		return m, nil, nil, errors.New("no exact verified workspace archive manifest is pinned")
	}
	if rule.Archive.Manifest != config.WorkspaceArchiveManifestPath(rule) {
		return m, nil, nil, errors.New("manifest is not the rule's archive manifest")
	}
	root, err := openDirectory(rule.Archive.Directory)
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
	if _, _, err = checkMount(rule, rootSt); err != nil {
		return m, nil, nil, err
	}
	manifest, _, err := openRegularChild(root, ManifestName(rule))
	if err != nil {
		return m, nil, nil, err
	}
	data, err := io.ReadAll(contextReader{ctx, io.LimitReader(manifest, maxManifestBytes+1)})
	manifest.Close()
	if err != nil {
		return m, nil, nil, err
	}
	if len(data) > maxManifestBytes {
		return m, nil, nil, errors.New("oversized archive manifest")
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != rule.Archive.ManifestSHA256 {
		return m, nil, nil, errors.New("archive manifest checksum mismatch")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&m); err != nil {
		return m, nil, nil, err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return m, nil, nil, errors.New("trailing archive manifest data")
	}
	if err = validManifest(m, rule); err != nil {
		return m, nil, nil, err
	}
	tarFile, _, err := openRegularChild(root, m.TarFile)
	if err != nil {
		return m, nil, nil, err
	}
	ok = true
	return m, root, tarFile, nil
}

// Check validates the pinned manifest. Full checks re-read the whole tar
// (stream hash, member list, metadata and per-file content) and the history
// bundle; they never need the source.
func Check(ctx context.Context, rule config.WorkspaceArchiveRule, full bool) (Manifest, *Binding, error) {
	m, root, tarFile, err := load(ctx, rule)
	if err != nil {
		return m, nil, err
	}
	defer root.Close()
	defer tarFile.Close()
	if full {
		if err := verifyArchive(ctx, m, root, tarFile); err != nil {
			return m, nil, err
		}
	}
	return m, &Binding{Manifest: rule.Archive.Manifest, ManifestSHA256: rule.Archive.ManifestSHA256}, nil
}

// verifyArchive is the full read-back shared by Check and Bind: the whole tar
// (stream hash, member list, metadata and per-file content) and the history
// bundle.
func verifyArchive(ctx context.Context, m Manifest, root, tarFile *os.File) error {
	readback, err := verifyTar(ctx, tarFile, m.Members, m.TarBytes)
	if err != nil {
		return err
	}
	if readback != m.StreamSHA256 {
		return errors.New("archive tar checksum differs from its manifest")
	}
	if m.Bundle == nil {
		return nil
	}
	bundle, _, err := openRegularChild(root, m.Bundle.File)
	if err != nil {
		return err
	}
	defer bundle.Close()
	return verifyBundle(ctx, bundle, m.Bundle)
}

// Restore extracts the verified tree to destination, which must not exist and
// must not be strictly inside or strictly contain the source path, then
// re-walks the restored tree and compares it with the manifest. It never
// overwrites anything and never touches the archive or the source.
func Restore(ctx context.Context, rule config.WorkspaceArchiveRule, destination string) (Manifest, error) {
	if !core.IsCanonicalPath(destination) || destination == "/" {
		return Manifest{}, errors.New("restore destination must be a canonical absolute path")
	}
	if core.PathsOverlap(destination, rule.Archive.Directory) {
		return Manifest{}, errors.New("restore must not modify the archive directory")
	}
	// The source is copy-only: a destination inside or around it would write
	// into or over the released tree. The original path itself is allowed;
	// the existence check below refuses it while the source is still there.
	if destination != rule.Path && core.PathsOverlap(destination, rule.Path) {
		return Manifest{}, errors.New("restore destination must not be inside or contain the released workspace path")
	}
	m, root, tarFile, err := load(ctx, rule)
	if err != nil {
		return m, err
	}
	defer root.Close()
	defer tarFile.Close()
	parent, err := openDirectory(filepath.Dir(destination))
	if err != nil {
		return m, err
	}
	defer parent.Close()
	base := filepath.Base(destination)
	if exists, err := childExists(parent, base); err != nil || exists {
		return m, fmt.Errorf("restore destination %s must not exist", destination)
	}
	if err = requireSpace(parent, uint64(m.ContentBytes)+uint64(len(m.Members))*4096+(1<<20)); err != nil {
		return m, err
	}
	stageName := ".partial-restore-" + uuid.NewString()
	if err = unix.Mkdirat(int(parent.Fd()), stageName, 0700); err != nil {
		return m, err
	}
	published := false
	defer func() {
		if !published {
			os.RemoveAll(filepath.Join(descriptorPath(parent), stageName)) // only our private staging tree
		}
	}()
	stage, err := openChild(parent, stageName, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return m, err
	}
	defer stage.Close()
	readback, err := readTar(ctx, tarFile, m.Members, m.TarBytes, func(member Member, content io.Reader) error {
		return extractMember(stage, member, content)
	})
	if err != nil {
		return m, err
	}
	if readback != m.StreamSHA256 {
		return m, errors.New("archive tar checksum differs from its manifest; restore discarded")
	}
	// Directory times last and deepest first: creating children changes them.
	for i := len(m.Members) - 1; i > 0; i-- {
		member := m.Members[i]
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
	if err = unix.Syncfs(int(stage.Fd())); err != nil {
		return m, err
	}
	if err = unix.Renameat2(int(parent.Fd()), stageName, int(parent.Fd()), base, unix.RENAME_NOREPLACE); err != nil {
		return m, err
	}
	published = true
	if err = setMetadata(stage, m.Members[0]); err != nil {
		return m, fmt.Errorf("restored tree at %s is incomplete; inspect it before use: %w", destination, err)
	}
	if err = verifyRestored(ctx, stage, destination, m); err != nil {
		return m, fmt.Errorf("restored tree at %s failed verification; inspect it before use: %w", destination, err)
	}
	if err = parent.Sync(); err != nil {
		return m, err
	}
	return m, nil
}

func extractMember(stage *os.File, m Member, content io.Reader) error {
	if m.Path == "." {
		return nil
	}
	dir, err := openBeneath(stage, filepath.Dir(m.Path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW)
	if err != nil {
		return err
	}
	defer dir.Close()
	name := filepath.Base(m.Path)
	switch m.Type {
	case TypeDirectory:
		return unix.Mkdirat(int(dir.Fd()), name, 0700)
	case TypeSymlink:
		if err := unix.Symlinkat(m.Linkname, int(dir.Fd()), name); err != nil {
			return err
		}
		return setLinkMetadata(dir, name, m)
	default:
		f, err := createChild(dir, name)
		if err != nil {
			return err
		}
		defer f.Close()
		n, err := io.Copy(f, io.LimitReader(content, m.Size+1))
		if err != nil {
			return err
		}
		if n != m.Size {
			return fmt.Errorf("restored member %s size differs", m.Path)
		}
		return setMetadata(f, m)
	}
}

func verifyRestored(ctx context.Context, root *os.File, destination string, m Manifest) error {
	walk, err := scanTree(ctx, root, destination, nil, len(m.Members), true, false)
	if err != nil {
		return err
	}
	if len(walk.refusals) > 0 {
		return errors.New(walk.refusals[0])
	}
	got := walk.inv.members
	if len(got) != len(m.Members) {
		return fmt.Errorf("restored %d members, manifest records %d", len(got), len(m.Members))
	}
	for i := range got {
		if got[i] != m.Members[i] {
			return fmt.Errorf("restored member %s differs from the manifest", m.Members[i].Path)
		}
	}
	return nil
}
