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
	"strings"
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
// parent is the source's directory, through which the companion is observed;
// tarRoot names the source in a unit layout tar ("" is the classic layout).
type inspected struct {
	source, root        *os.File
	sourceState, rootSt state
	inv                 inventory
	mountSource, fstype string
	parent              *os.File
	tarRoot             string
	companion           *companion
}

func (in *inspected) close() {
	if in.source != nil {
		in.source.Close()
	}
	if in.root != nil {
		in.root.Close()
	}
	if in.parent != nil {
		in.parent.Close()
	}
	in.companion.close()
}

// archivedCompanion is the companion's manifest record: nil when the rule has
// none or it is absent.
func (in *inspected) archivedCompanion() *Member {
	if in.companion == nil || in.companion.file == nil {
		return nil
	}
	return &in.companion.member
}

// totals counts every archived entry and content byte, companion included.
func (in *inspected) totals() (int, int64) {
	members, content := len(in.inv.members), in.inv.contentBytes
	if c := in.archivedCompanion(); c != nil {
		members, content = members+1, content+c.Size
	}
	return members, content
}

func (s Scope) limit() int {
	if s.MaxEntries <= 0 {
		return defaultMaxEntries
	}
	return s.MaxEntries
}

// Inspect runs every refusal check without writing anything: secret-like
// names, unsupported members, mount crossings, destination mount
// expectations, live process references and mentions, and external
// dependents, over the source and its companion.
func Inspect(ctx context.Context, rule config.WorkspaceArchiveRule, scope Scope) (Inspection, error) {
	in, err := inspect(ctx, rule, scope)
	if err != nil {
		return Inspection{}, err
	}
	defer in.close()
	members, content := in.totals()
	return Inspection{Source: in.sourceState.id, Members: members, ContentBytes: content, LinkedWorktree: in.inv.worktreeAdmin != "", MountSource: in.mountSource, FSType: in.fstype}, nil
}

func inspect(ctx context.Context, rule config.WorkspaceArchiveRule, scope Scope) (*inspected, error) {
	if err := validCompanion(rule); err != nil {
		return nil, err
	}
	paths := unitPaths(rule, rule.Path)
	for _, path := range paths {
		if core.PathsOverlap(path, rule.Archive.Directory) {
			return nil, errors.New("archive directory must be outside the archived workspace")
		}
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
	if in.parent, err = openDirectory(filepath.Dir(rule.Path)); err != nil {
		return nil, fmt.Errorf("workspace: %w", err)
	}
	if in.source, _, err = openEntry(in.parent, rule.Path, true); err != nil {
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
	in.tarRoot = unitRoot(rule, in.inv.members[0])
	if in.sourceState.id == in.rootSt.id {
		return nil, errors.New("archive directory and workspace are the same directory")
	}
	if rule.Companion != "" {
		if in.companion, err = observeCompanion(ctx, in.parent, rule.Companion, scope.SensitiveNames, in.sourceState, false); err != nil {
			return nil, err
		}
	}
	if err = scope.live(ctx, paths, rule.Mentions); err != nil {
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
	if in.companion != nil {
		if err := in.companion.unchanged(in.parent); err != nil {
			return fmt.Errorf("%w; original retained", err)
		}
	}
	return scope.live(ctx, unitPaths(rule, rule.Path), rule.Mentions)
}

// live runs the live process check of paths, one unit's names, and mentions,
// then the external dependent check of each path.
func (s Scope) live(ctx context.Context, paths, mentions []string) error {
	if err := liveReferences(ctx, s.ProcRoot, paths, mentions); err != nil {
		return err
	}
	for _, path := range paths {
		if err := s.dependents(ctx, path); err != nil {
			return err
		}
	}
	return nil
}

// validCompanion refuses a companion that is not a sibling of rule.Path whose
// name extends rule.Path's: the unit moves and restores as one name pair.
func validCompanion(rule config.WorkspaceArchiveRule) error {
	if rule.Companion == "" {
		return nil
	}
	base, name := filepath.Base(rule.Path), filepath.Base(rule.Companion)
	if !core.IsCanonicalPath(rule.Path) || !core.IsCanonicalPath(rule.Companion) || filepath.Dir(rule.Companion) != filepath.Dir(rule.Path) ||
		len(name) <= len(base) || !strings.HasPrefix(name, base) {
		return fmt.Errorf("archive companion %s must be a sibling of %s whose name extends %q", rule.Companion, rule.Path, base)
	}
	return nil
}

// unitPaths are the names of one unit at path: path itself and, when the
// rule has a companion, path plus the companion suffix.
func unitPaths(rule config.WorkspaceArchiveRule, path string) []string {
	if rule.Companion == "" {
		return []string{path}
	}
	return []string{path, path + rule.CompanionSuffix()}
}

// unitRoot is the tar name of the archived root. A directory archived alone
// keeps the classic layout ("" here): "./" and members by relative path. A
// file root, or a rule with a companion, uses the unit layout: the root by
// its base name, members beneath it and the companion by its own base name,
// so extracting into the source's parent recreates the original names.
func unitRoot(rule config.WorkspaceArchiveRule, root Member) string {
	if rule.Companion == "" && root.Type == TypeDirectory {
		return ""
	}
	return filepath.Base(rule.Path)
}

// tarLayout is the entry sequence of one tar: members named under root
// (classic names when root is ""), then the companion, if any, by its Path.
type tarLayout struct {
	members   []Member
	root      string
	companion *Member
}

func manifestLayout(m Manifest) tarLayout {
	return tarLayout{members: m.Members, root: unitRoot(m.Rule, m.Members[0]), companion: m.Companion}
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
	entries, content := in.totals()
	overhead := uint64(entries)*1536 + (1 << 20)
	if err = requireSpace(in.root, uint64(content)+overhead); err != nil {
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
	readback, err := verifyTar(ctx, tarFile, tarLayout{members: members, root: in.tarRoot, companion: in.archivedCompanion()}, tarBytes)
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
		StreamSHA256: streamSHA, ReadbackSHA256: readback, ContentBytes: content,
		Members: members, Companion: in.archivedCompanion(), Bundle: bundle, CreatedAt: time.Now().UTC(),
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
		if err = publishNoReplace(int(stage.Fd()), item.from, int(in.root.Fd()), item.to); err != nil {
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

// header is m's tar header. In the classic layout (root "") members are
// named by their relative paths and the root directory "./"; in the unit
// layout the root is named root and members root/<path>. A companion is
// named by its Path, its base name, in the classic manner.
func header(m Member, root string) *tar.Header {
	name := m.Path
	if root != "" {
		name = root
		if m.Path != "." {
			name = root + "/" + m.Path
		}
	}
	h := &tar.Header{Name: name, Mode: int64(m.Mode), Uid: int(m.UID), Gid: int(m.GID), ModTime: time.Unix(0, m.ModifiedNS), Format: tar.FormatPAX}
	switch m.Type {
	case TypeDirectory:
		h.Typeflag = tar.TypeDir
		h.Name += "/"
	case TypeSymlink:
		h.Typeflag, h.Linkname = tar.TypeSymlink, m.Linkname
	default:
		h.Typeflag, h.Size = tar.TypeReg, m.Size
	}
	return h
}

func headerMatches(h *tar.Header, m Member, root string) bool {
	want := header(m, root)
	return h.Name == want.Name && h.Typeflag == want.Typeflag && h.Linkname == want.Linkname && h.Size == want.Size &&
		h.Mode == want.Mode && h.Uid == want.Uid && h.Gid == want.Gid && h.ModTime.UnixNano() == m.ModifiedNS
}

// writeTar streams the tree, then the companion, into out, hashing every
// byte written and every regular file read. Each file must keep its recorded
// identity and metadata.
func writeTar(ctx context.Context, in *inspected, out *os.File, members []Member) (string, int64, error) {
	stream, count := sha256.New(), &countingWriter{}
	buffered := bufio.NewWriterSize(io.MultiWriter(spaceWriter{in.root, 0, out}, stream, count), 1<<20)
	tw := tar.NewWriter(buffered)
	for i := range members {
		m := &members[i]
		if err := ctx.Err(); err != nil {
			return "", 0, err
		}
		if err := tw.WriteHeader(header(*m, in.tarRoot)); err != nil {
			return "", 0, fmt.Errorf("archive %s: %w", m.Path, err)
		}
		if m.Type != TypeFile {
			continue
		}
		if err := copyMember(ctx, in, tw, m, in.inv.states[i]); err != nil {
			return "", 0, err
		}
	}
	if c := in.archivedCompanion(); c != nil {
		if err := tw.WriteHeader(header(*c, "")); err != nil {
			return "", 0, fmt.Errorf("archive %s: %w", in.companion.path, err)
		}
		if err := copyContent(ctx, in.companion.file, tw, c, in.companion.state); err != nil {
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

// copyMember copies one regular file of the source; a file root is the
// already open source itself.
func copyMember(ctx context.Context, in *inspected, tw io.Writer, m *Member, recorded state) error {
	if m.Path == "." {
		return copyContent(ctx, in.source, tw, m, recorded)
	}
	f, err := openBeneath(in.source, m.Path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK)
	if err != nil {
		return err
	}
	defer f.Close()
	return copyContent(ctx, f, tw, m, recorded)
}

// copyContent copies f, which must keep its recorded identity and metadata
// throughout, from offset 0 into tw and records its SHA-256 in m.
func copyContent(ctx context.Context, f *os.File, tw io.Writer, m *Member, recorded state) error {
	if before, err := fstate(f); err != nil || before != recorded {
		return fmt.Errorf("%s changed before it was archived; original retained", m.Path)
	}
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(tw, hash), contextReader{ctx, io.NewSectionReader(f, 0, m.Size)})
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
func verifyTar(ctx context.Context, file *os.File, layout tarLayout, size int64) (string, error) {
	return readTar(ctx, file, layout, size, nil)
}

// readTar is the single bounded pass shared by verification and restore.
// extract, when set, receives each verified member with its content reader;
// companion marks the companion, which follows the members.
func readTar(ctx context.Context, file *os.File, layout tarLayout, size int64, extract func(m Member, companion bool, content io.Reader) error) (string, error) {
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
	next := func(m Member, root string, companion bool) error {
		h, err := tr.Next()
		if err != nil {
			return fmt.Errorf("archive ends before member %s: %w", m.Path, err)
		}
		if !headerMatches(h, m, root) {
			return fmt.Errorf("archive member %s differs from the manifest", m.Path)
		}
		if extract != nil {
			content := sha256.New()
			if err := extract(m, companion, io.TeeReader(tr, content)); err != nil {
				return err
			}
			if m.Type == TypeFile && hex.EncodeToString(content.Sum(nil)) != m.SHA256 {
				return fmt.Errorf("restored member %s checksum differs", m.Path)
			}
			return nil
		}
		if m.Type == TypeFile {
			content := sha256.New()
			n, err := io.Copy(content, tr)
			if err != nil || n != m.Size || hex.EncodeToString(content.Sum(nil)) != m.SHA256 {
				return fmt.Errorf("archive member %s content differs from the manifest", m.Path)
			}
		}
		return nil
	}
	for _, m := range layout.members {
		if err := next(m, layout.root, false); err != nil {
			return "", err
		}
	}
	if layout.companion != nil {
		if err := next(*layout.companion, "", true); err != nil {
			return "", err
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
	if err := validCompanion(rule); err != nil {
		return err
	}
	if len(m.Members) == 0 || m.Members[0].Path != "." {
		return errors.New("archive manifest lacks its root directory or file")
	}
	switch root := m.Members[0]; root.Type {
	case TypeDirectory:
	case TypeFile:
		if len(m.Members) != 1 || !validFile(root) {
			return errors.New("archive manifest root file record is invalid")
		}
	default:
		return errors.New("archive manifest lacks its root directory or file")
	}
	if c := m.Companion; c != nil && (rule.Companion == "" || c.Path != filepath.Base(rule.Companion) || !validFile(*c)) {
		return errors.New("archive manifest companion record is invalid")
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
			if !isSHA256(member.SHA256) {
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

// validFile accepts a recorded regular file: permission bits only, a
// non-negative size, no link target and a SHA-256.
func validFile(m Member) bool {
	return m.Type == TypeFile && m.Mode&^07777 == 0 && m.Size >= 0 && m.Linkname == "" && isSHA256(m.SHA256)
}

func isSHA256(sum string) bool {
	_, err := hex.DecodeString(sum)
	return len(sum) == 64 && err == nil
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
// (stream hash, member list, companion, metadata and per-file content) and
// the history bundle.
func verifyArchive(ctx context.Context, m Manifest, root, tarFile *os.File) error {
	readback, err := verifyTar(ctx, tarFile, manifestLayout(m), m.TarBytes)
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

// Restore extracts the verified tree to destination and the archived
// companion, if any, to destination plus the rule's companion suffix. Neither
// name may exist, be strictly inside or strictly contain the source's names.
// Both are staged in one private directory, published without replacing
// anything, companion first, and re-walked and compared with the manifest. It
// never overwrites anything and never touches the archive or the source.
func Restore(ctx context.Context, rule config.WorkspaceArchiveRule, destination string) (Manifest, error) {
	if !core.IsCanonicalPath(destination) || destination == "/" {
		return Manifest{}, errors.New("restore destination must be a canonical absolute path")
	}
	if err := validCompanion(rule); err != nil {
		return Manifest{}, err
	}
	targets, sources := unitPaths(rule, destination), unitPaths(rule, rule.Path)
	for i, target := range targets {
		if core.PathsOverlap(target, rule.Archive.Directory) {
			return Manifest{}, errors.New("restore must not modify the archive directory")
		}
		// The source is copy-only: a destination inside or around it would
		// write into or over the released unit. The original names
		// themselves are allowed; the existence check below refuses them
		// while the source is still there.
		for j, source := range sources {
			if (i != j || target != source) && core.PathsOverlap(target, source) {
				return Manifest{}, errors.New("restore destination must not be inside or contain the released workspace path")
			}
		}
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
	for _, target := range targets {
		if exists, err := childExists(parent, filepath.Base(target)); err != nil || exists {
			return m, fmt.Errorf("restore destination %s must not exist", target)
		}
	}
	entries := len(m.Members)
	if m.Companion != nil {
		entries++
	}
	if err = requireSpace(parent, uint64(m.ContentBytes)+uint64(entries)*4096+(1<<20)); err != nil {
		return m, err
	}
	stageName := ".partial-restore-" + uuid.NewString()
	if err = unix.Mkdirat(int(parent.Fd()), stageName, 0700); err != nil {
		return m, err
	}
	// Published entries have left the stage; anything still in it is not.
	defer os.RemoveAll(filepath.Join(descriptorPath(parent), stageName)) // only our private staging tree
	stage, err := openChild(parent, stageName, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return m, err
	}
	defer stage.Close()
	base := filepath.Base(destination)
	companionName := base + rule.CompanionSuffix()
	var tree *os.File // the restored root directory; nil for a file root
	defer func() {
		if tree != nil {
			tree.Close()
		}
	}()
	readback, err := readTar(ctx, tarFile, manifestLayout(m), m.TarBytes, func(member Member, companion bool, content io.Reader) error {
		switch {
		case companion:
			return extractFile(stage, companionName, member, content)
		case member.Path != ".":
			return extractMember(tree, member, content)
		case member.Type == TypeFile:
			return extractFile(stage, base, member, content)
		}
		if err := unix.Mkdirat(int(stage.Fd()), base, 0700); err != nil {
			return err
		}
		var err error
		tree, err = openChild(stage, base, unix.O_RDONLY|unix.O_DIRECTORY)
		return err
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
		dir, err := openBeneath(tree, member.Path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW)
		if err != nil {
			return m, err
		}
		err = setMetadata(dir, member)
		dir.Close()
		if err != nil {
			return m, err
		}
	}
	restored := tree
	if restored == nil {
		if restored, err = openChild(stage, base, unix.O_RDONLY); err != nil {
			return m, err
		}
		defer restored.Close()
	}
	var companion *os.File
	if m.Companion != nil {
		if companion, err = openChild(stage, companionName, unix.O_RDONLY); err != nil {
			return m, err
		}
		defer companion.Close()
	}
	if err = unix.Syncfs(int(stage.Fd())); err != nil {
		return m, err
	}
	// The companion is published first: the restored root, published last,
	// completes the unit.
	if companion != nil {
		if err = unix.Renameat2(int(stage.Fd()), companionName, int(parent.Fd()), companionName, unix.RENAME_NOREPLACE); err != nil {
			return m, err
		}
	}
	if err = unix.Renameat2(int(stage.Fd()), base, int(parent.Fd()), base, unix.RENAME_NOREPLACE); err != nil {
		if companion != nil {
			return m, fmt.Errorf("restored companion %s is published without %s; inspect it before use: %w", targets[1], destination, err)
		}
		return m, err
	}
	// Moving a directory to a new parent rewrites its ".." entry; its
	// recorded metadata is set afterwards.
	if tree != nil {
		if err = setMetadata(tree, m.Members[0]); err != nil {
			return m, fmt.Errorf("restored tree at %s is incomplete; inspect it before use: %w", destination, err)
		}
	}
	if err = verifyRestored(ctx, restored, companion, destination, m); err != nil {
		return m, fmt.Errorf("restored tree at %s failed verification; inspect it before use: %w", destination, err)
	}
	if err = parent.Sync(); err != nil {
		return m, err
	}
	return m, nil
}

// extractMember creates one non-root member beneath the restored directory
// stage.
func extractMember(stage *os.File, m Member, content io.Reader) error {
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
		return extractFile(dir, name, m, content)
	}
}

// extractFile creates the regular file name in dir from content and applies
// m's metadata.
func extractFile(dir *os.File, name string, m Member, content io.Reader) error {
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

// verifyRestored re-walks the restored root, hashing every file, and
// re-reads the restored companion, if any, and compares both with the
// manifest.
func verifyRestored(ctx context.Context, root, companion *os.File, destination string, m Manifest) error {
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
	if m.Companion == nil {
		return nil
	}
	st, err := fstate(companion)
	if err != nil {
		return err
	}
	if st.kind() != unix.S_IFREG {
		return fmt.Errorf("restored companion %s is not a regular file", m.Companion.Path)
	}
	restored := regularMember(m.Companion.Path, st)
	if restored.SHA256, err = hashRegular(ctx, companion, st.size, m.Companion.Path); err != nil {
		return err
	}
	if restored != *m.Companion {
		return fmt.Errorf("restored companion %s differs from the manifest", m.Companion.Path)
	}
	return nil
}
