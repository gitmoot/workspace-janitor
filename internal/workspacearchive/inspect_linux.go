//go:build linux

package workspacearchive

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
	"golang.org/x/sys/unix"
)

const (
	defaultMaxEntries = 200000
	// dependentDepth matches the proven manual mover's bounded search.
	dependentDepth = 6
	maxTreeDepth   = 512
	maxPointerSize = 64 << 10
	// maxLinkHops matches the kernel's MAXSYMLINKS.
	maxLinkHops = 40
	maxReported = 20
)

// Built-in screen ported from the proven manual mover. Policy
// protect.name_patterns are applied in addition, verbatim.
var (
	secretNames    = []string{".env", "id_rsa", "id_ed25519", ".netrc", ".pgpass", ".npmrc", ".pypirc", "credentials.json", "service-account.json", "token.json"}
	secretSuffixes = []string{".pem", ".key", ".p12", ".pfx", ".kdbx", ".keystore", ".jks"}
	secretExamples = []string{".env.example", ".env.sample", ".env.template"}
)

func builtinSecret(name, parent string) bool {
	low := strings.ToLower(name)
	for _, example := range secretExamples {
		if low == example {
			return false
		}
	}
	// certifi's cacert.pem is the public Mozilla CA bundle, not a secret.
	if low == "cacert.pem" && filepath.Base(parent) == "certifi" {
		return false
	}
	for _, exact := range secretNames {
		if low == exact {
			return true
		}
	}
	if strings.HasPrefix(low, ".env.") || strings.HasPrefix(low, "id_rsa") || strings.HasPrefix(low, "id_ed25519") {
		return true
	}
	for _, suffix := range secretSuffixes {
		if strings.HasSuffix(low, suffix) {
			return true
		}
	}
	return false
}

func secretLike(name, parent string, patterns []string) bool {
	if builtinSecret(name, parent) {
		return true
	}
	// Policy patterns match case-insensitively, like the built-in screen:
	// "*TOKEN*" and "*token*" keep the same names local.
	low := strings.ToLower(name)
	for _, pattern := range patterns {
		// An unusable pattern is an unknown, not an all-clear.
		if matched, err := filepath.Match(strings.ToLower(pattern), low); matched || err != nil {
			return true
		}
	}
	return false
}

// inventory is the exact local tree, in archive order, with the statx
// observation each member was recorded from.
type inventory struct {
	members       []Member
	states        []state
	contentBytes  int64
	worktreeAdmin string
}

type walker struct {
	ctx       context.Context
	source    string
	rootState state
	patterns  []string
	max       int
	// hash records each regular file's SHA-256; screen applies the source
	// refusal screens (secret-like names, xattrs, outbound Git pointers).
	hash, screen bool
	inv          inventory
	secrets      []string
	refusals     []string
}

func (w *walker) refuse(format string, args ...any) {
	if len(w.refusals) < maxReported {
		w.refusals = append(w.refusals, fmt.Sprintf(format, args...))
	}
}

func (w *walker) add(m Member, st state) error {
	if len(w.inv.members) >= w.max {
		return fmt.Errorf("tree exceeds the %d-entry archive bound; retain the original", w.max)
	}
	w.inv.members = append(w.inv.members, m)
	w.inv.states = append(w.inv.states, st)
	w.inv.contentBytes += m.Size
	return nil
}

// scanTree records every member without following symlinks or crossing
// mounts. hash also hashes regular files; screen applies the refusal screens,
// which apply to sources and to local trees bound for expiry, not to restores.
func scanTree(ctx context.Context, root *os.File, source string, patterns []string, limit int, hash, screen bool) (*walker, error) {
	rootState, err := fstate(root)
	if err != nil {
		return nil, err
	}
	if rootState.kind() != unix.S_IFDIR {
		return nil, errors.New("workspace archive source must be a directory")
	}
	w := &walker{ctx: ctx, source: source, rootState: rootState, patterns: patterns, max: limit, hash: hash, screen: screen}
	if screen {
		if secretLike(filepath.Base(source), filepath.Dir(source), patterns) {
			w.secrets = append(w.secrets, ".")
		}
		if hasXattrs(unix.Flistxattr(int(root.Fd()), nil)) {
			w.refuse(".: extended attributes are unsupported")
		}
	}
	if err = w.add(Member{Path: ".", Type: TypeDirectory, Mode: rootState.mode & 07777, UID: rootState.uid, GID: rootState.gid, ModifiedNS: rootState.mtimeNS}, rootState); err != nil {
		return nil, err
	}
	if err = w.walk(root, ".", 0); err != nil {
		return nil, err
	}
	return w, nil
}

func readNames(dir *os.File, limit int) ([]string, error) {
	if _, err := dir.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	var names []string
	for {
		batch, err := dir.Readdirnames(256)
		names = append(names, batch...)
		if len(names) > limit {
			return nil, fmt.Errorf("directory listing exceeds the %d-entry bound", limit)
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(names)
	return names, nil
}

func (w *walker) walk(dir *os.File, rel string, depth int) error {
	if depth > maxTreeDepth {
		return fmt.Errorf("%s exceeds the %d-level depth bound", rel, maxTreeDepth)
	}
	names, err := readNames(dir, w.max)
	if err != nil {
		return fmt.Errorf("list %s: %w", rel, err)
	}
	for _, name := range names {
		if err := w.visit(dir, rel, name, depth); err != nil {
			return err
		}
	}
	return nil
}

// visit records one child of dir and, for a directory, walks it.
func (w *walker) visit(dir *os.File, rel, name string, depth int) error {
	if err := w.ctx.Err(); err != nil {
		return err
	}
	fd := int(dir.Fd())
	path := joinMember(rel, name)
	st, err := statxAt(fd, name, 0)
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if st.id.Device != w.rootState.id.Device || st.mountID != w.rootState.mountID {
		w.refuse("%s: crosses a mount boundary inside the tree", path)
		return nil
	}
	if w.screen {
		if secretLike(name, filepath.Join(w.source, rel), w.patterns) && len(w.secrets) < maxReported {
			w.secrets = append(w.secrets, path)
		}
		if hasXattrs(unix.Llistxattr(fmt.Sprintf("%s/%s", descriptorPath(dir), name), nil)) {
			w.refuse("%s: extended attributes are unsupported", path)
		}
	}
	m := Member{Path: path, Mode: st.mode & 07777, UID: st.uid, GID: st.gid, ModifiedNS: st.mtimeNS}
	switch st.kind() {
	case unix.S_IFDIR:
		m.Type = TypeDirectory
		if err := w.add(m, st); err != nil {
			return err
		}
		child, err := openChild(dir, name, unix.O_RDONLY|unix.O_DIRECTORY)
		if err != nil {
			return err
		}
		opened, err := fstate(child)
		if err == nil && opened.id != st.id {
			err = fmt.Errorf("%s changed while being inspected", path)
		}
		if err == nil {
			err = w.walk(child, path, depth+1)
		}
		child.Close()
		if err != nil {
			return err
		}
	case unix.S_IFREG:
		m.Type, m.Size = TypeFile, st.size
		if w.hash || (w.screen && (name == ".git" || name == "alternates")) {
			if err := w.readRegular(dir, name, rel, &m, st); err != nil {
				return err
			}
		}
		if err := w.add(m, st); err != nil {
			return err
		}
	case unix.S_IFLNK:
		m.Type = TypeSymlink
		target, err := readlinkAt(fd, name)
		if err != nil {
			return fmt.Errorf("readlink %s: %w", path, err)
		}
		m.Linkname = target
		if name == ".git" && w.screen {
			w.screenGitLink(path, rel, target)
		}
		if err := w.add(m, st); err != nil {
			return err
		}
	default:
		w.refuse("%s: unsupported file type (only directories, regular files and symlinks are archived)", path)
	}
	return nil
}

// readRegular hashes files when hashing and screens Git pointers when
// screening: a tree whose history lives outside it is archived only as a root
// linked worktree (a root .git file), with a bundle; nested outbound gitdirs
// and alternates are refused. .git symlinks are screened by screenGitLink.
func (w *walker) readRegular(dir *os.File, name, rel string, m *Member, st state) error {
	f, err := openChild(dir, name, unix.O_RDONLY)
	if err != nil {
		return err
	}
	defer f.Close()
	opened, err := fstate(f)
	if err != nil || opened.id != st.id {
		return fmt.Errorf("%s changed while being inspected", m.Path)
	}
	if w.hash {
		hash := sha256.New()
		n, err := io.Copy(hash, contextReader{w.ctx, io.LimitReader(f, st.size+1)})
		if err != nil {
			return err
		}
		if n != st.size {
			return fmt.Errorf("%s size changed while being verified", m.Path)
		}
		m.SHA256 = hex.EncodeToString(hash.Sum(nil))
		if !w.screen || (name != ".git" && name != "alternates") {
			return nil
		}
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return err
		}
	}
	data, err := io.ReadAll(io.LimitReader(f, maxPointerSize+1))
	if err != nil {
		return err
	}
	if len(data) > maxPointerSize {
		w.refuse("%s: oversized Git pointer file", m.Path)
		return nil
	}
	dirAbs := filepath.Join(w.source, rel)
	switch name {
	case ".git":
		target, ok := gitdirTarget(string(data), dirAbs)
		switch {
		case !ok:
			w.refuse("%s: unrecognized .git file", m.Path)
		case core.PathWithin(target, w.source):
		case rel == ".":
			w.inv.worktreeAdmin = target
		default:
			w.refuse("%s: nested worktree history lives outside the archived tree at %s", m.Path, target)
		}
	case "alternates":
		if filepath.Base(dirAbs) != "info" || filepath.Base(filepath.Dir(dirAbs)) != "objects" {
			return nil
		}
		for _, target := range alternateTargets(string(data), filepath.Dir(dirAbs)) {
			if !core.PathWithin(target, w.source) {
				w.refuse("%s: repository borrows objects from %s outside the archived tree", m.Path, target)
			}
		}
	}
	return nil
}

// screenGitLink treats a .git symlink like a gitdir file. Symlinked history is
// never bundled, even at the root: the link must resolve to a directory inside
// the archived tree, so an outbound, dangling, non-directory or unresolvable
// link refuses.
func (w *walker) screenGitLink(path, rel, target string) {
	visited, err := resolveLink(filepath.Join(w.source, rel, ".git"), target)
	if err != nil {
		w.refuse("%s: .git symlink to %s cannot be resolved: %v", path, target, err)
		return
	}
	final := visited[len(visited)-1]
	var st unix.Stat_t
	switch {
	case core.PathWithin(final, w.source):
		if err := unix.Lstat(final, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR {
			w.refuse("%s: .git symlink to %s does not resolve to a directory inside the archived tree", path, target)
		}
	case rel == ".":
		w.refuse("%s: Git history lives outside the archived tree at %s behind a symlink, which is never bundled", path, final)
	default:
		w.refuse("%s: nested worktree history lives outside the archived tree at %s", path, final)
	}
}

// resolveLink follows the symlink at link, whose text is target, the way the
// kernel would: component by component, through chained links and symlinked
// directories, for at most maxLinkHops links. link's directory must already be
// symlink-free. It returns every path the resolution reaches, the final
// location last; a missing component ends resolution with the remainder
// joined lexically. A loop, a longer chain or a component that cannot be
// examined is an error, never "resolves nowhere".
func resolveLink(link, target string) ([]string, error) {
	dir, pending := filepath.Dir(link), target
	if filepath.IsAbs(target) {
		dir = "/"
	}
	var visited []string
	hops := 1
	for pending != "" {
		var part string
		part, pending, _ = strings.Cut(pending, "/")
		switch part {
		case "", ".":
			continue
		case "..":
			dir = filepath.Dir(dir)
			continue
		}
		next := filepath.Join(dir, part)
		visited = append(visited, next)
		var st unix.Stat_t
		if err := unix.Lstat(next, &st); err != nil {
			if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) {
				return append(visited, filepath.Join(next, pending)), nil
			}
			return visited, fmt.Errorf("examine %s: %w", next, err)
		}
		if st.Mode&unix.S_IFMT != unix.S_IFLNK {
			dir = next
			continue
		}
		if hops++; hops > maxLinkHops {
			return visited, fmt.Errorf("more than %d chained symlinks (loop or overlong chain)", maxLinkHops)
		}
		text, err := os.Readlink(next)
		if err != nil {
			return visited, fmt.Errorf("readlink %s: %w", next, err)
		}
		if filepath.IsAbs(text) {
			dir = "/"
		}
		pending = text + "/" + pending
	}
	return append(visited, dir), nil
}

func readlinkAt(dirfd int, name string) (string, error) {
	buf := make([]byte, unix.PathMax)
	n, err := unix.Readlinkat(dirfd, name, buf)
	if err != nil {
		return "", err
	}
	if n >= len(buf) {
		return "", errors.New("symlink target exceeds PATH_MAX")
	}
	return string(buf[:n]), nil
}

func gitdirTarget(content, dirAbs string) (string, bool) {
	line, _, _ := strings.Cut(content, "\n")
	target, ok := strings.CutPrefix(strings.TrimSpace(line), "gitdir:")
	target = strings.TrimSpace(target)
	if !ok || target == "" {
		return "", false
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(dirAbs, target)
	}
	return filepath.Clean(target), true
}

func alternateTargets(content, objectsDir string) []string {
	var out []string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !filepath.IsAbs(line) {
			line = filepath.Join(objectsDir, line)
		}
		out = append(out, filepath.Clean(line))
	}
	return out
}

func (w *walker) err() error {
	if len(w.secrets) > 0 {
		return fmt.Errorf("secret-like files keep %s local: %s", w.source, strings.Join(w.secrets, ", "))
	}
	if len(w.refusals) > 0 {
		return fmt.Errorf("%s cannot be archived faithfully: %s", w.source, strings.Join(w.refusals, "; "))
	}
	return nil
}

// unchanged is the extraction-equivalent comparison: every recorded member
// still has its identity, type, size, ownership, mode, mtime and ctime.
func (inv *inventory) unchanged(src *os.File) error {
	for i, m := range inv.members {
		var st state
		var err error
		if m.Path == "." {
			st, err = fstate(src)
		} else {
			st, err = statBeneath(src, m.Path)
		}
		if err != nil || st != inv.states[i] {
			return fmt.Errorf("source member %s changed during archiving; original retained", m.Path)
		}
	}
	return nil
}

// mountFacts returns the mountinfo source and filesystem type for a statx
// mount ID, as seen by this process.
func mountFacts(mountID uint64) (source, fstype string, err error) {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	want := strconv.FormatUint(mountID, 10)
	for scanner.Scan() {
		line := scanner.Text()
		id, _, _ := strings.Cut(line, " ")
		if id != want {
			continue
		}
		_, tail, ok := strings.Cut(line, " - ")
		fields := strings.Fields(tail)
		if !ok || len(fields) < 2 {
			return "", "", fmt.Errorf("malformed mountinfo entry for mount %d", mountID)
		}
		return unescapeMount(fields[1]), unescapeMount(fields[0]), nil
	}
	if err := scanner.Err(); err != nil {
		return "", "", err
	}
	return "", "", fmt.Errorf("mount %d is absent from mountinfo", mountID)
}

func unescapeMount(value string) string {
	var b strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] == '\\' && i+3 < len(value) {
			if n, err := strconv.ParseUint(value[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(value[i])
	}
	return b.String()
}

// checkMount refuses a destination whose live mount differs from the
// expectation; an unmounted destination shows the parent filesystem's facts
// and is refused the same way, never written as a local fallback.
func checkMount(rule config.WorkspaceArchiveRule, root state) (source, fstype string, err error) {
	source, fstype, err = mountFacts(root.mountID)
	if err != nil {
		return "", "", err
	}
	if want := rule.Archive.ExpectMountSource; want != "" && source != want {
		return source, fstype, fmt.Errorf("archive directory %s is mounted from %q, expected %q; refusing to write anywhere else", rule.Archive.Directory, source, want)
	}
	if want := rule.Archive.ExpectFSType; want != "" && fstype != want {
		return source, fstype, fmt.Errorf("archive directory %s is on a %q mount, expected %q; refusing to write anywhere else", rule.Archive.Directory, fstype, want)
	}
	return source, fstype, nil
}

// liveReferences fails closed: any process whose cwd, root, executable, open
// descriptor or mapped file is inside source, or any process that cannot be
// inspected, keeps the source local.
func liveReferences(ctx context.Context, procRoot, source string) error {
	var hits []string
	unknown, err := processReferences(ctx, procRoot, func(pid, label, target string) bool {
		if !core.PathWithin(target, source) {
			return false
		}
		if len(hits) < maxReported {
			hits = append(hits, fmt.Sprintf("pid %s %s", pid, label))
		}
		return true
	})
	if err != nil {
		return err
	}
	if len(hits) > 0 || unknown > 0 {
		return fmt.Errorf("live process references keep %s local: [%s]; %d process(es) could not be inspected", source, strings.Join(hits, ", "), unknown)
	}
	return nil
}

// processReferences calls match with every absolute path a process holds:
// its cwd, root and executable, each open descriptor and each mapped file.
// match returns true once it has seen enough of that process. The count of
// processes that could not be fully inspected is returned; a process that
// exited meanwhile holds nothing and is not counted.
func processReferences(ctx context.Context, procRoot string, match func(pid, label, target string) bool) (int, error) {
	if procRoot == "" {
		return 0, errors.New("live process check requires a procfs root")
	}
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return 0, fmt.Errorf("live process check: %w", err)
	}
	self := strconv.Itoa(os.Getpid())
	clean := func(target string) (string, bool) {
		target = strings.TrimSuffix(target, " (deleted)")
		if !filepath.IsAbs(target) {
			return "", false
		}
		return filepath.Clean(target), true
	}
	unknown := 0
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return unknown, err
		}
		pid := entry.Name()
		if _, err := strconv.Atoi(pid); err != nil || pid == self {
			continue
		}
		dir := filepath.Join(procRoot, pid)
		found, unreadable := false, false
		for _, link := range []string{"cwd", "root", "exe"} {
			target, err := os.Readlink(filepath.Join(dir, link))
			if err != nil {
				unreadable = unreadable || !errors.Is(err, os.ErrNotExist)
				continue
			}
			if target, ok := clean(target); ok && match(pid, link, target) {
				found = true
				break
			}
		}
		if !found {
			descriptors, err := os.ReadDir(filepath.Join(dir, "fd"))
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				unreadable = true
			}
			for _, descriptor := range descriptors {
				target, err := os.Readlink(filepath.Join(dir, "fd", descriptor.Name()))
				if err != nil {
					unreadable = unreadable || !errors.Is(err, os.ErrNotExist)
					continue
				}
				if target, ok := clean(target); ok && match(pid, "fd "+descriptor.Name(), target) {
					found = true
					break
				}
			}
		}
		if !found {
			mapped, err := mappedFiles(filepath.Join(dir, "maps"))
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				unreadable = true
			}
			for _, target := range mapped {
				if target, ok := clean(target); ok && match(pid, "mapped file", target) {
					found = true
					break
				}
			}
		}
		if !found && unreadable {
			if _, err := os.Lstat(dir); err == nil {
				unknown++
			}
		}
	}
	return unknown, nil
}

// mappedFiles lists the file paths of a /proc/<pid>/maps file.
func mappedFiles(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	seen := map[string]bool{}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		// address perms offset dev inode pathname
		fields := strings.SplitN(scanner.Text(), " ", 6)
		if len(fields) < 6 {
			continue
		}
		name := strings.TrimLeft(fields[5], " ")
		if strings.HasPrefix(name, "/") && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	return out, scanner.Err()
}

// externalDependents finds gitdir files, object alternates and symlinks
// outside source that resolve into it; symlinks are followed through chains
// and symlinked directories. Each search root is walked to a bounded depth on
// its own filesystem; an exceeded bound, unreadable directory, oversized
// pointer file or unresolvable symlink refuses rather than reporting "no
// dependents".
func externalDependents(ctx context.Context, source string, roots []string, limit int) error {
	var hits []string
	for _, root := range roots {
		if core.PathWithin(root, source) {
			continue
		}
		dir, err := openDirectory(root)
		if err != nil {
			if errors.Is(err, unix.ENOENT) {
				continue
			}
			return fmt.Errorf("dependent scan of %s: %w", root, err)
		}
		rootState, err := fstate(dir)
		if err == nil {
			visited := 0
			err = scanDependents(ctx, dir, root, source, rootState.id.Device, 0, &visited, limit, &hits)
		}
		dir.Close()
		if err != nil {
			return fmt.Errorf("dependent scan of %s: %w", root, err)
		}
	}
	if len(hits) > 0 {
		return fmt.Errorf("external dependents keep %s local: %s", source, strings.Join(hits, "; "))
	}
	return nil
}

func scanDependents(ctx context.Context, dir *os.File, dirAbs, source string, device uint64, depth int, visited *int, limit int, hits *[]string) error {
	names, err := readNames(dir, limit)
	if err != nil {
		return err
	}
	fd := int(dir.Fd())
	hit := func(detail string) {
		if len(*hits) < maxReported {
			*hits = append(*hits, detail)
		}
	}
	record := func(path, target, what string) {
		if core.PathWithin(target, source) {
			hit(fmt.Sprintf("%s %s -> %s", what, path, target))
		}
	}
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return err
		}
		*visited++
		if *visited > limit {
			return fmt.Errorf("exceeded the %d-entry bound; narrow dependent_roots", limit)
		}
		path := filepath.Join(dirAbs, name)
		if core.PathWithin(path, source) {
			continue
		}
		st, err := statxAt(fd, name, 0)
		if err != nil {
			if errors.Is(err, unix.ENOENT) {
				continue
			}
			return err
		}
		switch st.kind() {
		case unix.S_IFLNK:
			target, err := readlinkAt(fd, name)
			if err != nil {
				return err
			}
			// Every path the chain reaches counts, so a link through source or
			// a symlinked directory is a dependent; a chain that cannot be
			// followed to its end may reach source and refuses.
			reached, err := resolveLink(path, target)
			if err != nil {
				hit(fmt.Sprintf("symlink %s -> %s cannot be resolved: %v", path, target, err))
				continue
			}
			lexical := target
			if !filepath.IsAbs(lexical) {
				lexical = filepath.Join(dirAbs, lexical)
			}
			for _, p := range append(reached, filepath.Clean(lexical)) {
				if core.PathWithin(p, source) {
					hit(fmt.Sprintf("symlink %s -> %s reaches %s", path, target, p))
					break
				}
			}
		case unix.S_IFREG:
			isAlternates := name == "alternates" && filepath.Base(dirAbs) == "info" && filepath.Base(filepath.Dir(dirAbs)) == "objects"
			if name != ".git" && !isAlternates {
				continue
			}
			data, err := readSmall(dir, name)
			if err != nil {
				return fmt.Errorf("read %s: %w", path, err)
			}
			if isAlternates {
				for _, target := range alternateTargets(data, filepath.Dir(dirAbs)) {
					record(path, target, "alternates")
				}
			} else if target, ok := gitdirTarget(data, dirAbs); ok {
				record(path, target, "gitdir")
			}
		case unix.S_IFDIR:
			if depth+1 >= dependentDepth || st.id.Device != device {
				continue
			}
			child, err := openChild(dir, name, unix.O_RDONLY|unix.O_DIRECTORY)
			if err != nil {
				return err
			}
			err = scanDependents(ctx, child, path, source, device, depth+1, visited, limit, hits)
			child.Close()
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func readSmall(dir *os.File, name string) (string, error) {
	f, err := openChild(dir, name, unix.O_RDONLY)
	if err != nil {
		return "", err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxPointerSize+1))
	if err != nil {
		return "", err
	}
	if len(data) > maxPointerSize {
		return "", fmt.Errorf("pointer file exceeds the %d-byte bound; cannot rule out a dependent", maxPointerSize)
	}
	return string(data), nil
}

// hasXattrs fails closed: extended metadata is not archived, so any present
// or unknowable attribute keeps the item local. A filesystem without xattr
// support has none.
func hasXattrs(n int, err error) bool {
	if errors.Is(err, unix.ENOTSUP) {
		return false
	}
	return err != nil || n != 0
}
