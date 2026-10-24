//go:build linux

package exportarchive

import (
	"bytes"
	"compress/gzip"
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

const maxManifestBytes = 64 << 10

type contextReader struct {
	context.Context
	io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.Err(); err != nil {
		return 0, err
	}
	return r.Reader.Read(p)
}

type spaceWriter struct {
	root    *os.File
	reserve uint64
	out     io.Writer
}

func (w spaceWriter) Write(p []byte) (int, error) {
	if err := requireSpace(w.root, w.reserve+uint64(len(p))); err != nil {
		return 0, err
	}
	return w.out.Write(p)
}

// Create publishes only after a real restore verifies content and metadata.
// preflight must rerun the ordinary fresh safety observation, without treating
// the missing archive itself as permission to bypass any other protection.
func Create(ctx context.Context, rule config.EvidenceExportRule, expected core.Entry, preflight func() error) (Manifest, *core.ExportArchiveBinding, error) {
	var m Manifest
	if preflight == nil {
		return m, nil, errors.New("archive creation requires fresh safety preflight")
	}
	if err := preflight(); err != nil {
		return m, nil, err
	}
	source, err := openRegular(rule.Path)
	if err != nil {
		return m, nil, err
	}
	defer source.Close()
	before, err := checkExportFile(source, rule.MaxBytes)
	if err != nil {
		return m, nil, err
	}
	if before.Identity != expected.FilesystemID {
		return m, nil, errors.New("export identity changed after safety observation")
	}
	root, err := openDirectory(rule.Archive.Directory)
	if err != nil {
		return m, nil, err
	}
	defer root.Close()
	rootState, err := snapshot(root)
	if err != nil {
		return m, nil, err
	}
	container, err := independentContainer(rule.SourceContainer, rootState)
	if err != nil {
		return m, nil, err
	}
	if container.MountID != before.MountID {
		return m, nil, errors.New("export crosses its declared source container mount")
	}
	if err = requireSpace(root, uint64(before.Size)*2+(1<<20)); err != nil {
		return m, nil, err
	}
	stagePath, err := os.MkdirTemp(descriptorPath(root), ".partial-export-")
	if err != nil {
		return m, nil, err
	}
	defer os.RemoveAll(stagePath) // only this newly allocated private staging directory
	stageName := filepath.Base(stagePath)
	stage, err := openChild(root, stageName, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return m, nil, err
	}
	defer stage.Close()
	payload, err := openChild(stage, "content.gz", unix.O_RDWR|unix.O_CREAT|unix.O_EXCL)
	if err != nil {
		return m, nil, err
	}
	defer payload.Close()
	archiveHash, sourceHash := sha256.New(), sha256.New()
	compressed, err := gzip.NewWriterLevel(io.MultiWriter(spaceWriter{root, uint64(before.Size), payload}, archiveHash), gzip.BestSpeed)
	if err != nil {
		return m, nil, err
	}
	count, copyErr := io.Copy(io.MultiWriter(compressed, sourceHash), contextReader{ctx, io.LimitReader(source, rule.MaxBytes+1)})
	closeErr := compressed.Close()
	if copyErr != nil {
		return m, nil, copyErr
	}
	if closeErr != nil {
		return m, nil, closeErr
	}
	after, err := checkExportFile(source, rule.MaxBytes)
	if err != nil || before != after || count != before.Size {
		return m, nil, errors.New("export changed while being archived; original retained")
	}
	if err = payload.Sync(); err != nil {
		return m, nil, err
	}
	archived, err := snapshot(payload)
	if err != nil {
		return m, nil, err
	}
	m = Manifest{Version: 1, SourcePath: rule.Path, Source: before, SourceSHA256: hex.EncodeToString(sourceHash.Sum(nil)), RuleSHA256: RuleHash(rule), ArchiveDirectory: rootState.Identity, ArchiveBytes: archived.Size, ArchiveAllocatedBytes: archived.AllocatedBytes, ArchiveSHA256: hex.EncodeToString(archiveHash.Sum(nil)), CreatedAt: time.Now().UTC()}
	m.Rule = archiveRule(rule)
	restored, err := openChild(stage, "restore-proof", unix.O_RDWR|unix.O_CREAT|unix.O_EXCL)
	if err != nil {
		return m, nil, err
	}
	restoreErr := restorePayload(ctx, payload, restored, root, m)
	if restoreErr == nil {
		restoreErr = verifyRestored(ctx, restored, m)
	}
	closeErr = restored.Close()
	if restoreErr != nil {
		return m, nil, restoreErr
	}
	if closeErr != nil {
		return m, nil, closeErr
	}
	if err = unix.Unlinkat(int(stage.Fd()), "restore-proof", 0); err != nil {
		return m, nil, err
	}
	if err = preflight(); err != nil {
		return m, nil, err
	}
	after, err = checkExportFile(source, rule.MaxBytes)
	if err != nil || before != after {
		return m, nil, errors.New("export changed during restore proof")
	}
	m.RestoredAt = time.Now().UTC()
	data, err := json.Marshal(m)
	if err != nil {
		return m, nil, err
	}
	manifest, err := openChild(stage, "manifest.json", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL)
	if err != nil {
		return m, nil, err
	}
	_, err = manifest.Write(data)
	if err == nil {
		err = manifest.Sync()
	}
	closeErr = manifest.Close()
	if err != nil {
		return m, nil, err
	}
	if closeErr != nil {
		return m, nil, closeErr
	}
	if err = stage.Sync(); err != nil {
		return m, nil, err
	}
	finalName := "export-" + uuid.NewString()
	if err = publishDirectory(root, stageName, finalName); err != nil {
		return m, nil, err
	}
	sum := sha256.Sum256(data)
	binding := &core.ExportArchiveBinding{Manifest: filepath.Join(rule.Archive.Directory, finalName, "manifest.json"), ManifestSHA256: hex.EncodeToString(sum[:])}
	rule.Archive.Manifest, rule.Archive.ManifestSHA256 = binding.Manifest, binding.ManifestSHA256
	if _, _, err = Check(ctx, rule, rule.Path, true); err != nil {
		return m, nil, fmt.Errorf("published archive failed read-back; original retained: %w", err)
	}
	return m, binding, nil
}

// Check validates the pinned manifest and source identity/metadata. Full checks
// additionally verify both original bytes and decompressed archive bytes, and
// are mandatory before the existing engine moves or expires a local export.
func Check(ctx context.Context, rule config.EvidenceExportRule, sourcePath string, full bool) (Manifest, *core.ExportArchiveBinding, error) {
	m, payload, err := load(ctx, rule, sourcePath != "")
	if err != nil {
		return m, nil, err
	}
	defer payload.Close()
	if sourcePath != "" {
		source, err := openRegular(sourcePath)
		if err != nil {
			return m, nil, err
		}
		defer source.Close()
		before, err := checkExportFile(source, rule.MaxBytes)
		if err != nil || !sameMetadata(before, m.Source) {
			return m, nil, errors.New("export metadata or identity no longer matches its archive")
		}
		if full {
			digest, count, err := hashFile(ctx, source, rule.MaxBytes)
			after, statErr := checkExportFile(source, rule.MaxBytes)
			if err != nil || statErr != nil || before != after || count != m.Source.Size || digest != m.SourceSHA256 {
				return m, nil, errors.New("export bytes changed or could not be verified")
			}
		}
	}
	if full {
		if err = verifyPayload(ctx, payload, m); err != nil {
			return m, nil, err
		}
	}
	return m, &core.ExportArchiveBinding{Manifest: rule.Archive.Manifest, ManifestSHA256: rule.Archive.ManifestSHA256}, nil
}

func load(ctx context.Context, rule config.EvidenceExportRule, strictIdentity bool) (Manifest, *os.File, error) {
	var m Manifest
	if rule.Archive.Manifest == "" || rule.Archive.ManifestSHA256 == "" {
		return m, nil, errors.New("no exact verified archive manifest is approved")
	}
	if filepath.Base(rule.Archive.Manifest) != "manifest.json" || !core.PathWithin(rule.Archive.Manifest, rule.Archive.Directory) {
		return m, nil, errors.New("manifest escapes its approved archive directory")
	}
	manifest, err := openRegular(rule.Archive.Manifest)
	if err != nil {
		return m, nil, err
	}
	defer manifest.Close()
	data, err := io.ReadAll(contextReader{ctx, io.LimitReader(manifest, maxManifestBytes+1)})
	if err != nil {
		return m, nil, err
	}
	if len(data) > maxManifestBytes {
		return m, nil, errors.New("oversized archive manifest")
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != rule.Archive.ManifestSHA256 {
		return m, nil, errors.New("archive manifest checksum mismatch")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&m); err != nil {
		return m, nil, err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return m, nil, errors.New("trailing archive manifest data")
	}
	if m.Version != 1 || m.SourcePath != rule.Path || m.RuleSHA256 != RuleHash(rule) || m.Source.Size < 0 || m.Source.Size > rule.MaxBytes || m.ArchiveBytes < 0 || m.ArchiveBytes > rule.MaxBytes+(1<<20) || m.RestoredAt.IsZero() || m.CreatedAt.IsZero() || m.RestoredAt.Before(m.CreatedAt) || m.RestoredAt.After(time.Now().UTC()) {
		return m, nil, errors.New("archive authority, size, or restore proof is invalid")
	}
	if RuleHash(m.Rule) != m.RuleSHA256 {
		return m, nil, errors.New("manifest owner and lifetime record does not match its policy binding")
	}
	root, err := openDirectory(rule.Archive.Directory)
	if err != nil {
		return m, nil, err
	}
	rootState, statErr := snapshot(root)
	root.Close()
	if statErr != nil || (strictIdentity && rootState.Identity != m.ArchiveDirectory) {
		return m, nil, errors.New("archive destination identity changed")
	}
	if strictIdentity {
		if _, err := independentContainer(rule.SourceContainer, rootState); err != nil {
			return m, nil, err
		}
	}
	payload, err := openRegular(filepath.Join(filepath.Dir(rule.Archive.Manifest), "content.gz"))
	if err != nil {
		return m, nil, err
	}
	stat, err := snapshot(payload)
	if err != nil || stat.Size != m.ArchiveBytes || stat.Links != 1 {
		payload.Close()
		return m, nil, errors.New("archive payload metadata changed")
	}
	return m, payload, nil
}

func hashFile(ctx context.Context, file *os.File, limit int64) (string, int64, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", 0, err
	}
	hash := sha256.New()
	count, err := io.Copy(hash, contextReader{ctx, io.LimitReader(file, limit+1)})
	if err == nil && count > limit {
		err = errors.New("archive read exceeds its byte bound")
	}
	return hex.EncodeToString(hash.Sum(nil)), count, err
}

func verifyPayload(ctx context.Context, payload *os.File, m Manifest) error {
	before, err := snapshot(payload)
	if err != nil {
		return err
	}
	digest, count, err := hashFile(ctx, payload, m.ArchiveBytes)
	if err != nil || count != m.ArchiveBytes || digest != m.ArchiveSHA256 {
		return errors.New("archive payload checksum mismatch")
	}
	if _, err = payload.Seek(0, io.SeekStart); err != nil {
		return err
	}
	reader, err := gzip.NewReader(contextReader{ctx, payload})
	if err != nil {
		return err
	}
	defer reader.Close()
	hash := sha256.New()
	count, err = io.Copy(hash, io.LimitReader(reader, m.Source.Size+1))
	after, statErr := snapshot(payload)
	if err != nil || statErr != nil || before != after || count != m.Source.Size || hex.EncodeToString(hash.Sum(nil)) != m.SourceSHA256 {
		return errors.New("restored archive content or integrity does not match the export")
	}
	return nil
}

func restorePayload(ctx context.Context, payload, target, root *os.File, m Manifest) error {
	if err := verifyPayload(ctx, payload, m); err != nil {
		return err
	}
	if _, err := payload.Seek(0, io.SeekStart); err != nil {
		return err
	}
	reader, err := gzip.NewReader(contextReader{ctx, payload})
	if err != nil {
		return err
	}
	defer reader.Close()
	count, err := io.Copy(spaceWriter{root, 0, target}, io.LimitReader(reader, m.Source.Size+1))
	if err != nil {
		return err
	}
	if count != m.Source.Size {
		return errors.New("restored byte count differs")
	}
	if err = setMetadata(target, m.Source); err != nil {
		return err
	}
	return target.Sync()
}
func verifyRestored(ctx context.Context, target *os.File, m Manifest) error {
	state, err := checkExportFile(target, m.Source.Size)
	if err != nil {
		return err
	}
	if state.Size != m.Source.Size || state.Mode != m.Source.Mode || state.UID != m.Source.UID || state.GID != m.Source.GID || state.ModifiedNS != m.Source.ModifiedNS {
		return errors.New("restored metadata differs from the original export")
	}
	digest, count, err := hashFile(ctx, target, m.Source.Size)
	if err != nil || count != m.Source.Size || digest != m.SourceSHA256 {
		return errors.New("actual restored file checksum differs")
	}
	return nil
}

// Restore creates a new file exclusively. It never overwrites an existing path.
func Restore(ctx context.Context, rule config.EvidenceExportRule, destination string) (Manifest, error) {
	if !core.IsCanonicalPath(destination) {
		return Manifest{}, errors.New("restore destination must be canonical and absolute")
	}
	m, payload, err := load(ctx, rule, false)
	if err != nil {
		return m, err
	}
	defer payload.Close()
	if core.PathsOverlap(destination, rule.Archive.Directory) {
		return m, errors.New("restore must not modify the archive container")
	}
	parent, err := openDirectory(filepath.Dir(destination))
	if err != nil {
		return m, err
	}
	defer parent.Close()
	if err = requireSpace(parent, uint64(m.Source.Size)+(1<<20)); err != nil {
		return m, err
	}
	target, err := openChild(parent, filepath.Base(destination), unix.O_RDWR|unix.O_CREAT|unix.O_EXCL)
	if err != nil {
		return m, err
	}
	defer target.Close()
	success := false
	defer func() {
		if !success {
			removeCreated(parent, filepath.Base(destination), target)
		}
	}()
	if err = restorePayload(ctx, payload, target, parent, m); err != nil {
		return m, err
	}
	if err = verifyRestored(ctx, target, m); err != nil {
		return m, err
	}
	if err = parent.Sync(); err != nil {
		return m, err
	}
	success = true
	return m, nil
}
