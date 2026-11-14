//go:build linux

package workspacearchive

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

// deadlineAtOffset is a context whose deadline passes once file has been
// read up to at: every read through contextReader from then on fails with
// context.DeadlineExceeded, as a verification budget running out there would.
type deadlineAtOffset struct {
	context.Context
	file *os.File
	at   int64
}

func (c deadlineAtOffset) Err() error {
	if offset, err := c.file.Seek(0, io.SeekCurrent); err != nil || offset >= c.at {
		return context.DeadlineExceeded
	}
	return nil
}

// lastContentEnd is the tar offset just past the last member's content: the
// next read is its padding or the archive terminator.
func lastContentEnd(t *testing.T, raw []byte) int64 {
	t.Helper()
	r := bytes.NewReader(raw)
	tr := tar.NewReader(r)
	end := int64(-1)
	for {
		_, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, tr); err != nil {
			t.Fatal(err)
		}
		end = r.Size() - int64(r.Len())
	}
	if end < 0 {
		t.Fatal("tar holds no member")
	}
	return end
}

// #215 review: a deadline that strikes after the last member's content, at
// the archive terminator, keeps its identity, so the caller can defer the
// verification instead of refusing a valid archive as holding extra members.
func TestVerifyTarKeepsADeadlineAtTheTerminator(t *testing.T) {
	m, file, path := fileUnitTar(t)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := deadlineAtOffset{Context: context.Background(), file: file, at: lastContentEnd(t, raw)}
	_, err = verifyTar(ctx, file, manifestLayout(m), m.TarBytes)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("verifyTar = %v, want the deadline", err)
	}
	if !strings.Contains(err.Error(), "reading archive terminator") {
		t.Fatalf("verifyTar = %v, want a read error at the terminator", err)
	}
}

// Guard: a member the manifest does not list, after every listed one, is
// still refused as such.
func TestVerifyTarStillRefusesAnExtraMember(t *testing.T) {
	m, file, path := fileUnitTar(t)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Replace the terminator with one more member and a new terminator.
	end := lastContentEnd(t, raw)
	end += (512 - end%512) % 512
	var extra bytes.Buffer
	tw := tar.NewWriter(&extra)
	if err := tw.WriteHeader(&tar.Header{Name: "extra.txt", Mode: 0o600, Size: 5, Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("extra")); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	grown := append(append([]byte(nil), raw[:end]...), extra.Bytes()...)
	if err := file.Truncate(0); err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt(grown, 0); err != nil {
		t.Fatal(err)
	}
	_, err = verifyTar(context.Background(), file, manifestLayout(m), int64(len(grown)))
	if err == nil || !strings.Contains(err.Error(), "archive holds members absent from the manifest") {
		t.Fatalf("verifyTar = %v, want the extra member refused", err)
	}
}
