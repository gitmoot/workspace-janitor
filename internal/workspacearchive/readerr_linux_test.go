//go:build linux

package workspacearchive

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// failingContext lets the first ok calls to Err pass, then fails every read
// through contextReader: with cancel set it cancels the real context (a
// deadline or shutdown mid-copy), otherwise it returns err (an I/O error).
type failingContext struct {
	context.Context
	ok     int
	err    error
	cancel context.CancelFunc
}

func (c *failingContext) Err() error {
	if c.ok > 0 {
		c.ok--
		return c.Context.Err()
	}
	if c.cancel != nil {
		c.cancel()
		return c.Context.Err()
	}
	return c.err
}

// fileUnitTar archives one large file so that its member spans many reads,
// and returns the manifest with the open tar.
func fileUnitTar(t *testing.T) (Manifest, *os.File, string) {
	t.Helper()
	f := newFixture(t)
	f.source = filepath.Join(f.home, "work", "big.bin")
	f.rule.Name, f.rule.Path = "big", f.source
	write(t, f.source, bytes.Repeat([]byte("0123456789abcdef"), 64<<10), 0o640)
	stamp(t, f.source)
	m, _, err := Create(context.Background(), f.rule, f.scope, allow)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	path := filepath.Join(f.archive, "big.tar")
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { file.Close() })
	return m, file, path
}

func TestVerifyTarReportsAReadErrorMidMemberAsARead(t *testing.T) {
	injected := errors.New("sshfs: input/output error")
	cases := map[string]func() (context.Context, error){
		"injected I/O error": func() (context.Context, error) {
			return &failingContext{Context: context.Background(), ok: 4, err: injected}, injected
		},
		"context cancelled mid-copy": func() (context.Context, error) {
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			return &failingContext{Context: ctx, ok: 4, cancel: cancel}, context.Canceled
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			m, file, _ := fileUnitTar(t)
			ctx, cause := setup()
			_, err := verifyTar(ctx, file, manifestLayout(m), m.TarBytes)
			if err == nil {
				t.Fatal("verifyTar accepted an archive it could not read")
			}
			if !errors.Is(err, cause) {
				t.Fatalf("verifyTar error %q does not wrap %v", err, cause)
			}
			if !strings.Contains(err.Error(), "reading archive member .") || strings.Contains(err.Error(), "differs") {
				t.Fatalf("verifyTar error %q, want a read error for the member, not a mismatch", err)
			}
		})
	}
}

func TestVerifyTarStillReportsChangedContent(t *testing.T) {
	m, file, path := fileUnitTar(t)
	// Flip one byte inside the member's content, past whatever headers
	// precede it, so the size is unchanged and only the hash differs.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	at := int64(bytes.Index(raw, []byte("0123456789abcdef")) + 1000)
	if at < 1000 {
		t.Fatal("member content not found in the tar")
	}
	if _, err := file.WriteAt([]byte{raw[at] ^ 0xff}, at); err != nil {
		t.Fatal(err)
	}
	_, err = verifyTar(context.Background(), file, manifestLayout(m), m.TarBytes)
	if err == nil || !strings.Contains(err.Error(), "archive member . content differs from the manifest") {
		t.Fatalf("verifyTar = %v, want the content mismatch", err)
	}
}
