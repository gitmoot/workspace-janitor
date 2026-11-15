package core

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
)

// GitBlobID hashes exactly size bytes of r as a Git blob object in the object
// format of like (a 40- or 64-digit object ID) and returns its ID. Every byte
// is also written to also when it is not nil. A short read or an unknown
// object format is an error. Callers re-check the file's identity and size
// afterwards: bytes appended during the read are not seen here.
func GitBlobID(ctx context.Context, r io.Reader, size int64, like string, also io.Writer) (string, error) {
	var sum hash.Hash
	switch len(like) {
	case 40:
		// SHA-1 here verifies Git's object format, not a content approval.
		sum = sha1.New()
	case 64:
		sum = sha256.New()
	default:
		return "", errors.New("unknown Git object format")
	}
	if size < 0 {
		return "", errors.New("negative blob size")
	}
	fmt.Fprintf(sum, "blob %d\x00", size)
	var writer io.Writer = sum
	if also != nil {
		writer = io.MultiWriter(sum, also)
	}
	var buffer [32 << 10]byte
	for remaining := size; remaining > 0; {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		chunk := min(remaining, int64(len(buffer)))
		n, err := io.ReadFull(r, buffer[:chunk])
		if err != nil {
			return "", err
		}
		_, _ = writer.Write(buffer[:n])
		remaining -= int64(n)
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}
