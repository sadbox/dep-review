package artifact

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"golang.org/x/mod/sumdb/dirhash"
)

func hashMismatch(ref Ref, format string, args ...any) error {
	return fmt.Errorf("%w: %s %s@%s: %s", ErrHashMismatch, ref.Kind, ref.Name, ref.Version, fmt.Sprintf(format, args...))
}

// The exact shape of each kind's hash. Anything else is refused before
// any download: a hash the gate cannot check is not a weaker hash, it is
// no hash.
var (
	// One "h1:" hash: base64 of a SHA-256.
	moduleHashRE = regexp.MustCompile(`^h1:[A-Za-z0-9+/]{43}=$`)
	// Exactly one sha512 token. npm accepts a download that matches any
	// token of a multi-hash integrity string, so a second token would let
	// other bytes through than the ones checked here.
	integrityRE = regexp.MustCompile(`^sha512-[A-Za-z0-9+/]{86}==$`)
	// A full SHA-1 commit ID.
	commitRE = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// verify checks a downloaded archive against ref.Hash. It runs before the
// archive is extracted, and for the two kinds that have a content hash,
// before anything in the archive is interpreted at all.
func verify(archive string, ref Ref) error {
	switch ref.Kind {
	case GoModuleZip:
		return verifyModuleZip(archive, ref)
	case NPMTarball:
		return verifyIntegrity(archive, ref)
	case ActionTarball:
		return verifyCommit(archive, ref)
	}
	return fmt.Errorf("%w: kind %q", ErrBadRef, ref.Kind)
}

// verifyModuleZip recomputes the module's "h1:" hash, the one go.sum and
// the checksum database hold, with the go command's own code.
func verifyModuleZip(archive string, ref Ref) error {
	got, err := dirhash.HashZip(archive, dirhash.Hash1)
	if err != nil {
		return unsafeArchive("hashing the module zip: %v", err)
	}
	if got != ref.Hash {
		return hashMismatch(ref, "the zip hashes to %s, the pull request is bound to %s", got, ref.Hash)
	}
	return nil
}

// verifyIntegrity compares the SHA-512 of the tarball's bytes with the
// lockfile's integrity.
func verifyIntegrity(archive string, ref Ref) error {
	want, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(ref.Hash, "sha512-"))
	if err != nil || len(want) != sha512.Size {
		return fmt.Errorf("%w: integrity %q", ErrBadRef, ref.Hash)
	}
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha512.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	if got := h.Sum(nil); !bytes.Equal(got, want) {
		return hashMismatch(ref, "the tarball is sha512-%s, the pull request is bound to %s",
			base64.StdEncoding.EncodeToString(got), ref.Hash)
	}
	return nil
}

// verifyCommit checks that a repository tarball says it is the commit the
// pull request pins.
//
// This is weaker than the other two and cannot be made stronger: a git
// archive has no content hash. What binds the bytes to the commit is that
// GitHub was asked, over TLS, for that commit by its full ID, which is
// exactly what the Actions runner does and all it has. The commit ID
// that git archive writes into the tarball's global header (the one "git
// get-tar-commit-id" prints) is checked on top, so a tarball of some
// other commit, served or stored under the wrong name, is not read.
func verifyCommit(archive string, ref Ref) error {
	got, err := tarballCommit(archive)
	if err != nil {
		return err
	}
	if got == "" {
		return hashMismatch(ref, "the tarball does not say which commit it is")
	}
	if got != ref.Hash {
		return hashMismatch(ref, "the tarball is commit %s, the pull request is bound to %s", escapeLine(got), ref.Hash)
	}
	return nil
}

// tarballCommit returns the commit ID in a git archive's global header,
// or "" when the tarball's first entry is not one.
func tarballCommit(archive string) (string, error) {
	f, err := os.Open(archive)
	if err != nil {
		return "", err
	}
	defer f.Close()
	zr, err := gzip.NewReader(bufio.NewReader(f))
	if err != nil {
		return "", unsafeArchive("not a gzip stream: %v", err)
	}
	defer zr.Close()
	h, err := tar.NewReader(zr).Next()
	if err != nil {
		return "", unsafeArchive("reading the archive: %v", err)
	}
	if h.Typeflag != tar.TypeXGlobalHeader {
		return "", nil
	}
	return h.PAXRecords["comment"], nil
}
