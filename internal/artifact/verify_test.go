package artifact

import (
	"archive/tar"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sadbox/dep-review/internal/allow"
)

// Each recorded artifact verifies against the hash its authority
// reported, and against no other.
func TestVerifyRecorded(t *testing.T) {
	refs := []Ref{recordedNPM.Old, recordedNPM.New, recordedModule.Old, recordedModule.New, recordedAction.Old, recordedAction.New}
	for _, ref := range refs {
		if err := verify(recordedFile(ref), ref); err != nil {
			t.Errorf("%s %s@%s: %v", ref.Kind, ref.Name, ref.Version, err)
		}
	}
	// Every artifact under its neighbour's hash.
	for i, ref := range refs {
		other := refs[i^1]
		wrong := ref
		wrong.Hash = other.Hash
		err := verify(recordedFile(ref), wrong)
		if !errors.Is(err, ErrHashMismatch) {
			t.Errorf("%s %s@%s under the hash of %s: error %v, want ErrHashMismatch", ref.Kind, ref.Name, ref.Version, other.Version, err)
		}
	}
}

func TestVerifyOneChangedByte(t *testing.T) {
	for _, ref := range []Ref{recordedNPM.New, recordedModule.New} {
		b, err := os.ReadFile(recordedFile(ref))
		if err != nil {
			t.Fatal(err)
		}
		// In the module zip, a byte of a stored file's content: the h1
		// hash covers names and contents, not the zip's own framing.
		at := len(b) / 2
		if ref.Kind == GoModuleZip {
			at = strings.Index(string(b), "rsc.io/quote@v1.5.2/go.mod") + len("rsc.io/quote@v1.5.2/go.mod") + 2
		}
		b[at] ^= 1
		name := filepath.Join(t.TempDir(), "changed")
		if err := os.WriteFile(name, b, 0o600); err != nil {
			t.Fatal(err)
		}
		err = verify(name, ref)
		if err == nil {
			t.Errorf("%s: one changed byte verified", ref.Kind)
		} else if !errors.Is(err, ErrHashMismatch) && !errors.Is(err, ErrUnsafeArchive) {
			t.Errorf("%s: error %v", ref.Kind, err)
		}
	}
}

func TestVerifyCommit(t *testing.T) {
	commit := strings.Repeat("ab", 20)
	ref := Ref{Kind: ActionTarball, Name: "owner/repo", Version: "v1", Hash: commit}
	file := tarEntry{name: "owner-repo-abababa/action.yml", body: "name: x\n"}
	tests := []struct {
		name    string
		archive []byte
		want    error
		say     string
	}{
		{"the commit", actionTarball(t, commit, map[string]string{"action.yml": "name: x\n"}), nil, ""},
		{"another commit", actionTarball(t, strings.Repeat("cd", 20), map[string]string{"action.yml": "name: x\n"}), ErrHashMismatch, "is commit cdcd"},
		{"no global header", gzipped(t, buildTar(t, []tarEntry{file})), ErrHashMismatch, "does not say which commit"},
		{"a global header without the commit", gzipped(t, buildTar(t, []tarEntry{
			{typ: tar.TypeXGlobalHeader, pax: map[string]string{"mtime": "1"}}, file})), ErrHashMismatch, "does not say which commit"},
		{"the commit in a later header", gzipped(t, buildTar(t, []tarEntry{
			file, {typ: tar.TypeXGlobalHeader, pax: map[string]string{"comment": commit}}})), ErrHashMismatch, "does not say which commit"},
		{"the commit with something after it", actionTarball(t, commit+"\n", map[string]string{"action.yml": "name: x\n"}), ErrHashMismatch, "is commit"},
		{"a prefix of the commit", actionTarball(t, commit[:39]+"x", map[string]string{"action.yml": "name: x\n"}), ErrHashMismatch, "is commit"},
		{"not gzip", buildTar(t, []tarEntry{file}), ErrUnsafeArchive, "not a gzip stream"},
		{"empty", nil, ErrUnsafeArchive, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name := filepath.Join(t.TempDir(), "a.tar.gz")
			if err := os.WriteFile(name, tt.archive, 0o600); err != nil {
				t.Fatal(err)
			}
			err := verify(name, ref)
			if tt.want == nil {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if !errors.Is(err, tt.want) || !strings.Contains(err.Error(), tt.say) {
				t.Errorf("error %v, want %v saying %q", err, tt.want, tt.say)
			}
			if strings.ContainsAny(err.Error(), "\n\r") {
				t.Errorf("the error message has a line break from the archive: %q", err)
			}
		})
	}
}

// Verification comes before extraction: an archive that is both the
// wrong one and unsafe is refused for being the wrong one, and none of it
// is written out.
func TestVerifyComesBeforeExtract(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "outside")
	unsafe := gzipped(t, buildTar(t, []tarEntry{
		{name: "package/link", typ: tar.TypeSymlink, link: outside},
		{name: outside, body: "x"},
	}))
	good := npmTarball(t, map[string]string{"index.js": "a\n"})

	t.Run("npm", func(t *testing.T) {
		p := Pair{Ecosystem: allow.NPM, Name: "demo", From: "1.0.0", To: "1.0.1",
			Old: Ref{Kind: NPMTarball, Name: "demo", Version: "1.0.0", Hash: integrity(good)},
			New: Ref{Kind: NPMTarball, Name: "demo", Version: "1.0.1", Hash: integrity(good)}}
		r := newReader(t, fakeFetcher{p.Old: good, p.New: unsafe})
		_, err := r.Prepare(context.Background(), p, roomy)
		if !errors.Is(err, ErrHashMismatch) || errors.Is(err, ErrUnsafeArchive) {
			t.Errorf("error %v, want ErrHashMismatch and not ErrUnsafeArchive", err)
		}
		// The same archive under its own hash gets as far as the
		// extractor, which refuses it.
		p.New.Hash = integrity(unsafe)
		r = newReader(t, fakeFetcher{p.Old: good, p.New: unsafe})
		if _, err := r.Prepare(context.Background(), p, roomy); !errors.Is(err, ErrUnsafeArchive) {
			t.Errorf("error %v, want ErrUnsafeArchive", err)
		}
	})

	t.Run("gomod", func(t *testing.T) {
		zipped := moduleZip(t, "example.com/mod", "v1.0.1", map[string]string{"go.mod": "module example.com/mod\n"})
		oldZip := moduleZip(t, "example.com/mod", "v1.0.0", map[string]string{"go.mod": "module example.com/mod\n"})
		p := Pair{Ecosystem: allow.GoModules, Name: "example.com/mod", From: "v1.0.0", To: "v1.0.1",
			Old: Ref{Kind: GoModuleZip, Name: "example.com/mod", Version: "v1.0.0", Hash: h1(t, oldZip)},
			New: Ref{Kind: GoModuleZip, Name: "example.com/mod", Version: "v1.0.1", Hash: h1(t, oldZip)}}
		r := newReader(t, fakeFetcher{p.Old: oldZip, p.New: zipped})
		if _, err := r.Prepare(context.Background(), p, roomy); !errors.Is(err, ErrHashMismatch) {
			t.Errorf("error %v, want ErrHashMismatch", err)
		}
		// A zip for another version, under its own hash: the hash
		// matches, the go command's rules for a module zip do not.
		p.New.Hash = h1(t, oldZip)
		r = newReader(t, fakeFetcher{p.Old: oldZip, p.New: oldZip})
		if _, err := r.Prepare(context.Background(), p, roomy); !errors.Is(err, ErrUnsafeArchive) {
			t.Errorf("error %v, want ErrUnsafeArchive: the zip is for v1.0.0", err)
		}
	})

	if _, err := os.Lstat(outside); err == nil {
		t.Errorf("%s was written", outside)
	}
}
