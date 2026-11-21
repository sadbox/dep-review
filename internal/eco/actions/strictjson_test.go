package actions

import (
	"errors"
	"testing"

	"github.com/sadbox/dep-review/internal/strictjson"
)

// TestPOCActionsFold is the re-review's N4 PoC: encoding/json binds
// "Scripts" and "Version" case-insensitively and lets the last duplicate
// win, so a changed build script or bundler version hid behind an
// unchanged case-folded twin. Both readers now refuse.
func TestPOCActionsFold(t *testing.T) {
	_, err := comparePackageJSON([]byte(`{"scripts":{"build":"ncc build"}}`), []byte(`{"scripts":{"build":"ncc build && node evil.js"},"Scripts":{"build":"ncc build"}}`))
	if !errors.Is(err, strictjson.ErrRejected) {
		t.Errorf("package.json with scripts/Scripts: err %v, want ErrRejected", err)
	}
	_, err = comparePackageJSON([]byte(`{"Scripts":{"build":"x"}}`), []byte(`{"scripts":{"build":"x"}}`))
	if !errors.Is(err, strictjson.ErrRejected) {
		t.Errorf("old package.json with Scripts only: err %v, want ErrRejected", err)
	}
	for _, lock := range []string{
		`{"packages":{"node_modules/esbuild":{"version":"0.99.0","Version":"0.19.0"}}}`,
		`{"packages":{"node_modules/esbuild":{"Version":"0.19.0"}}}`,
		`{"lockfileVersion":1,"dependencies":{"esbuild":{"version":"0.99.0","Version":"0.19.0"}}}`,
	} {
		if _, err := parseLockfile("package-lock.json", []byte(lock)); !errors.Is(err, strictjson.ErrRejected) {
			t.Errorf("%s: err %v, want ErrRejected", lock, err)
		}
	}
	d, err := parseLockfile("package-lock.json", []byte(`{"packages":{"":{"name":"a"},"node_modules/esbuild":{"version":"0.19.0","resolved":"x"}}}`))
	if err != nil || !d.names["esbuild"]["0.19.0"] {
		t.Errorf("ordinary lockfile: %+v %v", d, err)
	}
}
