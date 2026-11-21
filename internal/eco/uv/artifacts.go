package uv

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/sadbox/dep-review/internal/eco/ecoutil"
	"github.com/sadbox/dep-review/internal/evidence"
	"github.com/sadbox/dep-review/internal/fetch"
	"github.com/sadbox/dep-review/internal/model"
)

// Bounds on the artifacts checked beyond the diffed one, per package. A
// package over them is reported unverified (RouteHuman).
const (
	MaxArtifacts      = 64
	MaxArtifactsBytes = 1 << 30
)

// maxArtifactsBytes is MaxArtifactsBytes; tests lower it.
var maxArtifactsBytes int64 = MaxArtifactsBytes

// checkOtherArtifacts downloads, verifies and checks every artifact the
// lock pins for the new version besides the diffed wheel and sdist
// (sides[1]). Each other wheel is checked against the diffed wheel; a
// wheel whose files differ from it gets its own diff in the evidence and a
// finding, since the reviewer saw only the diffed one. The sdist is checked
// against the old version's.
func (f Fetcher) checkOtherArtifacts(ctx context.Context, env fetch.Env, home, dir string, c change, wheel, sdist *Artifact, sides [2]sideTrees, summary *bytes.Buffer) ([]model.Finding, error) {
	u := c.update
	var rest []Artifact
	var size int64
	unsized := false
	for _, a := range c.head.Artifacts() {
		if (wheel != nil && a.URL == wheel.URL) || (sdist != nil && a.URL == sdist.URL) {
			continue
		}
		rest = append(rest, a)
		size += a.Size
		// The lock's size is the PR's word; a missing one could hide
		// anything, so it counts as over the cap.
		unsized = unsized || a.Size <= 0
	}
	if len(rest) == 0 {
		return nil, nil
	}
	notVerified := func(why string) model.Finding {
		return human("uv.not-verified", u.Name, fmt.Sprintf("%s: %s; the remaining artifacts were not checked", u.To, why))
	}
	switch {
	case unsized:
		return []model.Finding{notVerified("the lock gives an artifact no positive size")}, nil
	case len(rest) > MaxArtifacts || size > maxArtifactsBytes:
		return []model.Finding{notVerified(fmt.Sprintf("%d further artifacts (%d bytes declared) exceed what the gate downloads", len(rest), size))}, nil
	}
	// Declared sizes can understate: count what actually arrives, and
	// stop once that is over the cap.
	var downloaded int64
	overCap := func(dst string) bool {
		if fi, err := os.Stat(dst + ".dl"); err == nil {
			downloaded += fi.Size()
		}
		return downloaded > maxArtifactsBytes
	}
	var out []model.Finding
	add := func(code, detail string) {
		out = append(out, model.Finding{Code: code, Route: model.RouteHuman, Detail: detail})
	}
	oldSdist := sides[0].sdist
	seen := map[string]bool{}
	for n, a := range rest {
		name := artifactName(a.URL)
		dst := filepath.Join(dir, fmt.Sprintf("extra-%d", n))
		t, bad, err := f.fetchArtifact(ctx, env, dst, a)
		if err != nil {
			return nil, err
		}
		if overCap(dst) {
			out = append(out, notVerified(fmt.Sprintf("downloads reached %d bytes, over the gate's %d", downloaded, maxArtifactsBytes)))
			break
		}
		if bad != nil {
			bad.Detail = u.To + " " + name + ": " + bad.Detail
			out = append(out, *bad)
			continue
		}
		fmt.Fprintf(summary, "- %s==%s %s: %s matches the lock; %d files (checked, not diffed)\n", u.Name, u.To, name, a.Hash, len(t.Files))
		if len(t.Rejected) > 0 {
			add("uv.unsafe-archive-entry", fmt.Sprintf("%s %s has entries the gate does not extract: %s", u.To, name, ecoutil.List(t.Rejected, 10)))
		}
		var fs []model.Finding
		if strings.HasSuffix(name, ".whl") {
			ref := sides[1].wheel
			fs = append(checkPackage(sideTrees{wheel: ref}, sideTrees{wheel: t}), rootFindings(sides[0].wheel, t)...)
			if differ := variantFiles(ref, t); len(differ) > 0 {
				add("uv.wheel-variant-differs", fmt.Sprintf("%s %s differs from the reviewed %s in: %s", u.To, name, artifactName(wheel.URL), ecoutil.List(differ, 10)))
				diffs, cut, err := ecoutil.DiffTrees(ctx, home, dir, filepath.Base(ref.Dir), filepath.Base(t.Dir))
				if err != nil {
					return nil, err
				}
				text, _ := ecoutil.JoinDiffs(diffs, wheelBookkeeping)
				if cut {
					text = append(text, "\n[dep-review: diff exceeded the gate's read limit]\n"...)
				}
				if key := string(text); len(text) > 0 && !seen[key] {
					seen[key] = true
					ev := "uv" + u.Directory + "/" + u.Name + "@" + u.To + "." + name + ".variant.diff"
					desc := fmt.Sprintf("diff of Python package %s %s: the reviewed wheel %s against %s (third-party code)", u.Name, u.To, artifactName(wheel.URL), name)
					if err := env.Evidence.AddUntrusted(ev, desc, text); err != nil {
						return nil, err
					}
				}
			}
		} else {
			if oldSdist == nil && u.From != "" && c.base.Sdist != nil {
				odst := filepath.Join(dir, "old-sdist-extra")
				ot, bad, err := f.fetchArtifact(ctx, env, odst, *c.base.Sdist)
				if err != nil {
					return nil, err
				}
				if overCap(odst) {
					out = append(out, notVerified(fmt.Sprintf("downloads reached %d bytes, over the gate's %d", downloaded, maxArtifactsBytes)))
					break
				}
				if bad != nil {
					bad.Detail = u.From + " sdist: " + bad.Detail
					out = append(out, *bad)
					continue
				}
				oldSdist = ot
			}
			fs = checkPackage(sideTrees{sdist: oldSdist}, sideTrees{sdist: t})
		}
		for _, fd := range fs {
			fd.Detail = name + ": " + fd.Detail
			out = append(out, fd)
		}
	}
	for i := range out {
		out[i].Update = u.Name
	}
	return out, nil
}

// wheelBookkeeping are the per-wheel files that legitimately differ
// between the wheels of one release (tags, file hashes).
func wheelBookkeeping(rel string) bool {
	dir, base := path.Split(rel)
	return strings.HasSuffix(dir, ".dist-info/") && strings.Count(rel, "/") == 1 && (base == "RECORD" || base == "WHEEL")
}

// variantFiles lists the files of wheel t that are missing from, or
// differ from, the reviewed wheel ref (and those only ref has), apart from
// wheel bookkeeping and native extensions (flagged on their own).
func variantFiles(ref, t *ecoutil.Tree) []string {
	var out []string
	for _, tr := range [][2]*ecoutil.Tree{{ref, t}, {t, ref}} {
		for _, f := range tr[1].Files {
			if wheelBookkeeping(f) || isNativeExt(f) {
				continue
			}
			if !tr[0].Has(f) {
				out = append(out, f)
				continue
			}
			if tr[1] == t && !bytes.Equal(ref.ReadFile(f), t.ReadFile(f)) {
				out = append(out, f)
			}
		}
	}
	return out
}

func isNativeExt(f string) bool {
	switch path.Ext(f) {
	case ".so", ".pyd", ".dylib", ".dll":
		return true
	}
	return false
}

// isExecutable: ELF, Mach-O, PE or WebAssembly.
func isExecutable(b []byte) bool {
	for _, magic := range [][]byte{
		{0x7f, 'E', 'L', 'F'}, {0xfe, 0xed, 0xfa, 0xce}, {0xfe, 0xed, 0xfa, 0xcf},
		{0xce, 0xfa, 0xed, 0xfe}, {0xcf, 0xfa, 0xed, 0xfe}, {0xca, 0xfe, 0xba, 0xbe},
		{'M', 'Z'}, {0x00, 'a', 's', 'm'},
	} {
		if bytes.HasPrefix(b, magic) {
			return true
		}
	}
	return false
}

// compiledFiles finds what nobody can review as source in cur: Python
// bytecode (.pyc/.pyo, anything under __pycache__/), with the
// unchecked-hash ones (PEP 552 flags == 1: the interpreter runs them
// without ever looking at the .py beside them) listed separately, and
// executables or other binary files added or changed since old. No
// directory is exempt: a wheel installs everything it holds, and an sdist
// build can read anything in it.
func compiledFiles(old, cur *ecoutil.Tree) (pyc, unchecked, opaque []string) {
	for _, f := range cur.Files {
		if isNativeExt(f) {
			continue
		}
		data := cur.ReadFile(f)
		if ext := path.Ext(f); ext == ".pyc" || ext == ".pyo" || strings.Contains("/"+f, "/__pycache__/") {
			pyc = append(pyc, f)
			if len(data) >= 8 && data[4] == 1 && data[5] == 0 && data[6] == 0 && data[7] == 0 {
				unchecked = append(unchecked, f)
			}
			continue
		}
		if !isExecutable(data) && !evidence.IsBinary(data) {
			continue
		}
		if old.Has(f) && bytes.Equal(old.ReadFile(f), data) {
			continue
		}
		opaque = append(opaque, f)
	}
	return pyc, unchecked, opaque
}
