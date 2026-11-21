// Package uv is the uv fetcher. It recomputes the change set from uv.lock
// at the merge base and the head, downloads the locked artifacts of every
// changed package from files.pythonhosted.org (uv and pip are never run),
// verifies their sha256 against the lockfiles, extracts them with the
// gate's own readers, diffs them and runs the Python hard stops.
package uv

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/sadbox/dep-review/internal/eco/ecoutil"
	"github.com/sadbox/dep-review/internal/fetch"
	"github.com/sadbox/dep-review/internal/gh"
	"github.com/sadbox/dep-review/internal/model"
	"github.com/sadbox/dep-review/internal/strictjson"
)

// MaxPackages bounds how many changed packages are downloaded and diffed;
// the rest are reported unverified (RouteHuman).
const MaxPackages = 25

const (
	pypiRegistry = "https://pypi.org/simple"
	filesHost    = "files.pythonhosted.org"
)

// Fetcher implements fetch.Ecosystem for uv.
type Fetcher struct {
	// AllowHost overrides files.pythonhosted.org (tests only).
	AllowHost string
	// PyPI overrides https://pypi.org (tests only).
	PyPI string
}

type change struct {
	update     model.Update
	base, head Package
}

func (f Fetcher) host() string {
	if f.AllowHost != "" {
		return f.AllowHost
	}
	return filesHost
}

func (f Fetcher) Fetch(ctx context.Context, env fetch.Env) (fetch.Result, error) {
	home := filepath.Join(env.Scratch, "uv-home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		return fetch.Result{}, err
	}
	git := ecoutil.Git{Repo: env.RepoDir, Home: home}
	base, err := git.MergeBase(ctx, env.Class.BaseSHA, env.Class.HeadSHA)
	if err != nil {
		return fetch.Result{}, err
	}
	files, err := git.ChangedFiles(ctx, base, env.Class.HeadSHA)
	if err != nil {
		return fetch.Result{}, err
	}
	var res fetch.Result
	dirs := map[string]bool{}
	var other []string
	for _, p := range files {
		switch path.Base(p) {
		case "uv.lock", "pyproject.toml":
			dirs[path.Dir(p)] = true
		default:
			other = append(other, p)
		}
	}
	if len(other) > 0 {
		res.Findings = append(res.Findings, human("uv.unexpected-files", "", "the PR changes files other than uv.lock and pyproject.toml: "+ecoutil.List(other, 20)))
	}
	var summary bytes.Buffer
	var changes []change
	for _, dir := range slices.Sorted(maps.Keys(dirs)) {
		cs, fs, err := dirChanges(ctx, git, base, env.Class.HeadSHA, dir, &summary)
		if err != nil {
			return fetch.Result{}, err
		}
		mf, err := manifestChanges(ctx, git, base, env.Class.HeadSHA, dir, env.Class.Declared)
		if err != nil {
			return fetch.Result{}, err
		}
		fs = append(fs, mf...)
		changes = append(changes, cs...)
		res.Findings = append(res.Findings, fs...)
	}
	for _, c := range changes {
		res.Updates = append(res.Updates, c.update)
	}
	sort.SliceStable(changes, func(i, j int) bool { return changes[i].update.Direct && !changes[j].update.Direct })
	work := changes
	if len(work) > MaxPackages {
		var names []string
		for _, c := range work[MaxPackages:] {
			names = append(names, c.update.Name+"=="+c.update.To)
		}
		res.Findings = append(res.Findings, human("uv.not-verified", "", fmt.Sprintf("more than %d changed packages; not downloaded or diffed: %s", MaxPackages, ecoutil.List(names, 30))))
		work = work[:MaxPackages]
	}
	summary.WriteString("## Downloads (files.pythonhosted.org)\n\n")
	for _, c := range work {
		fs, err := f.crossCheckPyPI(ctx, env, c)
		if err != nil {
			return fetch.Result{}, err
		}
		res.Findings = append(res.Findings, fs...)
	}
	for i, c := range work {
		fs, err := f.verifyAndDiff(ctx, env, home, filepath.Join(env.Scratch, "uv", fmt.Sprint(i)), c, &summary)
		if err != nil {
			return fetch.Result{}, err
		}
		res.Findings = append(res.Findings, fs...)
	}
	if err := env.Evidence.Add("uv-summary.md", "uv change set, hash verification and checks run by the gate", summary.Bytes()); err != nil {
		return fetch.Result{}, err
	}
	return res, nil
}

func dirChanges(ctx context.Context, git ecoutil.Git, base, head, dir string, summary *bytes.Buffer) ([]change, []model.Finding, error) {
	depDir := path.Clean("/" + dir)
	var findings []model.Finding
	load := func(sha string) (*Lock, error) {
		b, err := git.Show(ctx, sha, path.Join(dir, "uv.lock"))
		if errors.Is(err, ecoutil.ErrNotExist) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		return ParseLock(string(b))
	}
	bl, err := load(base)
	var exit interface{ ExitCode() int }
	if err != nil && errors.As(err, &exit) {
		return nil, nil, err
	}
	hl, herr := load(head)
	if herr != nil && errors.As(herr, &exit) {
		return nil, nil, herr
	}
	if err != nil || herr != nil {
		findings = append(findings, human("uv.lockfile-unsupported", "", fmt.Sprintf("%s: %v", depDir, errors.Join(err, herr))))
		return nil, findings, nil
	}
	if hl == nil {
		findings = append(findings, human("uv.no-lockfile", "", depDir+": no uv.lock at head"))
		return nil, findings, nil
	}
	if bl == nil {
		bl = &Lock{}
	}
	fmt.Fprintf(summary, "## %s (uv.lock)\n\n", depDir)

	refuse := func(code, name, detail string) {
		findings = append(findings, model.Finding{Code: code, Route: model.RouteRefuse, Update: name, Detail: depDir + ": " + detail})
	}

	// The workspace's own packages are never downloaded, so which ones
	// they are comes from the head's pyproject.toml files, not the lock.
	hw, err := loadWorkspace(ctx, git, head, dir)
	if err != nil {
		if errors.As(err, &exit) {
			return nil, nil, err
		}
		findings = append(findings, human("uv.manifest-unparseable", "", fmt.Sprintf("%s: %v", depDir, err)))
		return nil, findings, nil
	}
	headProject := map[int]bool{}
	direct := map[string]bool{}
	for i, p := range hl.Packages {
		if len(p.Source) != 1 {
			refuse("uv.source-ambiguous", Normalize(p.Name), fmt.Sprintf("%s==%s has source %v; a uv source has exactly one key", p.Name, p.Version, p.Source))
			continue
		}
		rel, ok := p.projectPath()
		if !ok {
			continue
		}
		why, err := hw.checkProject(ctx, p, rel)
		if err != nil {
			return nil, nil, err
		}
		if why != "" {
			refuse("uv.project-source-invalid", Normalize(p.Name), fmt.Sprintf("source %v: %s", p.Source, why))
			continue
		}
		headProject[i] = true
		for _, d := range p.Deps {
			direct[d] = true
		}
	}
	type key struct{ name, version string }
	// Every copy is kept: uv.lock can list one name==version more than once
	// (resolution forks), and each copy's artifacts are installable.
	index := func(l *Lock, isProject func(int, Package) bool) (map[string][]string, map[key][]Package) {
		vers := map[string][]string{}
		byKey := map[key][]Package{}
		for i, p := range l.Packages {
			if isProject(i, p) {
				continue
			}
			n := Normalize(p.Name)
			k := key{n, p.Version}
			if _, ok := byKey[k]; !ok {
				vers[n] = append(vers[n], p.Version)
			}
			byKey[k] = append(byKey[k], p)
		}
		return vers, byKey
	}
	// The base is trusted: its workspace packages are whatever it says.
	bv, bk := index(bl, func(_ int, p Package) bool { _, ok := p.projectPath(); return ok })
	hv, hk := index(hl, func(i int, _ Package) bool { return headProject[i] })
	for _, k := range slices.SortedFunc(maps.Keys(hk), func(a, b key) int { return strings.Compare(a.name+"=="+a.version, b.name+"=="+b.version) }) {
		copies := hk[k]
		for _, p := range copies[1:] {
			if pkgOrigin(p) != pkgOrigin(copies[0]) {
				refuse("uv.duplicate-disagrees", k.name, fmt.Sprintf("%s==%s is listed more than once with different source or artifacts", k.name, k.version))
				break
			}
		}
		known := map[string]bool{}
		for _, b := range bk[k] {
			known[pkgOrigin(b)] = true
		}
		for _, p := range copies {
			if known[pkgOrigin(p)] {
				continue // unchanged since the base
			}
			if len(bk[k]) > 0 {
				refuse("uv.same-version-changed", k.name, fmt.Sprintf("%s==%s keeps its version but its source or artifacts changed", k.name, k.version))
			}
			// New or changed: the source and every artifact, downloaded or not.
			if p.Registry() != pypiRegistry {
				refuse("uv.source-off-registry", k.name, fmt.Sprintf("%s==%s comes from %v, not %s", k.name, k.version, p.Source, pypiRegistry))
			}
			for _, a := range p.Artifacts() {
				if err := ecoutil.CheckHost(a.URL, filesHost); err != nil {
					refuse("uv.artifact-off-registry", k.name, fmt.Sprintf("%s==%s: %v", k.name, k.version, err))
				}
				if !sha256RE.MatchString(a.Hash) {
					refuse("uv.weak-hash", k.name, fmt.Sprintf("%s==%s: %s has hash %q, not sha256", k.name, k.version, artifactName(a.URL), a.Hash))
				}
			}
		}
	}

	var changes []change
	for _, name := range slices.Sorted(maps.Keys(ecoutil.Union(bv, hv))) {
		removed, added := ecoutil.DiffSets(bv[name], hv[name])
		if len(removed) == 0 && len(added) == 0 {
			continue
		}
		pairs, gone := ecoutil.Pair(removed, added, ecoutil.Intersect(bv[name], hv[name]))
		for _, g := range gone {
			fmt.Fprintf(summary, "- %s %s: removed\n", name, g)
		}
		for _, p := range pairs {
			u := model.Update{Ecosystem: model.UV, Directory: depDir, Name: name, From: p[0], To: p[1],
				Type: ecoutil.TypeOf(p[0], p[1]), Direct: direct[name]}
			// Copies agree or the PR is refused above, so the first stands for all.
			c := change{update: u, head: hk[key{name, p[1]}][0]}
			if p[0] != "" {
				if b, ok := bk[key{name, p[0]}]; ok {
					c.base = b[0]
				} else {
					c.base = hk[key{name, p[0]}][0]
				}
			}
			kind := "transitive"
			if u.Direct {
				kind = "direct"
			}
			fmt.Fprintf(summary, "- %s: %s -> %s (%s, %s)\n", name, ecoutil.OrNew(u.From), u.To, u.Type, kind)
			changes = append(changes, c)
		}
	}
	summary.WriteString("\n")
	return changes, findings, nil
}

var (
	pyNameRE    = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$`)
	pyVersionRE = regexp.MustCompile(`^[0-9A-Za-z.+!_-]+$`)
)

// crossCheckPyPI compares every artifact the lock pins for the new version
// (wheels for every platform, not only the one the gate downloads) with
// PyPI's own file list and sha256 digests for that release.
func (f Fetcher) crossCheckPyPI(ctx context.Context, env fetch.Env, c change) ([]model.Finding, error) {
	u := c.update
	if !pyNameRE.MatchString(u.Name) || !pyVersionRE.MatchString(u.To) {
		return []model.Finding{{Code: "uv.bad-name", Route: model.RouteRefuse, Update: u.Name, Detail: fmt.Sprintf("refusing package %q version %q", u.Name, u.To)}}, nil
	}
	base := f.PyPI
	if base == "" {
		base = "https://pypi.org"
	}
	b, err := ecoutil.GetBytes(ctx, env.HTTP, base+"/pypi/"+u.Name+"/"+u.To+"/json", ecoutil.MetadataLimit, map[string][]string{"Accept": {"application/json"}})
	if errors.Is(err, gh.ErrNotFound) {
		return []model.Finding{human("uv.not-on-pypi", u.Name, fmt.Sprintf("%s==%s is not on PyPI (deleted release?)", u.Name, u.To))}, nil
	}
	if err != nil {
		return nil, err
	}
	var doc struct {
		URLs []struct {
			Filename string `json:"filename"`
			Digests  struct {
				SHA256 string `json:"sha256"`
			} `json:"digests"`
		} `json:"urls"`
	}
	if err := strictjson.Unmarshal(b, &doc); err != nil {
		return []model.Finding{{Code: "uv.pypi-json-ambiguous", Route: model.RouteRefuse, Update: u.Name,
			Detail: fmt.Sprintf("PyPI JSON for %s==%s: %v", u.Name, u.To, err)}}, nil
	}
	onPyPI := map[string]string{}
	for _, f := range doc.URLs {
		onPyPI[f.Filename] = "sha256:" + strings.ToLower(f.Digests.SHA256)
	}
	var bad []string
	for _, a := range c.head.Artifacts() {
		name := artifactName(a.URL)
		if got, ok := onPyPI[name]; !ok || got != a.Hash {
			bad = append(bad, name)
		}
	}
	if len(bad) > 0 {
		return []model.Finding{{Code: "uv.hash-not-on-pypi", Route: model.RouteRefuse, Update: u.Name,
			Detail: fmt.Sprintf("%s==%s: lock artifacts missing from PyPI's release or with a different sha256: %s", u.Name, u.To, ecoutil.List(bad, 10))}}, nil
	}
	return nil, nil
}

// pick chooses what to download for one version: the pure-Python wheel if
// there is one (then uv never builds the sdist), otherwise a linux x86_64
// wheel (what the gate's own runners and servers install) plus the sdist.
// like, if set, is the file-name tail of the wheel chosen for the other
// version, so both sides compare the same build.
func pick(p Package, like string) (wheel *Artifact, sdist *Artifact) {
	var pure, linux, sameTags *Artifact
	for i := range p.Wheels {
		w := &p.Wheels[i]
		name := artifactName(w.URL)
		switch {
		case like != "" && wheelTags(name) == like:
			sameTags = w
		case strings.HasSuffix(name, "-none-any.whl") && (pure == nil || strings.Contains(name, "-py3-")):
			pure = w
		case linux == nil && strings.Contains(name, "manylinux") && strings.Contains(name, "x86_64"):
			linux = w
		}
	}
	switch {
	case sameTags != nil:
		wheel = sameTags
	case pure != nil:
		wheel = pure
	case linux != nil:
		wheel = linux
	case len(p.Wheels) > 0:
		wheel = &p.Wheels[0]
	}
	if wheel == nil || !strings.HasSuffix(artifactName(wheel.URL), "-none-any.whl") {
		sdist = p.Sdist
	}
	return wheel, sdist
}

func artifactName(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return path.Base(u.Path)
}

// wheelTags is "pyver-abi-platform.whl" from a wheel file name.
func wheelTags(name string) string {
	parts := strings.Split(name, "-")
	if len(parts) < 5 {
		return ""
	}
	return strings.Join(parts[len(parts)-3:], "-")
}

// sideTrees holds one version's extracted artifacts.
type sideTrees struct {
	wheel, sdist *ecoutil.Tree
}

func (f Fetcher) verifyAndDiff(ctx context.Context, env fetch.Env, home, dir string, c change, summary *bytes.Buffer) ([]model.Finding, error) {
	u := c.update
	var findings []model.Finding
	add := func(route model.Route, code, detail string) {
		findings = append(findings, model.Finding{Code: code, Route: route, Update: u.Name, Detail: u.Name + ": " + detail})
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	newWheel, newSdist := pick(c.head, "")
	if newWheel == nil && newSdist == nil {
		add(model.RouteHuman, "uv.no-artifacts", u.To+": the lock lists no wheel or sdist")
		return findings, nil
	}
	like := ""
	if newWheel != nil {
		like = wheelTags(artifactName(newWheel.URL))
	}
	oldWheel, oldSdist := pick(c.base, like)
	if newSdist != nil && oldSdist == nil {
		oldSdist = c.base.Sdist
	}

	var sides [2]sideTrees
	for i, s := range []struct {
		label        string
		ver          string
		wheel, sdist *Artifact
	}{{"old", u.From, oldWheel, oldSdist}, {"new", u.To, newWheel, newSdist}} {
		if s.ver == "" {
			continue
		}
		for _, a := range []struct {
			kind string
			art  *Artifact
			dst  **ecoutil.Tree
		}{{"wheel", s.wheel, &sides[i].wheel}, {"sdist", s.sdist, &sides[i].sdist}} {
			if a.art == nil {
				continue
			}
			t, bad, err := f.fetchArtifact(ctx, env, filepath.Join(dir, s.label+"-"+a.kind), *a.art)
			if err != nil {
				return nil, err
			}
			if bad != nil {
				bad.Update = u.Name
				bad.Detail = u.Name + "==" + s.ver + ": " + bad.Detail
				findings = append(findings, *bad)
				return findings, nil
			}
			if i == 1 && len(t.Rejected) > 0 {
				add(model.RouteHuman, "uv.unsafe-archive-entry", fmt.Sprintf("%s %s has entries the gate does not extract: %s", s.ver, a.kind, ecoutil.List(t.Rejected, 10)))
			}
			*a.dst = t
			fmt.Fprintf(summary, "- %s==%s %s %s: %s matches the lock; %d files\n", u.Name, s.ver, a.kind, artifactName(a.art.URL), a.art.Hash, len(t.Files))
		}
	}
	for _, fd := range checkPackage(sides[0], sides[1]) {
		add(fd.Route, fd.Code, fd.Detail)
	}

	// uv installs whichever wheel fits the machine, or builds the sdist,
	// so every artifact the lock pins for the new version gets the same
	// hard checks, not only the one diffed above.
	extra, err := f.checkOtherArtifacts(ctx, env, home, dir, c, newWheel, newSdist, sides, summary)
	if err != nil {
		return nil, err
	}
	for _, fd := range extra {
		add(fd.Route, fd.Code, fd.Detail)
	}

	// Diff what gets installed: the wheel, else the sdist.
	kind, oldT, newT := "wheel", sides[0].wheel, sides[1].wheel
	if newT == nil {
		kind, oldT, newT = "sdist", sides[0].sdist, sides[1].sdist
	}
	rel := func(t *ecoutil.Tree) string {
		if t == nil {
			return ""
		}
		return filepath.Base(t.Dir)
	}
	diffs, cut, err := ecoutil.DiffTrees(ctx, home, dir, rel(oldT), rel(newT))
	if err != nil {
		return nil, err
	}
	text, _ := ecoutil.JoinDiffs(diffs, nil)
	if cut {
		text = append(text, "\n[dep-review: diff exceeded the gate's read limit]\n"...)
	}
	if len(text) == 0 {
		text = []byte("(the trees are identical)\n")
	}
	name := "uv" + u.Directory + "/" + u.Name + "@" + ecoutil.OrNew(u.From) + "..." + u.To + "." + kind + ".diff"
	if err := env.Evidence.AddUntrusted(name, fmt.Sprintf("diff of Python package %s %s -> %s (%s; third-party code)", u.Name, ecoutil.OrNew(u.From), u.To, kind), text); err != nil {
		return nil, err
	}
	return findings, nil
}

// fetchArtifact downloads, verifies and extracts one artifact into dst
// (dst+".dl" holds the download). A non-nil Finding means the artifact
// must not be used.
func (f Fetcher) fetchArtifact(ctx context.Context, env fetch.Env, dst string, a Artifact) (*ecoutil.Tree, *model.Finding, error) {
	if err := ecoutil.CheckHost(a.URL, f.host()); err != nil && f.AllowHost == "" {
		return nil, &model.Finding{Code: "uv.artifact-off-registry", Route: model.RouteRefuse, Detail: err.Error()}, nil
	}
	want, ok := strings.CutPrefix(a.Hash, "sha256:")
	if !ok || len(want) != 64 {
		return nil, &model.Finding{Code: "uv.weak-hash", Route: model.RouteHuman, Detail: fmt.Sprintf("lock hash %q is not sha256", a.Hash)}, nil
	}
	dl := dst + ".dl"
	if err := ecoutil.GetFile(ctx, env.HTTP, a.URL, dl, ecoutil.ArtifactLimit); err != nil {
		if errors.Is(err, gh.ErrNotFound) {
			return nil, &model.Finding{Code: "uv.artifact-missing", Route: model.RouteHuman, Detail: artifactName(a.URL) + " is not on " + filesHost}, nil
		}
		return nil, nil, err
	}
	fh, err := os.Open(dl)
	if err != nil {
		return nil, nil, err
	}
	h := sha256.New()
	_, err = io.Copy(h, fh)
	fh.Close()
	if err != nil {
		return nil, nil, err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != strings.ToLower(want) {
		return nil, &model.Finding{Code: "uv.hash-mismatch", Route: model.RouteRefuse,
			Detail: fmt.Sprintf("%s has sha256 %s, the lock says %s", artifactName(a.URL), got, want)}, nil
	}
	name := artifactName(a.URL)
	var t *ecoutil.Tree
	switch {
	case strings.HasSuffix(name, ".whl"):
		t, err = ecoutil.ExtractZip(dl, dst, false)
	case strings.HasSuffix(name, ".zip"):
		t, err = ecoutil.ExtractZip(dl, dst, true)
	case strings.HasSuffix(name, ".tar.gz"), strings.HasSuffix(name, ".tgz"):
		t, err = ecoutil.ExtractTarGz(dl, dst, true)
	default:
		return nil, &model.Finding{Code: "uv.unknown-archive", Route: model.RouteHuman, Detail: name + ": unsupported archive format"}, nil
	}
	if err != nil {
		return nil, &model.Finding{Code: "uv.bad-archive", Route: model.RouteHuman, Detail: fmt.Sprintf("%s: %v", name, err)}, nil
	}
	return t, nil, nil
}

var sha256RE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// pkgOrigin is what must not differ between two copies of one version.
func pkgOrigin(p Package) string { return fmt.Sprint(p.Source, p.Sdist, p.Wheels) }

func human(code, update, detail string) model.Finding {
	return model.Finding{Code: code, Route: model.RouteHuman, Update: update, Detail: detail}
}
