// Package npm is the npm_and_yarn fetcher. It recomputes the change set
// from package-lock.json (v2/v3) or yarn.lock (v1) at the merge base and
// the head, fetches registry metadata and both tarballs of every changed
// package from registry.npmjs.org (npm and yarn are never run), verifies
// the sha512 integrity against the lockfiles, extracts the tarballs with
// the gate's own reader, diffs them and runs the npm hard stops.
package npm

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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
	"github.com/sadbox/dep-review/internal/model"
)

// MaxPackages bounds how many changed packages are downloaded and diffed;
// the rest are reported unverified (RouteHuman).
const MaxPackages = 40

const registryHost = "registry.npmjs.org"

// Fetcher implements fetch.Ecosystem for npm_and_yarn.
type Fetcher struct {
	// Registry overrides https://registry.npmjs.org (tests only).
	Registry string
}

type change struct {
	update   model.Update
	base     Entry // zero for a new package
	head     Entry
	lockKind string
}

func (f Fetcher) registry() string {
	if f.Registry != "" {
		return f.Registry
	}
	return "https://" + registryHost
}

func (f Fetcher) Fetch(ctx context.Context, env fetch.Env) (fetch.Result, error) {
	home := filepath.Join(env.Scratch, "npm-home")
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
		case "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock":
			dirs[path.Dir(p)] = true
		default:
			other = append(other, p)
		}
	}
	if len(other) > 0 {
		res.Findings = append(res.Findings, human("npm.unexpected-files", "", "the PR changes files other than package.json and lockfiles: "+ecoutil.List(other, 20)))
	}
	var summary bytes.Buffer
	var changes []change
	for _, dir := range slices.Sorted(maps.Keys(dirs)) {
		cs, fs, err := dirChanges(ctx, git, base, env.Class.HeadSHA, dir, &summary)
		if err != nil {
			return fetch.Result{}, err
		}
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
			names = append(names, c.update.Name+"@"+c.update.To)
		}
		res.Findings = append(res.Findings, human("npm.not-verified", "", fmt.Sprintf("more than %d changed packages; not downloaded or diffed: %s", MaxPackages, ecoutil.List(names, 30))))
		work = work[:MaxPackages]
	}
	summary.WriteString("## Downloads (registry.npmjs.org)\n\n")
	for i, c := range work {
		fs, err := f.verifyAndDiff(ctx, env, home, filepath.Join(env.Scratch, "npm", fmt.Sprint(i)), c, &summary)
		if err != nil {
			return fetch.Result{}, err
		}
		res.Findings = append(res.Findings, fs...)
	}
	if err := env.Evidence.Add("npm-summary.md", "npm change set, integrity verification and checks run by the gate", summary.Bytes()); err != nil {
		return fetch.Result{}, err
	}
	return res, nil
}

func readAt(ctx context.Context, git ecoutil.Git, sha, p string) ([]byte, error) {
	b, err := git.Show(ctx, sha, p)
	if errors.Is(err, ecoutil.ErrNotExist) {
		return nil, nil
	}
	return b, err
}

func loadLock(ctx context.Context, git ecoutil.Git, sha, dir string) (*Lock, error) {
	for _, name := range []string{"npm-shrinkwrap.json", "package-lock.json", "yarn.lock"} {
		b, err := readAt(ctx, git, sha, path.Join(dir, name))
		if err != nil {
			return nil, err
		}
		if b == nil {
			continue
		}
		if name == "yarn.lock" {
			l, err := ParseYarnLock(b)
			if err != nil {
				return nil, err
			}
			pj, err := readAt(ctx, git, sha, path.Join(dir, "package.json"))
			if err != nil {
				return nil, err
			}
			if pj != nil {
				if l.Direct, err = ManifestDirect(pj); err != nil {
					return nil, fmt.Errorf("package.json: %w", err)
				}
			}
			return l, nil
		}
		return ParsePackageLock(b)
	}
	return nil, nil
}

// dirChanges compares one directory's lockfile at base and head.
func dirChanges(ctx context.Context, git ecoutil.Git, base, head, dir string, summary *bytes.Buffer) ([]change, []model.Finding, error) {
	depDir := path.Clean("/" + dir)
	var findings []model.Finding
	bl, berr := loadLock(ctx, git, base, dir)
	hl, herr := loadLock(ctx, git, head, dir)
	for _, e := range []error{berr, herr} {
		if e != nil {
			var exit interface{ ExitCode() int }
			if errors.As(e, &exit) {
				return nil, nil, e // git itself failed
			}
			findings = append(findings, human("npm.lockfile-unsupported", "", depDir+": "+e.Error()))
			return nil, findings, nil
		}
	}
	if hl == nil {
		findings = append(findings, human("npm.no-lockfile", "", depDir+": no package-lock.json or yarn.lock at head; nothing pins what gets installed"))
		return nil, findings, nil
	}
	if bl == nil {
		bl = &Lock{Kind: hl.Kind, Direct: map[string]bool{}}
	}
	if bl.Kind != hl.Kind {
		findings = append(findings, human("npm.lockfile-kind-changed", "", fmt.Sprintf("%s: lockfile changed from %s to %s", depDir, bl.Kind, hl.Kind)))
	}
	fmt.Fprintf(summary, "## %s (%s lockfile)\n\n", depDir, hl.Kind)

	type key struct{ name, version string }
	index := func(l *Lock) (map[string][]string, map[key]Entry) {
		vers := map[string][]string{}
		byKey := map[key]Entry{}
		for _, e := range l.Entries {
			if e.Bundled {
				continue // inside its parent's tarball, diffed with it
			}
			k := key{e.Name, e.Version}
			if _, ok := byKey[k]; !ok {
				vers[e.Name] = append(vers[e.Name], e.Version)
			}
			byKey[k] = e
		}
		return vers, byKey
	}
	bv, bk := index(bl)
	hv, hk := index(hl)

	// Same name@version with different bytes or origin is never legitimate.
	for k, h := range hk {
		if b, ok := bk[k]; ok && (b.Integrity != h.Integrity || stripFragment(b.Resolved) != stripFragment(h.Resolved)) {
			findings = append(findings, model.Finding{Code: "npm.same-version-changed", Route: model.RouteRefuse, Update: k.name,
				Detail: fmt.Sprintf("%s: %s@%s keeps its version but its integrity or resolved URL changed", depDir, k.name, k.version)})
		}
	}
	// Every new or changed entry must come from the public registry, pinned by integrity.
	for k, h := range hk {
		if _, ok := bk[k]; ok {
			continue
		}
		switch {
		case h.Link:
			findings = append(findings, human("npm.link", k.name, fmt.Sprintf("%s: %s is a workspace link", depDir, k.name)))
		case !registryURL(h.Resolved, hl.Kind):
			findings = append(findings, model.Finding{Code: "npm.resolved-off-registry", Route: model.RouteRefuse, Update: k.name,
				Detail: fmt.Sprintf("%s: %s@%s resolves to %q, not %s", depDir, k.name, k.version, h.Resolved, registryHost)})
		case sha512Of(h.Integrity) == nil:
			findings = append(findings, human("npm.weak-integrity", k.name, fmt.Sprintf("%s: %s@%s has no sha512 integrity in the lockfile", depDir, k.name, k.version)))
		}
	}

	var changes []change
	names := slices.Sorted(maps.Keys(ecoutil.Union(bv, hv)))
	for _, name := range names {
		removed, added := ecoutil.DiffSets(bv[name], hv[name])
		if len(removed) == 0 && len(added) == 0 {
			continue
		}
		pairs, gone := ecoutil.Pair(removed, added, ecoutil.Intersect(bv[name], hv[name]))
		for _, g := range gone {
			fmt.Fprintf(summary, "- %s %s: removed\n", name, g)
		}
		for _, p := range pairs {
			u := model.Update{
				Ecosystem: model.NPM, Directory: depDir, Name: name, From: p[0], To: p[1],
				Type: ecoutil.TypeOf(p[0], p[1]), Direct: hl.Direct[name],
			}
			c := change{update: u, head: hk[key{name, p[1]}], lockKind: hl.Kind}
			if p[0] != "" {
				if e, ok := bk[key{name, p[0]}]; ok {
					c.base = e
				} else {
					c.base = hk[key{name, p[0]}] // a kept copy
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

func stripFragment(u string) string {
	u, _, _ = strings.Cut(u, "#")
	return u
}

// registryURL: an https tarball URL on the public registry. yarn v1 writes
// registry.yarnpkg.com, which serves the same registry.
func registryURL(raw, kind string) bool {
	hosts := []string{registryHost}
	if kind == "yarn" {
		hosts = append(hosts, "registry.yarnpkg.com")
	}
	return ecoutil.CheckHost(stripFragment(raw), hosts...) == nil
}

// sha512Of returns the sha512 digest in an SRI integrity string.
func sha512Of(integrity string) []byte {
	for _, h := range strings.Fields(integrity) {
		if b64, ok := strings.CutPrefix(h, "sha512-"); ok {
			if d, err := base64.StdEncoding.DecodeString(b64); err == nil && len(d) == sha512.Size {
				return d
			}
		}
	}
	return nil
}

// versionDoc is the registry's document for one version.
type versionDoc struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	NPMUser *struct {
		Name             string          `json:"name"`
		Email            string          `json:"email"`
		TrustedPublisher json.RawMessage `json:"trustedPublisher"`
	} `json:"_npmUser"`
	Maintainers []struct {
		Name string `json:"name"`
	} `json:"maintainers"`
	Dist struct {
		Tarball      string          `json:"tarball"`
		Integrity    string          `json:"integrity"`
		Shasum       string          `json:"shasum"`
		Attestations json.RawMessage `json:"attestations"`
	} `json:"dist"`
	manifest
}

var (
	nameRE    = regexp.MustCompile(`^(@[A-Za-z0-9][A-Za-z0-9._-]*/)?[A-Za-z0-9][A-Za-z0-9._-]*$`)
	versionRE = regexp.MustCompile(`^[0-9A-Za-z.+-]+$`)
)

func (f Fetcher) versionDoc(ctx context.Context, env fetch.Env, name, version string) (*versionDoc, []byte, error) {
	if !nameRE.MatchString(name) || !versionRE.MatchString(version) {
		return nil, nil, fmt.Errorf("refusing package %q version %q", name, version)
	}
	u := f.registry() + "/" + strings.Replace(name, "/", "%2f", 1) + "/" + url.PathEscape(version)
	b, err := ecoutil.GetBytes(ctx, env.HTTP, u, ecoutil.MetadataLimit, map[string][]string{"Accept": {"application/json"}})
	if err != nil {
		return nil, nil, err
	}
	var d versionDoc
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", u, err)
	}
	if d.Name != name || d.Version != version {
		return nil, nil, fmt.Errorf("%s: registry returned %s@%s", u, d.Name, d.Version)
	}
	return &d, b, nil
}

// side is one version of a package: registry doc, tarball, tree.
type side struct {
	doc  *versionDoc
	tree *ecoutil.Tree
	pkg  manifest // package.json from the tarball
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
	var sides [2]*side
	for i, s := range []struct {
		ver   string
		entry Entry
		label string
	}{{u.From, c.base, "old"}, {u.To, c.head, "new"}} {
		if s.ver == "" {
			continue
		}
		doc, _, err := f.versionDoc(ctx, env, u.Name, s.ver)
		if errors.Is(err, ecoutil.ErrNotFound) {
			add(model.RouteHuman, "npm.not-on-registry", fmt.Sprintf("%s is not on %s (unpublished?)", s.ver, registryHost))
			return findings, nil
		}
		if err != nil {
			return nil, err
		}
		want := sha512Of(s.entry.Integrity)
		if want == nil {
			add(model.RouteHuman, "npm.weak-integrity", s.ver+": lockfile has no sha512 integrity; not verified")
			return findings, nil
		}
		if reg := sha512Of(doc.Dist.Integrity); reg == nil || !bytes.Equal(reg, want) {
			add(model.RouteRefuse, "npm.integrity-mismatch", fmt.Sprintf("%s: lockfile integrity %s differs from the registry's %s", s.ver, s.entry.Integrity, doc.Dist.Integrity))
			return findings, nil
		}
		if err := ecoutil.CheckHost(doc.Dist.Tarball, registryHost); err != nil && f.Registry == "" {
			add(model.RouteRefuse, "npm.tarball-off-registry", s.ver+": "+err.Error())
			return findings, nil
		}
		tgz := filepath.Join(dir, s.label+".tgz")
		if err := ecoutil.GetFile(ctx, env.HTTP, doc.Dist.Tarball, tgz, ecoutil.ArtifactLimit); err != nil {
			return nil, err
		}
		data, err := os.ReadFile(tgz)
		if err != nil {
			return nil, err
		}
		sum := sha512.Sum512(data)
		if !bytes.Equal(sum[:], want) {
			add(model.RouteRefuse, "npm.integrity-mismatch", fmt.Sprintf("%s: downloaded tarball sha512 does not match the lockfile", s.ver))
			return findings, nil
		}
		if doc.Dist.Shasum != "" {
			if s1 := sha1.Sum(data); fmt.Sprintf("%x", s1) != doc.Dist.Shasum {
				add(model.RouteRefuse, "npm.integrity-mismatch", s.ver+": tarball sha1 differs from the registry's shasum")
				return findings, nil
			}
		}
		tree, err := ecoutil.ExtractTarGz(tgz, filepath.Join(dir, s.label), true)
		if err != nil {
			add(model.RouteHuman, "npm.bad-tarball", fmt.Sprintf("%s: %v", s.ver, err))
			return findings, nil
		}
		if i == 1 && len(tree.Rejected) > 0 {
			add(model.RouteHuman, "npm.unsafe-tarball-entry", fmt.Sprintf("%s: tarball has entries the gate does not extract: %s", s.ver, ecoutil.List(tree.Rejected, 10)))
		}
		sd := &side{doc: doc, tree: tree}
		if pj := tree.ReadFile("package.json"); pj != nil {
			if err := json.Unmarshal(pj, &sd.pkg); err != nil {
				add(model.RouteHuman, "npm.bad-package-json", fmt.Sprintf("%s: package.json: %v", s.ver, err))
			}
		} else {
			add(model.RouteHuman, "npm.bad-package-json", s.ver+": tarball has no package.json")
		}
		sides[i] = sd
		fmt.Fprintf(summary, "- %s@%s: sha512 matches lockfile and registry; %d files\n", u.Name, s.ver, len(tree.Files))
	}
	old, cur := sides[0], sides[1]
	if cur == nil {
		return findings, nil
	}
	for _, fd := range checkPackage(old, cur) {
		add(fd.Route, fd.Code, fd.Detail)
	}

	var oldRel string
	if old != nil {
		oldRel = "old"
	}
	diffs, cut, err := ecoutil.DiffTrees(ctx, home, dir, oldRel, "new")
	if err != nil {
		return nil, err
	}
	text, _ := ecoutil.JoinDiffs(diffs, nil)
	if cut {
		text = append(text, "\n[dep-review: diff exceeded the gate's read limit]\n"...)
	}
	if len(text) == 0 {
		text = []byte("(the package trees are identical)\n")
	}
	name := "npm" + u.Directory + "/" + u.Name + "@" + ecoutil.OrNew(u.From) + "..." + u.To + ".diff"
	if err := env.Evidence.AddUntrusted(name, fmt.Sprintf("diff of npm package %s %s -> %s (third-party code)", u.Name, ecoutil.OrNew(u.From), u.To), text); err != nil {
		return nil, err
	}
	return findings, nil
}

func human(code, update, detail string) model.Finding {
	return model.Finding{Code: code, Route: model.RouteHuman, Update: update, Detail: detail}
}
