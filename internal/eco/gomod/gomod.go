// Package gomod is the go_modules fetcher. It recomputes the change set from
// go.mod/go.sum at the merge base and the head (read with `git show`; the
// go command never runs inside the repository), downloads both versions of
// every changed module through proxy.golang.org with sum.golang.org
// checking on, verifies the hashes against the PR's go.sum, diffs the
// module trees and runs the Go checks (see checks.go), writing every item
// they flag into the focused evidence the reviewer must assess.
package gomod

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
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

// MaxModules bounds how many changed modules are downloaded and diffed.
// Direct ones go first; anything past the cap is reported, unverified, as
// a finding that forces RouteHuman.
const MaxModules = 25

// Fetcher implements fetch.Ecosystem for go_modules.
type Fetcher struct {
	GoBin string // the go command; "go" from PATH if empty
}

type change struct {
	update   model.Update
	dir      string // module directory, "" for the root
	baseSum  SumFile
	headSum  SumFile
	sumsOnly bool // only in go.sum (module graph, not in go.mod)
}

func (f Fetcher) Fetch(ctx context.Context, env fetch.Env) (fetch.Result, error) {
	home := filepath.Join(env.Scratch, "gomod-home")
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
		case "go.mod", "go.sum":
			dirs[path.Dir(p)] = true
		default:
			other = append(other, p)
		}
	}
	if len(other) > 0 {
		res.Findings = append(res.Findings, model.Finding{
			Code:   "gomod.unexpected-files",
			Route:  model.RouteHuman,
			Detail: "the PR changes files other than go.mod/go.sum (vendor/ is not verified by the gate): " + ecoutil.List(safeList(other, safeFile), 20),
		})
	}

	var changes []change
	var summary bytes.Buffer
	for _, dir := range slices.Sorted(maps.Keys(dirs)) {
		cs, fs, err := moduleChanges(ctx, git, base, env.Class.HeadSHA, dir, &summary)
		if err != nil {
			return fetch.Result{}, err
		}
		changes = append(changes, cs...)
		res.Findings = append(res.Findings, fs...)
	}
	for _, c := range changes {
		res.Updates = append(res.Updates, safeUpdate(c.update))
	}

	// Direct first, then go.mod indirect, then go.sum-only.
	sort.SliceStable(changes, func(i, j int) bool { return rank(changes[i]) < rank(changes[j]) })
	work := changes
	if len(work) > MaxModules {
		var names []string
		for _, c := range work[MaxModules:] {
			names = append(names, safeImport(c.update.Name)+"@"+safeVersion(c.update.To))
		}
		res.Findings = append(res.Findings, model.Finding{
			Code:   "gomod.not-verified",
			Route:  model.RouteHuman,
			Detail: fmt.Sprintf("more than %d changed modules; not downloaded or diffed: %s", MaxModules, ecoutil.List(names, 30)),
		})
		work = work[:MaxModules]
	}
	if len(work) > 0 {
		fs, flagged, err := f.verifyAndDiff(ctx, env, home, work, &summary)
		if err != nil {
			return fetch.Result{}, err
		}
		res.Findings = append(res.Findings, fs...)
		res.Flagged = flagged
	}
	if err := env.Evidence.Add("gomod-summary.md", "Go module change set, hash verification and checks run by the gate", summary.Bytes()); err != nil {
		return fetch.Result{}, err
	}
	return res, nil
}

func rank(c change) int {
	switch {
	case c.update.Direct:
		return 0
	case !c.sumsOnly:
		return 1
	}
	return 2
}

// moduleChanges compares one module directory's go.mod and go.sum.
func moduleChanges(ctx context.Context, git ecoutil.Git, base, head, dir string, summary *bytes.Buffer) ([]change, []model.Finding, error) {
	read := func(sha, name string) ([]byte, error) {
		b, err := git.Show(ctx, sha, path.Join(dir, name))
		if errors.Is(err, ecoutil.ErrNotExist) {
			return nil, nil
		}
		return b, err
	}
	depDir := path.Clean("/" + dir)
	safeDepDir := safeDir(depDir)
	var findings []model.Finding
	human := func(code, detail string) {
		findings = append(findings, model.Finding{Code: code, Route: model.RouteHuman, Detail: safeDepDir + ": " + detail})
	}

	bm, err := read(base, "go.mod")
	if err != nil {
		return nil, nil, err
	}
	hm, err := read(head, "go.mod")
	if err != nil {
		return nil, nil, err
	}
	bs, err := read(base, "go.sum")
	if err != nil {
		return nil, nil, err
	}
	hs, err := read(head, "go.sum")
	if err != nil {
		return nil, nil, err
	}
	if bm == nil || hm == nil {
		human("gomod.module-added-or-removed", "go.mod is added or removed by the PR")
		return nil, findings, nil
	}
	bmf, err := ParseModFile(bm)
	if errors.Is(err, ErrDuplicate) {
		findings = append(findings, model.Finding{Code: "gomod.duplicate-module", Route: model.RouteRefuse,
			Detail: safeDepDir + ": base go.mod names one module twice in require, replace or exclude (which one wins is up to the reader)"})
		return nil, findings, nil
	}
	if err != nil {
		human("gomod.parse", "base go.mod could not be parsed")
		return nil, findings, nil
	}
	hmf, err := ParseModFile(hm)
	if errors.Is(err, ErrDuplicate) {
		findings = append(findings, model.Finding{Code: "gomod.duplicate-module", Route: model.RouteRefuse,
			Detail: safeDepDir + ": head go.mod names one module twice in require, replace or exclude (which one wins is up to the reader)"})
		return nil, findings, nil
	}
	if err != nil {
		human("gomod.parse", "head go.mod could not be parsed")
		return nil, findings, nil
	}
	bsf, err := ParseSumFile(bs)
	if err != nil {
		human("gomod.parse", "base go.sum could not be parsed")
		return nil, findings, nil
	}
	hsf, err := ParseSumFile(hs)
	if err != nil {
		human("gomod.parse", "head go.sum could not be parsed")
		return nil, findings, nil
	}

	fmt.Fprintf(summary, "## Module %s (directory %s)\n\n", safeImport(hmf.Module), safeDepDir)
	if bmf.Module != hmf.Module {
		human("gomod.module-path-changed", fmt.Sprintf("module path changed from %s to %s", safeImport(bmf.Module), safeImport(hmf.Module)))
	}
	if bmf.Toolchain != hmf.Toolchain {
		human("gomod.toolchain-changed", fmt.Sprintf("toolchain directive changed from %q to %q", orEmpty(bmf.Toolchain, safeVersion), orEmpty(hmf.Toolchain, safeVersion)))
	}
	if bmf.Go != hmf.Go {
		fmt.Fprintf(summary, "- go directive: %s -> %s (language version for this repository's code)\n", orEmpty(bmf.Go, safeVersion), orEmpty(hmf.Go, safeVersion))
	}
	if !slices.Equal(bmf.Directives, hmf.Directives) {
		var added, removed []string
		for _, d := range hmf.Directives {
			if !slices.Contains(bmf.Directives, d) {
				added = append(added, d)
			}
		}
		for _, d := range bmf.Directives {
			if !slices.Contains(hmf.Directives, d) {
				removed = append(removed, d)
			}
		}
		human("gomod.directive-changed", fmt.Sprintf("replace/exclude/godebug/tool/ignore directives changed; added %q, removed %q", safeList(added, safeDirective), safeList(removed, safeDirective)))
	}

	// A hash is a property of a version: it can only change if someone
	// rewrote go.sum (or the module's history). The rest of this function
	// skips versions present on both sides, so check them here, for the
	// module zip and the /go.mod lines alike.
	for _, key := range slices.Sorted(maps.Keys(bsf)) {
		if h, ok := hsf[key]; ok && h != bsf[key] {
			mod, _, _ := strings.Cut(key, " ")
			findings = append(findings, model.Finding{
				Code: "gomod.sum-changed", Route: model.RouteRefuse, Update: safeImport(mod),
				Detail: fmt.Sprintf("%s: go.sum hash for %s changed from %s to %s; a version's hash never changes", safeDepDir, safeSumKey(key), safeHash(bsf[key]), safeHash(h)),
			})
		}
	}

	var changes []change
	mk := func(name, from, to string, direct, sumsOnly bool) change {
		return change{
			update: model.Update{
				Ecosystem: model.GoModules, Directory: depDir, Name: name, From: from, To: to,
				Type: ecoutil.TypeOf(from, to), Direct: direct,
			},
			dir: dir, baseSum: bsf, headSum: hsf, sumsOnly: sumsOnly,
		}
	}
	for _, name := range slices.Sorted(maps.Keys(ecoutil.Union(bmf.Require, hmf.Require))) {
		b, inBase := bmf.Require[name]
		h, inHead := hmf.Require[name]
		switch {
		case inBase && inHead && b.Version == h.Version:
			if b.Indirect != h.Indirect {
				fmt.Fprintf(summary, "- %s %s: indirect %v -> %v\n", safeImport(name), safeVersion(h.Version), b.Indirect, h.Indirect)
			}
		case inHead:
			from := ""
			if inBase {
				from = b.Version
			}
			changes = append(changes, mk(name, from, h.Version, !h.Indirect, false))
		default:
			fmt.Fprintf(summary, "- %s %s: no longer required\n", safeImport(name), safeVersion(b.Version))
			findings = append(findings, model.Finding{
				Code: "gomod.removed", Route: model.RouteReview, Update: safeImport(name),
				Detail: fmt.Sprintf("%s: %s %s is no longer required", safeDepDir, safeImport(name), safeVersion(b.Version)),
			})
		}
	}
	// A new /vN path is a major version: different module, same project.
	for _, c := range changes {
		if c.update.From != "" {
			continue
		}
		if prefix, ok := majorPrefix(c.update.Name); ok {
			for old := range bmf.Require {
				if p, ok := majorPrefix(old); (ok && p == prefix && old != c.update.Name) || old == prefix {
					findings = append(findings, model.Finding{
						Code: "gomod.major-path", Route: model.RouteHuman, Update: safeImport(c.update.Name),
						Detail: fmt.Sprintf("%s: %s is a new major version of %s", safeDepDir, safeImport(c.update.Name), safeImport(old)),
					})
				}
			}
		}
	}
	// Modules hashed in go.sum but not required in go.mod: part of the
	// module graph (tests of dependencies, older Go), still reviewed.
	bz, hz := bsf.ZipVersions(), hsf.ZipVersions()
	for _, name := range slices.Sorted(maps.Keys(ecoutil.Union(bz, hz))) {
		if _, ok := hmf.Require[name]; ok {
			continue
		}
		if _, ok := bmf.Require[name]; ok {
			continue
		}
		removed, added := ecoutil.DiffSets(bz[name], hz[name])
		pairs, _ := ecoutil.Pair(removed, added, ecoutil.Intersect(bz[name], hz[name]))
		for _, p := range pairs {
			changes = append(changes, mk(name, p[0], p[1], false, true))
		}
	}
	for _, c := range changes {
		u := safeUpdate(c.update)
		kind := "indirect"
		if u.Direct {
			kind = "direct"
		} else if c.sumsOnly {
			kind = "go.sum only"
		}
		fmt.Fprintf(summary, "- %s: %s -> %s (%s, %s)\n", u.Name, ecoutil.OrNew(u.From), u.To, u.Type, kind)
	}
	summary.WriteString("\n")
	return changes, findings, nil
}

var majorRE = regexp.MustCompile(`^(.*)/v([2-9]|[1-9][0-9]+)$`)

// majorPrefix returns the path without its /vN suffix ("gopkg.in/x.vN" is
// left alone: it does not occur in this gate's repositories).
func majorPrefix(mod string) (string, bool) {
	m := majorRE.FindStringSubmatch(mod)
	if m == nil {
		return mod, false
	}
	return m[1], true
}

// verifyAndDiff downloads both sides of each change, checks hashes,
// writes diffs, runs the checks and writes, per module with flagged
// items, the focused evidence that lists them.
func (f Fetcher) verifyAndDiff(ctx context.Context, env fetch.Env, home string, work []change, summary *bytes.Buffer) ([]model.Finding, []model.FlaggedItem, error) {
	var findings []model.Finding
	var flagged []model.FlaggedItem
	checked := map[string]bool{}          // flaggedUpdate keys already checked
	clock := ecoutil.NewClock(renderTime) // one for every module of this fetch
	dl := Downloader{Scratch: filepath.Join(env.Scratch, "gomod"), GoBin: f.GoBin}
	var args []string
	for _, c := range work {
		if c.update.From != "" {
			args = append(args, c.update.Name+"@"+c.update.From)
		}
		args = append(args, c.update.Name+"@"+c.update.To)
	}
	got, err := dl.Download(ctx, slices.Compact(slices.Sorted(slices.Values(args))))
	if err != nil {
		return nil, nil, err
	}
	summary.WriteString("## Downloads (proxy.golang.org, checked against sum.golang.org)\n\n")
	for _, c := range work {
		u := c.update
		bad := false
		var trees [2]*ecoutil.Tree
		var dirs [2]string
		for i, side := range []struct {
			ver string
			sum SumFile
			at  string
		}{{u.From, c.baseSum, "base"}, {u.To, c.headSum, "head"}} {
			if side.ver == "" {
				continue
			}
			m, ok := got[u.Name+"@"+side.ver]
			if !ok {
				return nil, nil, fmt.Errorf("go mod download returned nothing for %s@%s", u.Name, side.ver)
			}
			if m.Error != "" {
				switch errorClass(m.Error) {
				case "refuse":
					findings = append(findings, model.Finding{Code: "gomod.checksum", Route: model.RouteRefuse, Update: safeImport(u.Name),
						Detail: fmt.Sprintf("%s@%s failed checksum verification (go mod download reported a checksum error)", safeImport(u.Name), safeVersion(side.ver))})
				case "human":
					findings = append(findings, model.Finding{Code: "gomod.download-failed", Route: model.RouteHuman, Update: safeImport(u.Name),
						Detail: fmt.Sprintf("%s@%s could not be fetched from proxy.golang.org (not found or gone)", safeImport(u.Name), safeVersion(side.ver))})
				default:
					return nil, nil, fmt.Errorf("go mod download %s@%s: %s", u.Name, side.ver, m.Error)
				}
				bad = true
				continue
			}
			want, wantMod := side.sum[u.Name+" "+side.ver], side.sum[u.Name+" "+side.ver+"/go.mod"]
			switch {
			case want == "":
				findings = append(findings, model.Finding{Code: "gomod.sum-missing", Route: model.RouteHuman, Update: safeImport(u.Name),
					Detail: fmt.Sprintf("%s go.sum has no module hash for %s@%s", side.at, safeImport(u.Name), safeVersion(side.ver))})
				bad = true
			case want != m.Sum || (wantMod != "" && wantMod != m.GoModSum):
				findings = append(findings, model.Finding{Code: "gomod.sum-mismatch", Route: model.RouteRefuse, Update: safeImport(u.Name),
					Detail: fmt.Sprintf("%s go.sum hash for %s@%s (%s) differs from the checksum database (%s)", side.at, safeImport(u.Name), safeVersion(side.ver), safeHash(want), safeHash(m.Sum))})
				bad = true
			default:
				fmt.Fprintf(summary, "- %s@%s: %s matches %s go.sum and sum.golang.org\n", safeImport(u.Name), safeVersion(side.ver), safeHash(m.Sum), side.at)
			}
			t, err := ecoutil.DirTree(m.Dir)
			if err != nil {
				return nil, nil, err
			}
			trees[i], dirs[i] = t, m.Dir
		}
		if bad || trees[1] == nil {
			continue
		}
		su := safeUpdate(u)
		key := flaggedUpdate(su)
		if err := writeDiff(ctx, env, home, u, dirs); err != nil {
			return nil, nil, err
		}
		// The same module change in several directories (a grouped bump)
		// is the same two trees: checked, flagged and rendered once.
		if checked[key] {
			fmt.Fprintf(summary, "- %s: same change as in another directory; its flagged items are listed once\n", key)
		} else {
			checked[key] = true
			h := checkTrees(trees[0], trees[1], clock)
			findings = append(findings, h.findings(su.Name)...)
			flagged = append(flagged, h.flagged(key)...)
			if len(h.hits) > 0 {
				desc := fmt.Sprintf("every item the gate's checks flagged in %s, with exactly what changed (third-party code quoted under the gate's headings); assess each one", key)
				if err := env.Evidence.AddUntrusted(evName(u, "flagged.md"), desc, h.render(key)); err != nil {
					return nil, nil, err
				}
			}
		}
		if ex := changelogExcerpt(trees[0], trees[1]); ex != nil {
			if err := env.Evidence.AddUntrusted(evName(u, "changelog.md"), "changelog excerpt for "+safeImport(u.Name)+" "+safeVersion(u.To)+" (from the module, third-party text)", ex); err != nil {
				return nil, nil, err
			}
		}
	}
	summary.WriteString("\n")
	return findings, flagged, nil
}

// flaggedUpdate is the update a flagged item belongs to, as the verdict
// must name it: the module path and both versions, so the same module
// changing differently in two directories gives two distinct keys. Its
// parts are sanitized (at most maxDetailValue bytes each).
func flaggedUpdate(su model.Update) string {
	return su.Name + " " + ecoutil.OrNew(su.From) + " -> " + su.To
}

func writeDiff(ctx context.Context, env fetch.Env, home string, u model.Update, dirs [2]string) error {
	parent := filepath.Dir(dirs[1])
	rel := func(d string) string {
		if d == "" {
			return ""
		}
		if filepath.Dir(d) != parent {
			return "" // cannot happen for one module path; diff against empty
		}
		return filepath.Base(d)
	}
	diffs, cut, err := ecoutil.DiffTrees(ctx, home, parent, rel(dirs[0]), rel(dirs[1]))
	if err != nil {
		return err
	}
	// Nothing is left out: vendor/ and testdata/ can hold compiled code.
	text, _ := ecoutil.JoinDiffs(diffs, nil)
	if cut {
		text = append(text, "\n[dep-review: diff exceeded the gate's read limit]\n"...)
	}
	if len(text) == 0 {
		text = []byte("(the module trees are identical)\n")
	}
	su := safeUpdate(u)
	desc := fmt.Sprintf("diff of module %s %s -> %s (third-party code)", su.Name, ecoutil.OrNew(su.From), su.To)
	return env.Evidence.AddUntrusted(evName(u, "diff"), desc, text)
}

func evName(u model.Update, suffix string) string {
	u = safeUpdate(u)
	return "gomod" + u.Directory + "/" + u.Name + "@" + ecoutil.OrNew(u.From) + "..." + u.To + "." + suffix
}

var changelogRE = regexp.MustCompile(`(?i)^(changelog|changes|history|news|release[-_ ]?notes)(\.(md|txt|rst|markdown))?$`)

// changelogExcerpt returns what the new changelog at the module root adds
// at its top relative to the old one (changelogs are prepended), capped.
func changelogExcerpt(old, cur *ecoutil.Tree) []byte {
	const limit = 32 << 10
	for _, f := range cur.Files {
		if strings.Contains(f, "/") || !changelogRE.MatchString(f) {
			continue
		}
		n := cur.ReadFile(f)
		o := old.ReadFile(f)
		ex := n
		if len(o) > 0 {
			head := o[:min(len(o), 256)]
			if i := bytes.Index(n, head); i >= 0 {
				ex = n[:i]
			}
		}
		if len(bytes.TrimSpace(ex)) == 0 {
			continue
		}
		return ex[:min(len(ex), limit)]
	}
	return nil
}

// orEmpty applies f unless v is empty (an absent directive).
func orEmpty(v string, f func(string) string) string {
	if v == "" {
		return ""
	}
	return f(v)
}
