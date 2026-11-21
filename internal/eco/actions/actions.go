// Package actions is the github_actions ecosystem fetcher.
//
// For every `uses: owner/repo[/path]@<sha> # vX.Y.Z` line a Dependabot PR
// rewrites in .github/workflows/*.yml|yaml or an action.yml, it verifies
// the new pin against upstream (default/release branch, fast-forward from
// the old pin, a vX.Y.Z tag, a published non-draft non-prerelease release,
// advisories, provenance) and prepares evidence: the first-party source
// diff, the action.yml diff, the npm lockfile changes, and an attribution
// of every changed dist/ byte to a changed first-party file or a changed
// locked package, with what is left over listed as residual.
//
// A step of a workflow onboarded to .github/workflows/actions.lock names
// an exact tag instead (`uses: owner/repo@vX.Y.Z`), and the commit comes
// from the lockfile; the same checks then run on the locked commits, which
// must be the named tag's, in the repository with the locked IDs. The
// lockfile change must be exactly the bumped entries (see lockDelta in
// actionslock.go).
//
// Upstream code is only read: a blobless, checkout-less clone queried with
// git cat-file/diff, plus public REST endpoints. Nothing from the caller
// repository or upstream is executed, and dist/ is not rebuilt (see
// CodeRebuildNotRun).
package actions

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/sadbox/dep-review/internal/fetch"
	"github.com/sadbox/dep-review/internal/gh"
	"github.com/sadbox/dep-review/internal/model"
	"github.com/sadbox/dep-review/internal/strictjson"
)

// CodeRebuildNotRun is the finding left on every update whose dist/
// changed: the bundle was attributed from upstream-committed source maps
// and module markers, not rebuilt from source and byte-compared. A
// separately contained rebuild job is meant to replace it with its own
// result.
const CodeRebuildNotRun = "actions.rebuild-not-run"

// Config tunes the fetcher. The zero value uses the defaults.
type Config struct {
	// Git is the git binary (default "git").
	Git string
	// CloneBase is prefixed to "owner/repo" to clone an upstream
	// (default "https://github.com/").
	CloneBase string
	// MaxCommits routes to a human above this many upstream commits
	// between the old and new pin (default 50).
	MaxCommits int
	// MaxResidual routes to a human when any changed bundle has more than
	// this fraction of its bytes unexplained (default 0.005).
	MaxResidual float64
	// MaxTagDerefs caps REST calls spent dereferencing annotated tags per
	// commit (default 25).
	MaxTagDerefs int
}

type fetcher struct{ cfg Config }

// New returns the github_actions fetcher.
func New(cfg Config) fetch.Ecosystem {
	if cfg.Git == "" {
		cfg.Git = "git"
	}
	if cfg.CloneBase == "" {
		cfg.CloneBase = "https://github.com/"
	}
	if cfg.MaxCommits == 0 {
		cfg.MaxCommits = 50
	}
	if cfg.MaxResidual == 0 {
		cfg.MaxResidual = 0.005
	}
	if cfg.MaxTagDerefs == 0 {
		cfg.MaxTagDerefs = 25
	}
	return &fetcher{cfg}
}

// pair is one action repository moving from one pinned commit to another,
// possibly referenced from several lines, files and subpaths.
type pair struct {
	owner, repo string
	oldRef      string
	newRef      string
	subs        []string // action subpaths used ("" = repository root)
	changes     []usesChange
	directory   string
	// lock: some lines are steps of workflows onboarded to actions.lock,
	// so oldRef/newRef are the lockfile's commits, the lines name these
	// tags, and lockEntries are the new lockfile entries.
	lock                     bool
	lockOldTags, lockNewTags []string
	lockEntries              []*lockEntry
}

func (p *pair) name() string { return p.owner + "/" + p.repo }

type findings struct {
	list []model.Finding
}

func (f *findings) add(route model.Route, code, update, format string, args ...any) {
	f.list = append(f.list, model.Finding{Code: code, Route: route, Detail: fmt.Sprintf(format, args...), Update: update})
}

func (f *findings) worst(update string) model.Route {
	r := model.RouteAuto
	for _, x := range f.list {
		if x.Update == update {
			r = model.Worse(r, x.Route)
		}
	}
	return r
}

func (f *fetcher) Fetch(ctx context.Context, env fetch.Env) (fetch.Result, error) {
	if env.Evidence == nil || env.GitHub == nil {
		return fetch.Result{}, errors.New("actions: Evidence and GitHub are required")
	}
	caller := git{bin: f.cfg.Git, dir: env.RepoDir}
	base, head := env.Class.BaseSHA, env.Class.HeadSHA
	if !shaRx.MatchString(base) || !shaRx.MatchString(head) {
		return fetch.Result{}, fmt.Errorf("actions: base/head must be commit SHAs")
	}
	files, err := caller.changedFiles(ctx, base, head)
	if err != nil {
		return fetch.Result{}, fmt.Errorf("actions: listing changed files: %w", err)
	}
	var fs findings
	var all []usesChange
	lockChanged := false
	for _, fc := range files {
		kind := fileKind(fc.path)
		if kind == "" {
			fs.add(model.RouteRefuse, "actions.unexpected-file", "", "the PR changes a file that is not a workflow, action.yml or actions.lock: %s", safePath(fc.path))
			continue
		}
		if fc.status != 'M' || fc.oldMode != fc.newMode {
			fs.add(model.RouteRefuse, "actions.unexpected-file", "", "the PR adds, deletes or changes the mode of %s", safePath(fc.path))
			continue
		}
		if kind == kindLock {
			lockChanged = true
			continue
		}
		oldText, err := caller.show(ctx, base, fc.path)
		if err != nil {
			return fetch.Result{}, fmt.Errorf("actions: reading %s at base: %w", fc.path, err)
		}
		newText, err := caller.show(ctx, head, fc.path)
		if err != nil {
			return fetch.Result{}, fmt.Errorf("actions: reading %s at head: %w", fc.path, err)
		}
		ch, errs := usesChanges(fc.path, kind, string(oldText), string(newText))
		for _, e := range errs {
			code := e.code
			if code == "" {
				code = "actions.non-uses-change"
			}
			fs.add(model.RouteRefuse, code, "", "%s: %s", safePath(e.file), e.reason)
		}
		all = append(all, ch...)
	}
	if len(all) == 0 && len(fs.list) == 0 {
		fs.add(model.RouteRefuse, "actions.no-uses-change", "", "the PR changes no uses: line")
	}

	var summary strings.Builder
	summary.WriteString("# github_actions updates\n\n")
	if err := checkActionsLock(ctx, caller, env, base, head, lockChanged, all, &fs, &summary); err != nil {
		return fetch.Result{}, err
	}

	pairs, order := groupPairs(all, &fs)
	var updates []model.Update
	for _, key := range order {
		p := pairs[key]
		u, err := f.analyzePair(ctx, env, p, &fs, &summary)
		if err != nil {
			return fetch.Result{}, fmt.Errorf("actions: %s: %w", p.name(), err)
		}
		updates = append(updates, u)
	}
	if err := env.Evidence.Add("actions/summary.md", "github_actions fetcher summary: pins, versions, upstream checks, provenance and bundle attribution numbers", []byte(summary.String())); err != nil {
		return fetch.Result{}, err
	}
	return fetch.Result{Updates: updates, Findings: fs.list}, nil
}

// groupPairs validates each rewritten line and groups them by action
// repository and old/new ref.
func groupPairs(all []usesChange, fs *findings) (map[string]*pair, []string) {
	pairs := map[string]*pair{}
	var order []string
	for _, c := range all {
		owner, repo, sub, err := splitAction(c.new.action)
		if err != nil {
			fs.add(model.RouteRefuse, "actions.invalid-action", "", "%s:%d: %s", safePath(c.file), c.line, err)
			continue
		}
		if c.old.ref == c.new.ref {
			fs.add(model.RouteRefuse, "actions.non-uses-change", "", "%s:%d: only the comment changed; the pin is the same", safePath(c.file), c.line)
			continue
		}
		oldRef, newRef := c.old.ref, c.new.ref
		if c.lock != nil {
			// The commits the runner runs are the lockfile's.
			oldRef, newRef = c.lock.oldCommit, c.lock.newCommit
		}
		key := fetch.NormalizeName(model.GitHubActions, owner+"/"+repo) + "@" + oldRef + ".." + newRef
		p := pairs[key]
		if p == nil {
			dir := "/"
			if c.kind == kindAction {
				dir = path.Clean("/" + path.Dir(c.file))
			}
			p = &pair{owner: owner, repo: repo, oldRef: oldRef, newRef: newRef, directory: dir}
			pairs[key] = p
			order = append(order, key)
		}
		if !contains(p.subs, sub) {
			p.subs = append(p.subs, sub)
		}
		if c.lock != nil {
			p.lock = true
			if _, ok := parseTag(c.new.ref); ok && !contains(p.lockNewTags, c.new.ref) {
				p.lockNewTags = append(p.lockNewTags, c.new.ref)
			}
			if _, ok := parseTag(c.old.ref); ok && !contains(p.lockOldTags, c.old.ref) {
				p.lockOldTags = append(p.lockOldTags, c.old.ref)
			}
			if c.lock.newEntry != nil {
				p.lockEntries = append(p.lockEntries, c.lock.newEntry)
			}
		}
		p.changes = append(p.changes, c)
	}
	return pairs, order
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

var safePathRx = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,200}$`)

// safePath returns p if it is a plain path, for text the gate writes as
// trusted (findings, summary); anything else is elided.
func safePath(p string) string {
	if safePathRx.MatchString(p) {
		return p
	}
	return "(path with unusual characters)"
}

var loginRx = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})(\[bot\])?$`)

func safeLogin(s string) string {
	if loginRx.MatchString(s) {
		return s
	}
	return "(invalid login)"
}

func short(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}

func declaredHints(class model.Classification, name string) (from, to []string) {
	for _, d := range class.Declared {
		if fetch.SameName(model.GitHubActions, d.Name, name) {
			if d.From != "" {
				from = append(from, "v"+strings.TrimPrefix(d.From, "v"))
			}
			if d.To != "" {
				to = append(to, "v"+strings.TrimPrefix(d.To, "v"))
			}
		}
	}
	return from, to
}

func commentHints(changes []usesChange, old bool) []string {
	var hs []string
	for _, c := range changes {
		cm := c.new.comment
		if old {
			cm = c.old.comment
		}
		if _, ok := parseTag(strings.TrimSpace(cm)); ok {
			hs = append(hs, strings.TrimSpace(cm))
		}
	}
	return hs
}

// pickTag chooses among several vX.Y.Z tags on one commit: the one a
// version comment names, else the highest.
func pickTag(hits []tagRef, hints []string) tagRef {
	for _, h := range hints {
		for _, t := range hits {
			if t.name == h {
				return t
			}
		}
	}
	best := hits[0]
	for _, t := range hits[1:] {
		if t.v.cmp(best.v) > 0 {
			best = t
		}
	}
	return best
}

func (f *fetcher) analyzePair(ctx context.Context, env fetch.Env, p *pair, fs *findings, sum *strings.Builder) (model.Update, error) {
	name := p.name()
	u := model.Update{
		Ecosystem: model.GitHubActions,
		Directory: p.directory,
		Name:      name,
		FromRef:   p.oldRef,
		ToRef:     p.newRef,
		Type:      model.Unknown,
		Direct:    true,
	}
	for _, d := range env.Class.Declared {
		if fetch.SameName(model.GitHubActions, d.Name, name) {
			u.Security = u.Security || d.Security
			u.Advisory = append(u.Advisory, d.Advisory...)
		}
	}
	fmt.Fprintf(sum, "## %s %s -> %s\n\n", name, short(p.oldRef), short(p.newRef))
	for _, c := range p.changes {
		fmt.Fprintf(sum, "- %s:%d\n", safePath(c.file), c.line)
	}
	sum.WriteString("\n")
	switch {
	case p.lock:
		if !shaRx.MatchString(p.newRef) || !shaRx.MatchString(p.oldRef) {
			// checkActionsLock refused already: an entry is missing.
			fs.add(model.RouteRefuse, "actions.lock-uses-mismatch", name, "actions.lock has no commit for the old or the new tag")
		}
	default:
		if !shaRx.MatchString(p.newRef) {
			fs.add(model.RouteRefuse, "actions.ref-not-sha", name, "the new ref is not a full 40-hex commit SHA, and actions.lock does not lock this line")
		}
		if !shaRx.MatchString(p.oldRef) {
			fs.add(model.RouteRefuse, "actions.old-ref-not-sha", name, "the old ref is not a full 40-hex commit SHA, and actions.lock does not lock this line")
		}
	}
	if fs.worst(name) == model.RouteRefuse {
		u.From, u.To = strings.TrimPrefix(p.oldRef, "v"), strings.TrimPrefix(p.newRef, "v")
		sum.WriteString("refused before upstream checks (ref is not a SHA)\n\n")
		return u, nil
	}

	up := &upstream{gh: env.GitHub, owner: p.owner, repo: p.repo, tagDeref: map[string]string{}}
	var info repoInfo
	if err := up.get(ctx, "", &info); err != nil {
		if errors.Is(err, gh.ErrNotFound) {
			fs.add(model.RouteRefuse, "actions.repo-not-found", name, "upstream repository not found")
			return u, nil
		}
		return u, err
	}
	if !safePathRx.MatchString(info.DefaultBranch) {
		return u, fmt.Errorf("unexpected default branch name")
	}
	for _, e := range p.lockEntries {
		// The runner checks these IDs; the gate checks them against the
		// repository it is about to verify.
		if e.ownerID != info.Owner.ID || e.repoID != info.ID {
			fs.add(model.RouteRefuse, "actions.lock-identity-mismatch", name, "actions.lock records owner/repo IDs %d/%d, upstream is %d/%d", e.ownerID, e.repoID, info.Owner.ID, info.ID)
		}
	}

	// Ancestry: the new pin must be on the default branch (or a release
	// branch), and a fast-forward from the old pin.
	branch, err := up.onReleaseBranch(ctx, info.DefaultBranch, p.newRef)
	if err != nil {
		return u, err
	}
	switch branch {
	case "":
		fs.add(model.RouteRefuse, "actions.not-on-default-branch", name, "the new SHA is not an ancestor of %s or of a release branch (a fork or unmerged commit?)", info.DefaultBranch)
	case info.DefaultBranch:
	default:
		// A release-named branch, a vX.Y.Z tag and a published release all
		// prove only push access to upstream, not that the commit went
		// through whatever review the default branch gets.
		fs.add(model.RouteHuman, "actions.release-branch-only", name, "the new SHA is reachable from release branch %s but not from the default branch %s", safePath(branch), info.DefaultBranch)
	}
	cmp, err := up.compare(ctx, p.oldRef, p.newRef, 100)
	if err != nil && !errors.Is(err, gh.ErrNotFound) {
		return u, err
	}
	commits := 0
	if cmp == nil || cmp.Status != "ahead" {
		st := "unknown"
		if cmp != nil {
			st = cmp.Status
		}
		fs.add(model.RouteRefuse, "actions.not-fast-forward", name, "the old SHA is not an ancestor of the new one (compare status %q)", safeWord(st))
	} else {
		commits = cmp.TotalCommits
		if commits > f.cfg.MaxCommits {
			fs.add(model.RouteHuman, "actions.too-many-commits", name, "%d upstream commits between the pins (limit %d)", commits, f.cfg.MaxCommits)
		}
	}
	fmt.Fprintf(sum, "- upstream default branch: %s; new SHA reachable from: %s\n- upstream commits old..new: %d\n", info.DefaultBranch, orNone(branch), commits)

	// Versions from tags.
	tags, err := up.semverTags(ctx)
	if err != nil {
		return u, err
	}
	dFrom, dTo := declaredHints(env.Class, name)
	// A locked line names its tag; it outranks a version comment.
	oldHints := append(append([]string(nil), p.lockOldTags...), commentHints(p.changes, true)...)
	newHints := append(append([]string(nil), p.lockNewTags...), commentHints(p.changes, false)...)
	oldHits, _, err := up.tagsAt(ctx, tags, p.oldRef, append(oldHints, dFrom...), nil, f.cfg.MaxTagDerefs)
	if err != nil {
		return u, err
	}
	var oldTag *tagRef
	if len(oldHits) > 0 {
		t := pickTag(oldHits, oldHints)
		oldTag = &t
	}
	accept := func(v semver) bool { return oldTag == nil || v.cmp(oldTag.v) > 0 }
	newHits, derefs, err := up.tagsAt(ctx, tags, p.newRef, append(newHints, dTo...), accept, f.cfg.MaxTagDerefs)
	if err != nil {
		return u, err
	}
	var newTag *tagRef
	if len(newHits) == 0 {
		fs.add(model.RouteRefuse, "actions.no-version-tag", name, "no vX.Y.Z tag dereferences to the new SHA (%d annotated tags dereferenced)", derefs)
	} else {
		t := pickTag(newHits, newHints)
		newTag = &t
		u.To = t.v.String()
	}
	// The tag a locked line names must be upstream's tag on the locked
	// commit, not merely some tag there.
	for _, tn := range p.lockNewTags {
		ok, err := up.tagIs(ctx, tags, tn, p.newRef)
		if err != nil {
			return u, err
		}
		if !ok {
			fs.add(model.RouteRefuse, "actions.lock-tag-mismatch", name, "upstream tag %s does not dereference to the commit actions.lock records for it (%s)", tn, short(p.newRef))
		} else if newTag != nil && newTag.name != tn {
			fs.add(model.RouteRefuse, "actions.lock-tag-mismatch", name, "the workflow names %s, but the version the gate read for the locked commit is %s", tn, newTag.name)
		}
	}
	if oldTag == nil {
		fs.add(model.RouteHuman, "actions.old-version-unknown", name, "no vX.Y.Z tag dereferences to the old SHA; the update size is unknown")
	} else {
		u.From = oldTag.v.String()
	}
	if oldTag != nil && newTag != nil {
		if newTag.v.cmp(oldTag.v) <= 0 {
			fs.add(model.RouteHuman, "actions.version-downgrade", name, "new version %s is not newer than %s", newTag.v, oldTag.v)
		} else {
			u.Type = updateType(oldTag.v, newTag.v)
		}
	}
	fmt.Fprintf(sum, "- version: %s -> %s (%s)\n", orNone(tagName(oldTag)), orNone(tagName(newTag)), u.Type)

	// Version comments.
	if newTag != nil {
		for _, c := range p.changes {
			parts, ok := versionComment(c.new.comment)
			if !ok {
				switch {
				case c.new.comment != c.old.comment:
					// Dependabot writes a version here or leaves the comment
					// alone; anything else (including deleting it) is not its
					// edit, and unparsed text is where structure can hide.
					fs.add(model.RouteRefuse, "actions.version-comment-unparsed", name, "%s:%d: the comment after the pin changed and is not a version", safePath(c.file), c.line)
				case c.new.comment != "":
					fs.add(model.RouteReview, "actions.version-comment-unparsed", name, "%s:%d: the comment after the pin is not a version (unchanged by the PR)", safePath(c.file), c.line)
				}
				continue
			}
			if commentMatches(parts, newTag.v) {
				continue
			}
			if c.new.comment == c.old.comment {
				fs.add(model.RouteReview, "actions.version-comment-stale", name, "%s:%d: the version comment was left unchanged and does not match %s", safePath(c.file), c.line, newTag.name)
			} else {
				fs.add(model.RouteRefuse, "actions.version-comment-mismatch", name, "%s:%d: the version comment does not match the tag %s on the new SHA", safePath(c.file), c.line, newTag.name)
			}
		}
	}

	// Release, advisories, provenance.
	var newRel, oldRel *release
	if newTag != nil {
		if newRel, err = up.releaseFor(ctx, newTag.name); err != nil {
			return u, err
		}
		switch {
		case newRel == nil:
			fs.add(model.RouteHuman, "actions.release-missing", name, "no published release for %s (draft releases are not visible; the gate cannot tell)", newTag.name)
		case newRel.Draft:
			fs.add(model.RouteRefuse, "actions.release-draft", name, "the release for %s is a draft", newTag.name)
		case newRel.Prerelease:
			fs.add(model.RouteRefuse, "actions.release-prerelease", name, "the release for %s is a prerelease", newTag.name)
		}
		advs, err := advisories(ctx, env.GitHub, name, newTag.v.String())
		if err != nil {
			return u, err
		}
		for _, a := range advs {
			id := a.GHSAID
			if !ghsaRx.MatchString(id) {
				id = "(invalid GHSA id)"
			}
			fs.add(model.RouteRefuse, "actions.advisory", name, "advisory %s affects %s@%s", id, name, newTag.v)
		}
		if len(advs) > 0 {
			var sb strings.Builder
			for _, a := range advs {
				fmt.Fprintf(&sb, "%s (%s): %s\n", a.GHSAID, a.Severity, a.Summary)
				for _, v := range a.Vulnerabilities {
					fmt.Fprintf(&sb, "  %s %s\n", v.Package.Name, v.VulnerableVersionRange)
				}
			}
			if err := env.Evidence.AddUntrusted(evName(p, "advisories.txt"), "GitHub advisories matching the new version of "+name, []byte(sb.String())); err != nil {
				return u, err
			}
		}
	}
	if oldTag != nil {
		if oldRel, err = up.releaseFor(ctx, oldTag.name); err != nil {
			return u, err
		}
	}
	prov, err := provenance(ctx, up, p, oldRel, newRel)
	if err != nil {
		return u, err
	}
	sum.WriteString(prov.render())
	if prov.regressed() {
		fs.add(model.RouteHuman, "actions.provenance-regressed", name, "the old release was immutable with a release attestation; the new one is not")
	}
	if newRel != nil && newRel.Body != "" {
		if err := env.Evidence.AddUntrusted(evName(p, "release-notes.md"), "release notes for "+name+" "+tagName(newTag)+" (written by upstream)", []byte(newRel.Body)); err != nil {
			return u, err
		}
	}
	if cmp != nil && len(cmp.Commits) > 0 {
		var sb strings.Builder
		fmt.Fprintf(&sb, "%d commits (%d listed)\n", cmp.TotalCommits, len(cmp.Commits))
		for _, c := range cmp.Commits {
			login := ""
			if c.Author != nil {
				login = c.Author.Login
			}
			subject, _, _ := strings.Cut(c.Commit.Message, "\n")
			fmt.Fprintf(&sb, "%s %s <%s> %s\n", short(c.SHA), c.Commit.Author.Name, login, subject)
		}
		if err := env.Evidence.AddUntrusted(evName(p, "commits.txt"), "upstream commits between the pins of "+name, []byte(sb.String())); err != nil {
			return u, err
		}
	}

	if fs.worst(name) == model.RouteRefuse {
		sum.WriteString("- refused: upstream code not analyzed\n\n")
		return u, nil
	}
	if err := f.analyzeCode(ctx, env, p, fs, sum); err != nil {
		return u, err
	}
	sum.WriteString("\n")
	return u, nil
}

func tagName(t *tagRef) string {
	if t == nil {
		return ""
	}
	return t.name
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

var wordRx = regexp.MustCompile(`^[a-z_-]{0,20}$`)

func safeWord(s string) string {
	if wordRx.MatchString(s) {
		return s
	}
	return "?"
}

func evName(p *pair, file string) string {
	return fmt.Sprintf("actions/%s__%s/%s-%s/%s", strings.ToLower(p.owner), strings.ToLower(p.repo), short(p.oldRef)[:7], short(p.newRef)[:7], file)
}

type provFacts struct {
	oldImmutable, newImmutable bool
	oldAttest, newAttest       int
	oldRelease, newRelease     bool
	oldVerified, newVerified   commitVerification
	newAuthor                  string
}

func provenance(ctx context.Context, up *upstream, p *pair, oldRel, newRel *release) (*provFacts, error) {
	pf := &provFacts{}
	var err error
	if oldRel != nil {
		pf.oldRelease, pf.oldImmutable = true, oldRel.Immutable
	}
	if newRel != nil {
		pf.newRelease, pf.newImmutable, pf.newAuthor = true, newRel.Immutable, safeLogin(newRel.Author.Login)
	}
	if pf.oldAttest, err = up.releaseAttestations(ctx, p.oldRef); err != nil {
		return nil, err
	}
	if pf.newAttest, err = up.releaseAttestations(ctx, p.newRef); err != nil {
		return nil, err
	}
	if pf.oldVerified, err = up.commitVerification(ctx, p.oldRef); err != nil && !errors.Is(err, gh.ErrNotFound) {
		return nil, err
	}
	if pf.newVerified, err = up.commitVerification(ctx, p.newRef); err != nil && !errors.Is(err, gh.ErrNotFound) {
		return nil, err
	}
	return pf, nil
}

func (pf *provFacts) regressed() bool {
	return pf.oldImmutable && pf.oldAttest > 0 && !(pf.newImmutable && pf.newAttest > 0)
}

func (pf *provFacts) render() string {
	return fmt.Sprintf("- provenance (old -> new): release published %t -> %t; immutable release %t -> %t; release attestations %d -> %d (presence only, signatures not verified here); commit signature verified %t -> %t (%s); new release author %s\n",
		pf.oldRelease, pf.newRelease, pf.oldImmutable, pf.newImmutable, pf.oldAttest, pf.newAttest,
		pf.oldVerified.Verified, pf.newVerified.Verified, safeWord(pf.newVerified.Reason), orNone(pf.newAuthor))
}

// isDistPath reports a path under a dist/ directory.
func isDistPath(p string) bool {
	return strings.HasPrefix(p, "dist/") || strings.Contains(p, "/dist/")
}

func isTextAsset(p string) bool {
	b := strings.ToLower(path.Base(p))
	return strings.HasSuffix(b, ".txt") || strings.HasSuffix(b, ".md") || strings.HasPrefix(b, "license") || strings.HasPrefix(b, "notice")
}

func isJS(p string) bool {
	switch path.Ext(p) {
	case ".js", ".cjs", ".mjs":
		return true
	}
	return false
}

// clone makes (or reuses) a blobless, checkout-less clone of the upstream.
func (f *fetcher) clone(ctx context.Context, env fetch.Env, p *pair) (git, error) {
	dir := filepath.Join(env.Scratch, "actions", strings.ToLower(p.owner)+"__"+strings.ToLower(p.repo))
	g := git{bin: f.cfg.Git, dir: dir}
	if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
		return g, nil
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return g, err
	}
	src := f.cfg.CloneBase + p.owner + "/" + p.repo
	if _, err := (git{bin: f.cfg.Git}).run(ctx, "clone", "--quiet", "--filter=blob:none", "--no-checkout", src, dir); err != nil {
		return g, err
	}
	return g, nil
}

func (f *fetcher) analyzeCode(ctx context.Context, env fetch.Env, p *pair, fs *findings, sum *strings.Builder) error {
	name := p.name()
	up, err := f.clone(ctx, env, p)
	if err != nil {
		return err
	}
	for _, r := range []string{p.oldRef, p.newRef} {
		if !up.hasCommit(ctx, r) {
			fs.add(model.RouteHuman, "actions.sha-not-in-clone", name, "commit %s is not in the upstream clone", short(r))
			return nil
		}
	}
	for _, r := range []string{p.oldRef, p.newRef} {
		hits, err := archiveAttributes(ctx, up, r)
		if err != nil {
			return err
		}
		if len(hits) > 0 {
			fs.add(model.RouteHuman, "actions.archive-attributes", name, "at %s, .gitattributes sets attributes that make the tarball the runner downloads differ from the blobs the gate read: %s", short(r), strings.Join(hits, ", "))
		}
	}
	changed, err := up.changedFiles(ctx, p.oldRef, p.newRef)
	if err != nil {
		return err
	}
	lfs, err := lfsPointers(ctx, up, p.oldRef, p.newRef, changed)
	if err != nil {
		return err
	}
	if len(lfs) > 0 {
		fs.add(model.RouteHuman, "actions.lfs-pointer", name, "%d changed files are Git LFS pointers; the tarball the runner downloads may hold the LFS object, or the pointer, instead of what the gate read: %s", len(lfs), strings.Join(lfs[:min(len(lfs), 10)], ", "))
	}

	// action.yml for every subpath used.
	var entries []string
	var metaText strings.Builder
	for _, sub := range p.subs {
		oldY, oldPath := readActionYML(ctx, up, p.oldRef, sub)
		newY, newPath := readActionYML(ctx, up, p.newRef, sub)
		where := path.Join(sub, "action.yml")
		if newY == nil {
			fs.add(model.RouteHuman, "actions.action-yml-missing", name, "no action.yml/action.yaml at %s in the new commit", safePath(where))
			continue
		}
		if oldY == nil {
			fs.add(model.RouteHuman, "actions.action-yml-missing", name, "no action.yml/action.yaml at %s in the old commit", safePath(where))
			continue
		}
		om, err1 := parseActionMeta(string(oldY))
		nm, err2 := parseActionMeta(string(newY))
		if errors.Is(err1, errLineBreak) || errors.Is(err2, errLineBreak) {
			fs.add(model.RouteRefuse, codeLineBreak, name, "%s: %s", safePath(where), errLineBreak)
		}
		if err1 != nil || err2 != nil {
			fs.add(model.RouteHuman, "actions.action-yml-unparsed", name, "%s could not be read by the gate's YAML subset reader", safePath(where))
			metaText.WriteString(unifiedDiff("a/"+oldPath, "b/"+newPath, string(oldY), string(newY), 3))
			continue
		}
		mf, text := compareActionMeta(sub, om, nm)
		for _, x := range mf {
			fs.add(x.route, x.code, name, "%s", x.detail)
		}
		metaText.WriteString(text)
		if d := unifiedDiff("a/"+oldPath, "b/"+newPath, string(oldY), string(newY), 3); d != "" {
			metaText.WriteString("\nraw diff:\n" + d)
		}
		metaText.WriteString("\n")
		es, err := nm.entrypoints(sub)
		if err != nil {
			fs.add(model.RouteHuman, "actions.entrypoint-invalid", name, "%s: an entrypoint escapes the repository", safePath(where))
		}
		entries = append(entries, es...)
	}
	if metaText.Len() > 0 {
		if err := env.Evidence.AddUntrusted(evName(p, "action-yml.txt"), "structured and raw action.yml diff for "+name, []byte(metaText.String())); err != nil {
			return err
		}
	}

	// Classify upstream changes.
	isEntry := map[string]bool{}
	for _, e := range entries {
		isEntry[e] = true
	}
	var firstParty, bundles, distText, distOther, locks, pkgJSONs []fileChange
	for _, c := range changed {
		switch {
		case isLockfile(c.path):
			locks = append(locks, c)
		case isEntry[c.path] || isDistPath(c.path):
			switch {
			case strings.HasSuffix(c.path, ".map"):
			case isJS(c.path):
				bundles = append(bundles, c)
			case isTextAsset(c.path):
				distText = append(distText, c)
			default:
				distOther = append(distOther, c)
			}
		default:
			firstParty = append(firstParty, c)
			if path.Base(c.path) == "package.json" {
				pkgJSONs = append(pkgJSONs, c)
			}
			if isBuildConfig(c.path) {
				fs.add(model.RouteHuman, "actions.build-config-changed", name, "build configuration changed: %s", safePath(c.path))
			}
		}
	}

	// package.json: scripts and bundlers.
	var pkgNotes strings.Builder
	for _, c := range pkgJSONs {
		od, _ := up.show(ctx, p.oldRef, c.path)
		nd, err := up.show(ctx, p.newRef, c.path)
		if err != nil {
			continue // deleted
		}
		pc, err := comparePackageJSON(od, nd)
		if errors.Is(err, strictjson.ErrRejected) {
			fs.add(model.RouteRefuse, "actions.json-ambiguous", name, "%s: duplicate or case-folded keys (or other JSON a consumer may read differently)", safePath(c.path))
			continue
		}
		if err != nil {
			fs.add(model.RouteHuman, "actions.build-config-changed", name, "%s could not be parsed", safePath(c.path))
			continue
		}
		if len(pc.scripts) > 0 {
			fs.add(model.RouteHuman, "actions.build-config-changed", name, "%s: scripts changed (%d entries)", safePath(c.path), len(pc.scripts))
			fmt.Fprintf(&pkgNotes, "%s: scripts changed: %s\n", c.path, strings.Join(pc.scripts, ", "))
		}
		if len(pc.bundlersChanged) > 0 {
			fs.add(model.RouteHuman, "actions.build-config-changed", name, "%s: bundler/compiler packages added or removed", safePath(c.path))
			fmt.Fprintf(&pkgNotes, "%s: bundler packages added/removed: %s\n", c.path, strings.Join(pc.bundlersChanged, ", "))
		}
		if len(pc.bundlerVersions) > 0 {
			fmt.Fprintf(&pkgNotes, "%s: bundler version ranges changed: %s\n", c.path, strings.Join(pc.bundlerVersions, ", "))
		}
		if pc.packageManager != "" {
			fmt.Fprintf(&pkgNotes, "%s: packageManager %s\n", c.path, pc.packageManager)
		}
		if pc.engines != "" {
			fmt.Fprintf(&pkgNotes, "%s: engines %s\n", c.path, pc.engines)
		}
	}

	// Lockfiles.
	oldLock, newLock := lockSet{}, lockSet{}
	oldPaths, newPaths := map[string]string{}, map[string]string{}
	lockOK := true
	for _, c := range locks {
		for _, side := range []struct {
			rev   string
			set   lockSet
			paths map[string]string
		}{{p.oldRef, oldLock, oldPaths}, {p.newRef, newLock, newPaths}} {
			data, err := up.show(ctx, side.rev, c.path)
			if errors.Is(err, errMissing) {
				continue
			}
			if err != nil {
				return err
			}
			s, err := parseLockfile(c.path, data)
			if errors.Is(err, strictjson.ErrRejected) {
				fs.add(model.RouteRefuse, "actions.json-ambiguous", name, "%s: duplicate or case-folded keys (or other JSON a consumer may read differently)", safePath(c.path))
			}
			if err != nil {
				lockOK = false
				fs.add(model.RouteHuman, "actions.lockfile-unparsed", name, "%s could not be parsed", safePath(c.path))
				break
			}
			for n, vs := range s.names {
				for v := range vs {
					side.set.add(n, v)
				}
			}
			for k, v := range s.paths {
				side.paths[k] = v
			}
		}
	}
	pkgChanges := lockChanges(oldLock, newLock)
	lockChanged := map[string]bool{}
	var added, downgraded, bundlerLocked int
	var npmText strings.Builder
	for _, c := range pkgChanges {
		lockChanged[c.name] = true
		flag := ""
		switch {
		case c.added:
			flag = " NEW"
			added++
		case c.removed:
			flag = " REMOVED"
		case c.downgrade:
			flag = " DOWNGRADE"
			downgraded++
		}
		if isBundlerPackage(c.name) {
			flag += " BUNDLER"
			bundlerLocked++
		}
		fmt.Fprintf(&npmText, "%s %v -> %v%s\n", c.name, c.old, c.new, flag)
	}
	if downgraded > 0 {
		fs.add(model.RouteHuman, "actions.lockfile-downgrade", name, "%d locked npm packages moved to a lower version", downgraded)
	}
	if bundlerLocked > 0 {
		fs.add(model.RouteReview, "actions.bundler-version-changed", name, "%d bundler/compiler packages changed locked version", bundlerLocked)
	}
	if len(pkgChanges) > 0 || pkgNotes.Len() > 0 {
		text := fmt.Sprintf("%d packages changed (%d new, %d downgraded)\n\n%s", len(pkgChanges), added, downgraded, npmText.String())
		if pkgNotes.Len() > 0 {
			text += "\npackage.json:\n" + pkgNotes.String()
		}
		if err := env.Evidence.AddUntrusted(evName(p, "npm-packages.txt"), "npm packages whose locked versions changed in "+name+" (NEW, DOWNGRADE flagged)", []byte(text)); err != nil {
			return err
		}
	}
	fmt.Fprintf(sum, "- upstream files changed: %d (first-party %d, bundles %d, lockfiles %d); npm packages changed: %d (new %d, downgraded %d)\n",
		len(changed), len(firstParty), len(bundles), len(locks), len(pkgChanges), added, downgraded)

	// First-party source diff.
	if len(firstParty) > 0 {
		specs := []string{".", ":(exclude,glob)**/dist/**"}
		for b := range lockBasenames {
			specs = append(specs, ":(exclude,glob)**/"+b)
		}
		for _, e := range entries {
			if !isDistPath(e) {
				specs = append(specs, ":(exclude,literal)"+e)
			}
		}
		d, err := up.diff(ctx, p.oldRef, p.newRef, specs...)
		if err != nil {
			return err
		}
		if err := env.Evidence.AddUntrusted(evName(p, "source.diff"), "first-party source diff of "+name+" (dist/ and lockfiles excluded)", []byte(d)); err != nil {
			return err
		}
	}

	// Bundles.
	attr := attribution{lockChanged: lockChanged, lockPaths: changedPaths(oldPaths, newPaths), lockNew: newLock}
	for _, c := range firstParty {
		attr.firstParty = append(attr.firstParty, c.path)
	}
	if !lockOK {
		attr.lockChanged, attr.lockPaths = map[string]bool{}, map[string]bool{}
	}
	var reports []*bundleReport
	for _, c := range bundles {
		if c.status == 'D' {
			continue
		}
		in, err := readBundle(ctx, up, p, c)
		if err != nil {
			return err
		}
		reports = append(reports, analyzeBundle(in, attr))
	}
	for _, c := range distOther {
		if c.status == 'D' {
			continue
		}
		od, _ := up.show(ctx, p.oldRef, c.path)
		nd, err := up.show(ctx, p.newRef, c.path)
		if err != nil {
			return err
		}
		r := &bundleReport{path: c.path, oldBytes: len(od), newBytes: len(nd), mode: "other"}
		r.residual = len(nd)
		r.residuals = append(r.residuals, residualItem{resWhole, c.path, len(nd)})
		reports = append(reports, r)
	}
	sort.Slice(reports, func(i, j int) bool { return reports[i].path < reports[j].path })
	var bundleText, pkgText strings.Builder
	for _, r := range reports {
		fmt.Fprintf(sum, "- bundle %s: mode %s, new %d bytes, unchanged %d, attributed %d, residual %d (%.3f%%)\n",
			safePath(r.path), r.mode, r.newBytes, r.unchanged, r.attributed, r.residual, 100*r.residualFraction())
		if r.residualFraction() > f.cfg.MaxResidual {
			fs.add(model.RouteHuman, "actions.dist-residual", name, "%s: %.2f%% of the bundle changed without a changed first-party file or locked package to explain it (limit %.2f%%)",
				safePath(r.path), 100*r.residualFraction(), 100*f.cfg.MaxResidual)
		}
		if len(r.nullContent) > 0 {
			fs.add(model.RouteReview, "actions.sourcemap-content-missing", name, "%s: %d changed sources have null sourcesContent (%d generated bytes); no source diff for them",
				safePath(r.path), len(r.nullContent), r.nullContentBytes)
		}
		bundleText.WriteString(renderBundle(r))
		bundleText.WriteString("\n")
		pkgText.WriteString(renderBundlePackages(r))
	}
	if len(distText) > 0 {
		var specs []string
		for _, c := range distText {
			specs = append(specs, ":(literal)"+c.path)
		}
		d, err := up.diff(ctx, p.oldRef, p.newRef, specs...)
		if err != nil {
			return err
		}
		bundleText.WriteString("\n==== dist text files\n" + d)
	}
	if bundleText.Len() > 0 {
		if err := env.Evidence.AddUntrusted(evName(p, "dist.txt"), "dist/ attribution for "+name+": residual list, then residual and first-party per-module/per-source diffs", []byte(bundleText.String())); err != nil {
			return err
		}
	}
	if pkgText.Len() > 0 {
		if err := env.Evidence.AddUntrusted(evName(p, "dist-packages.diff"), "per-source/per-module diffs of bundled npm packages whose locked version changed ("+name+")", []byte(pkgText.String())); err != nil {
			return err
		}
	}
	if len(reports) > 0 {
		fs.add(model.RouteReview, CodeRebuildNotRun, name, "dist/ was attributed from committed source maps and module markers, not rebuilt from source")
		sum.WriteString("- rebuild: not run (" + CodeRebuildNotRun + ")\n")
	}
	return nil
}

func readActionYML(ctx context.Context, g git, rev, sub string) ([]byte, string) {
	for _, n := range []string{"action.yml", "action.yaml"} {
		p := path.Join(sub, n)
		if b, err := g.show(ctx, rev, p); err == nil {
			return b, p
		}
	}
	return nil, ""
}

// readBundle loads a bundle at both commits with its source map (a .map
// next to it, or the file its sourceMappingURL names, or an inline map).
func readBundle(ctx context.Context, g git, p *pair, c fileChange) (bundleInput, error) {
	in := bundleInput{path: c.path}
	nd, err := g.show(ctx, p.newRef, c.path)
	if err != nil {
		return in, fmt.Errorf("reading %s: %w", c.path, err)
	}
	in.new = nd
	if c.status != 'A' {
		od, err := g.show(ctx, p.oldRef, c.path)
		if err != nil && !errors.Is(err, errMissing) {
			return in, err
		}
		in.old = od
	}
	load := func(rev string, js []byte) []byte {
		if js == nil {
			return nil
		}
		inline, ref := mapReference(c.path, js)
		if inline != nil {
			return inline
		}
		for _, mp := range []string{ref, c.path + ".map"} {
			if mp == "" {
				continue
			}
			if b, err := g.show(ctx, rev, mp); err == nil {
				return b
			}
		}
		return nil
	}
	in.newMap = load(p.newRef, in.new)
	in.oldMap = load(p.oldRef, in.old)
	return in, nil
}

// archiveAttributes lists the .gitattributes files at rev that name an
// attribute git archive applies: export-subst and ident rewrite file
// content, export-ignore drops files, eol=crlf, the legacy crlf and
// working-tree-encoding convert them, and a filter (filter=lfs above all)
// can make the archive serve other bytes than the blob. The runner downloads the action as GitHub's tarball of
// the pinned commit, which honors them; the gate reads raw blobs. Their
// effect cannot be replayed deterministically (export-subst expands
// %d/%cr and friends, which change as refs move and time passes), so
// their presence routes to a human instead.
//
// The scan is deliberately coarse: every whitespace-separated token of
// every line, comments and patterns included, is checked. Go splits on a
// superset of git's attribute separators, so a token git reads is never
// missed; the cost is an occasional false positive.
func archiveAttributes(ctx context.Context, g git, rev string) ([]string, error) {
	out, err := g.run(ctx, "ls-tree", "-r", "-z", "--full-tree", "--name-only", rev)
	if err != nil {
		return nil, err
	}
	var hits []string
	for _, f := range strings.Split(string(out), "\x00") {
		if path.Base(f) != ".gitattributes" {
			continue
		}
		data, err := g.show(ctx, rev, f)
		if err != nil {
			return nil, err
		}
		found := map[string]bool{}
		for _, tok := range strings.Fields(string(data)) {
			name, val, _ := strings.Cut(strings.TrimLeft(tok, "-!"), "=")
			switch {
			case name == "export-subst", name == "export-ignore", name == "ident", name == "working-tree-encoding",
				name == "filter", // filter=lfs: the archive may serve the LFS object, or the pointer
				name == "crlf",   // legacy crlf / -crlf / crlf=input: end-of-line conversion
				name == "eol" && val == "crlf":
				found[name] = true
			}
		}
		for _, n := range sortedKeys(found) {
			hits = append(hits, safePath(f)+" ("+n+")")
		}
	}
	return hits, nil
}

func sortedKeys(m map[string]bool) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

const lfsPointerPrefix = "version https://git-lfs.github.com/spec/"

// lfsPointers returns the changed files whose new blob is a Git LFS
// pointer. A `git diff --numstat` first fetches the changed blobs of a
// blobless clone in one batch.
func lfsPointers(ctx context.Context, g git, from, to string, changed []fileChange) ([]string, error) {
	if _, err := g.run(ctx, "diff", "--numstat", "--no-renames", "--no-ext-diff", "--no-textconv", "-z", from, to, "--"); err != nil {
		return nil, err
	}
	var shas []string
	for _, c := range changed {
		if c.status != 'D' && shaRx.MatchString(c.newSHA) && c.newMode != "160000" {
			shas = append(shas, c.newSHA)
		}
	}
	pre, err := g.blobPrefixes(ctx, shas, len(lfsPointerPrefix))
	if err != nil {
		return nil, err
	}
	var out []string
	for _, c := range changed {
		if string(pre[c.newSHA]) == lfsPointerPrefix {
			out = append(out, safePath(c.path))
		}
	}
	return out, nil
}
