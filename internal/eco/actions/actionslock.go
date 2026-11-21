package actions

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/sadbox/dep-review/internal/fetch"
	"github.com/sadbox/dep-review/internal/model"
)

// GitHub workflow lockfiles (.github/workflows/actions.lock, written by
// `gh actions-lock`, schema github/actions-lockfile v0.0.3). An onboarded
// workflow names actions by tag (`uses: owner/repo@v1.2.3`) and the runner
// runs the commit the lockfile records for "owner/repo@v1.2.3". So a
// Dependabot bump of such a workflow is a tag change in the workflow plus
// a lockfile change, and the commit to verify comes from the lockfile.
//
// The gate reads only the exact form gh-actions-lock emits (yaml.v3,
// four-space indent, keys sorted, user strings single-quoted, fields in a
// fixed order). That form is a small line grammar, so it is parsed as one,
// and the text is also read by the gate's YAML subset reader (parseYAML)
// and both readings must agree. Anything else (another schema version, a
// hostname, double quotes, escapes, flow collections other than an empty
// workflow list, comments after the header, unknown fields, unsorted or
// duplicate keys, upper case in an owner/repo) is refused: the file is
// machine-generated, and a hand-edited or unfamiliar one is exactly what
// the gate must not guess about.

const (
	actionsLockPath    = ".github/workflows/actions.lock"
	actionsLockVersion = "v0.0.3"
	actionsLockMax     = 1 << 20 // github/actions-lockfile MaxParseSize
)

// lockEntry is one dependencies entry. commit is the 40-hex SHA without
// its "sha1-" prefix.
type lockEntry struct {
	ref     string
	commit  string
	ownerID int64
	repoID  int64
	uses    []string
}

func (e *lockEntry) equal(o *lockEntry) bool {
	return e.ref == o.ref && e.commit == o.commit && e.ownerID == o.ownerID && e.repoID == o.repoID &&
		strings.Join(e.uses, "\n") == strings.Join(o.uses, "\n")
}

type lockFile struct {
	workflows map[string][]string   // workflow path -> pin keys
	deps      map[string]*lockEntry // pin key -> entry
}

var (
	errLockFormat = errors.New("actions.lock is not in the form gh-actions-lock writes")

	lockCommentRx  = regexp.MustCompile(`^# [ -~]*$`)
	lockWorkflowRx = regexp.MustCompile(`^\.github/workflows/[A-Za-z0-9._-]{1,200}\.ya?ml$`)
	// lockPinRx is a canonical pin key: owner and repo lower case (as
	// github/actions-lockfile's Pin.Canonical writes them), ref as written.
	lockPinRx    = regexp.MustCompile(`^([a-z0-9](?:[a-z0-9-]{0,38}))/([a-z0-9._-]{1,100})@([A-Za-z0-9._/@+-]{1,255})$`)
	lockRefRx    = regexp.MustCompile(`^[A-Za-z0-9._/@+-]{1,255}$`)
	lockCommitRx = regexp.MustCompile(`^sha1-([0-9a-f]{40})$`)
	lockIntRx    = regexp.MustCompile(`^[1-9][0-9]{0,17}$`)
)

func lockErr(line int, format string, args ...any) error {
	return fmt.Errorf("%w: line %d: %s", errLockFormat, line, fmt.Sprintf(format, args...))
}

// splitPin returns the owner/repo and ref of a canonical pin key.
func splitPin(k string) (nwo, ref string, ok bool) {
	m := lockPinRx.FindStringSubmatch(k)
	if m == nil || m[2] == "." || m[2] == ".." {
		return "", "", false
	}
	return m[1] + "/" + m[2], m[3], true
}

// safePin returns k if it is a canonical pin key, for text the gate writes
// as trusted; a key built from a uses: line may hold anything else.
func safePin(k string) string {
	if _, _, ok := splitPin(k); ok {
		return k
	}
	return "(pin with unusual characters)"
}

// safeRef returns r if it is a vX.Y.Z tag, for trusted text.
func safeRef(r string) string {
	if _, ok := parseTag(r); ok {
		return r
	}
	return "(a ref that is not a vX.Y.Z tag)"
}

// pinKey is the lockfile key a `uses: owner/repo[/path]@ref` resolves to:
// the path is dropped and owner/repo lower-cased, as in
// github/actions-lockfile's ParsePin/Pin.Canonical.
func pinKey(owner, repo, ref string) string {
	return strings.ToLower(owner) + "/" + strings.ToLower(repo) + "@" + ref
}

// lockQuoted reads a single-quoted scalar that makes up all of s, with no
// quote inside (so none of YAML's doubled-quote escapes).
func lockQuoted(s string) (string, bool) {
	if len(s) < 2 || s[0] != '\'' || s[len(s)-1] != '\'' {
		return "", false
	}
	in := s[1 : len(s)-1]
	if in == "" || strings.ContainsRune(in, '\'') {
		return "", false
	}
	return in, true
}

// parseActionsLock parses and validates a lockfile. Errors wrap
// errLockFormat or errLineBreak.
func parseActionsLock(data []byte) (*lockFile, error) {
	if len(data) > actionsLockMax {
		return nil, fmt.Errorf("%w: larger than %d bytes", errLockFormat, actionsLockMax)
	}
	text := string(data)
	if err := checkYAMLText(text); err != nil {
		return nil, err
	}
	if strings.ContainsAny(text, "\r\t\"\\") {
		return nil, fmt.Errorf("%w: CR, tab, double quote or backslash", errLockFormat)
	}
	if !strings.HasSuffix(text, "\n") {
		return nil, fmt.Errorf("%w: no final newline", errLockFormat)
	}
	lf, err := parseLockLines(strings.Split(strings.TrimSuffix(text, "\n"), "\n"))
	if err != nil {
		return nil, err
	}
	if err := lf.validate(); err != nil {
		return nil, err
	}
	// Second reading: the gate's YAML subset reader must see the same data.
	v, err := parseYAML(text)
	if err != nil {
		return nil, fmt.Errorf("%w: YAML reader: %v", errLockFormat, err)
	}
	if err := lf.sameAsYAML(v); err != nil {
		return nil, fmt.Errorf("%w: YAML reader disagrees: %v", errLockFormat, err)
	}
	return lf, nil
}

func parseLockLines(lines []string) (*lockFile, error) {
	lf := &lockFile{workflows: map[string][]string{}, deps: map[string]*lockEntry{}}
	i := 0
	for i < len(lines) && strings.HasPrefix(lines[i], "#") {
		if !lockCommentRx.MatchString(lines[i]) {
			return nil, lockErr(i+1, "header comment")
		}
		i++
	}
	if i >= len(lines) {
		return nil, lockErr(i+1, "no version")
	}
	v, ok := strings.CutPrefix(lines[i], "version: ")
	if !ok {
		return nil, lockErr(i+1, "expected version")
	}
	if v, ok = lockQuoted(v); !ok || v != actionsLockVersion {
		return nil, lockErr(i+1, "schema version is not %s", actionsLockVersion)
	}
	i++
	// item reads "<indent>- '<pin>'" lines into a list.
	items := func(indent string) ([]string, error) {
		var out []string
		for i < len(lines) && strings.HasPrefix(lines[i], indent+"- ") {
			p, ok := lockQuoted(lines[i][len(indent)+2:])
			if !ok {
				return nil, lockErr(i+1, "list item")
			}
			out = append(out, p)
			i++
		}
		if len(out) == 0 {
			return nil, lockErr(i+1, "empty list")
		}
		return out, nil
	}
	var lastWF, lastDep string
	if i < len(lines) && lines[i] == "workflows:" {
		i++
		for i < len(lines) && strings.HasPrefix(lines[i], "    '") {
			l := lines[i]
			var wf string
			var list []string
			if k, ok := strings.CutSuffix(l[4:], ": []"); ok {
				if wf, ok = lockQuoted(k); !ok {
					return nil, lockErr(i+1, "workflow key")
				}
				list = []string{}
				i++
			} else if k, ok := strings.CutSuffix(l[4:], ":"); ok {
				if wf, ok = lockQuoted(k); !ok {
					return nil, lockErr(i+1, "workflow key")
				}
				i++
				var err error
				if list, err = items("        "); err != nil {
					return nil, err
				}
			} else {
				return nil, lockErr(i+1, "workflow key")
			}
			if wf <= lastWF {
				return nil, lockErr(i, "workflow keys not sorted, or a duplicate")
			}
			lastWF = wf
			lf.workflows[wf] = list
		}
		if len(lf.workflows) == 0 {
			return nil, lockErr(i+1, "empty workflows")
		}
	}
	if i < len(lines) && lines[i] == "dependencies:" {
		i++
		for i < len(lines) && strings.HasPrefix(lines[i], "    '") {
			k, ok := strings.CutSuffix(lines[i][4:], ":")
			if ok {
				k, ok = lockQuoted(k)
			}
			if !ok {
				return nil, lockErr(i+1, "dependency key")
			}
			if k <= lastDep {
				return nil, lockErr(i+1, "dependency keys not sorted, or a duplicate")
			}
			lastDep = k
			i++
			e := &lockEntry{}
			field := func(name string) (string, error) {
				if i >= len(lines) {
					return "", lockErr(i+1, "missing %s", name)
				}
				v, ok := strings.CutPrefix(lines[i], "        "+name+": ")
				if !ok {
					return "", lockErr(i+1, "expected %s", name)
				}
				i++
				return v, nil
			}
			ref, err := field("ref")
			if err != nil {
				return nil, err // a hostname line (or anything else) first is refused here
			}
			if e.ref, ok = lockQuoted(ref); !ok {
				return nil, lockErr(i, "ref")
			}
			c, err := field("commit")
			if err != nil {
				return nil, err
			}
			if c, ok = lockQuoted(c); !ok {
				return nil, lockErr(i, "commit")
			}
			m := lockCommitRx.FindStringSubmatch(c)
			if m == nil {
				return nil, lockErr(i, "commit is not sha1-<40 lower-case hex>")
			}
			e.commit = m[1]
			for _, f := range []struct {
				name string
				dst  *int64
			}{{"owner_id", &e.ownerID}, {"repo_id", &e.repoID}} {
				s, err := field(f.name)
				if err != nil {
					return nil, err
				}
				if !lockIntRx.MatchString(s) {
					return nil, lockErr(i, "%s is not a positive integer", f.name)
				}
				if *f.dst, err = strconv.ParseInt(s, 10, 64); err != nil {
					return nil, lockErr(i, "%s", f.name)
				}
			}
			if i < len(lines) && lines[i] == "        uses:" {
				i++
				if e.uses, err = items("            "); err != nil {
					return nil, err
				}
			}
			lf.deps[k] = e
		}
		if len(lf.deps) == 0 {
			return nil, lockErr(i+1, "empty dependencies")
		}
	}
	if i < len(lines) {
		return nil, lockErr(i+1, "unexpected line")
	}
	return lf, nil
}

func strictlySorted(l []string) bool {
	for i := 1; i < len(l); i++ {
		if l[i-1] >= l[i] {
			return false
		}
	}
	return true
}

// validate checks what the grammar cannot: names, sort order (which also
// rules out duplicates), references, key/entry agreement and cycles.
func (lf *lockFile) validate() error {
	bad := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", errLockFormat, fmt.Sprintf(format, args...))
	}
	folded := map[string]bool{}
	for wf, list := range lf.workflows {
		if !lockWorkflowRx.MatchString(wf) {
			return bad("workflow path %s", safePath(wf))
		}
		if folded[strings.ToLower(wf)] {
			return bad("two workflow paths differ only in case")
		}
		folded[strings.ToLower(wf)] = true
		if !strictlySorted(list) {
			return bad("pins of %s are not sorted or not unique", safePath(wf))
		}
		for _, p := range list {
			if lf.deps[p] == nil {
				return bad("%s names a pin with no dependencies entry", safePath(wf))
			}
		}
	}
	for k, e := range lf.deps {
		_, ref, ok := splitPin(k)
		if !ok {
			return bad("dependency key is not a canonical lower-case owner/repo@ref")
		}
		if !lockRefRx.MatchString(e.ref) {
			return bad("ref of %s", k)
		}
		if shaRx.MatchString(ref) {
			if e.commit != ref {
				return bad("%s: commit differs from the SHA in its key", k)
			}
		} else if e.ref != ref {
			return bad("%s: ref differs from the ref in its key", k)
		}
		if !strictlySorted(e.uses) {
			return bad("uses of %s are not sorted or not unique", k)
		}
		for _, u := range e.uses {
			if lf.deps[u] == nil || u == k {
				return bad("%s uses a pin with no dependencies entry", k)
			}
		}
	}
	// Cycles: github/actions-lockfile refuses them; so does the gate.
	state := map[string]int{}
	var visit func(k string) bool
	visit = func(k string) bool {
		switch state[k] {
		case 1:
			return false
		case 2:
			return true
		}
		state[k] = 1
		for _, u := range lf.deps[k].uses {
			if !visit(u) {
				return false
			}
		}
		state[k] = 2
		return true
	}
	for _, k := range sortedMapKeys(lf.deps) {
		if !visit(k) {
			return bad("uses cycle")
		}
	}
	return nil
}

func sortedMapKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// sameAsYAML compares the line-grammar reading with parseYAML's.
func (lf *lockFile) sameAsYAML(v any) error {
	root, ok := v.(*yMap)
	if !ok {
		return errors.New("not a mapping")
	}
	want := []string{"version"}
	if len(lf.workflows) > 0 {
		want = append(want, "workflows")
	}
	if len(lf.deps) > 0 {
		want = append(want, "dependencies")
	}
	if strings.Join(root.keys, ",") != strings.Join(want, ",") {
		return errors.New("top-level keys")
	}
	if root.get("version") != actionsLockVersion {
		return errors.New("version")
	}
	list := func(x any) ([]string, bool) {
		if f, ok := x.(yFlow); ok {
			return []string{}, f == "[]"
		}
		xs, ok := x.([]any)
		if !ok {
			return nil, false
		}
		out := make([]string, 0, len(xs))
		for _, e := range xs {
			s, ok := e.(string)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	}
	same := func(a, b []string) bool { return strings.Join(a, "\n") == strings.Join(b, "\n") }
	if len(lf.workflows) > 0 {
		w := root.sub("workflows")
		if w == nil || !same(w.keys, sortedMapKeys(lf.workflows)) {
			return errors.New("workflow keys (sorted, as written)")
		}
		for _, k := range w.keys {
			l, ok := list(w.get(k))
			if !ok || !same(l, lf.workflows[k]) {
				return errors.New("workflow pins")
			}
		}
	}
	if len(lf.deps) > 0 {
		d := root.sub("dependencies")
		if d == nil || !same(d.keys, sortedMapKeys(lf.deps)) {
			return errors.New("dependency keys (sorted, as written)")
		}
		for _, k := range d.keys {
			e, m := lf.deps[k], d.sub(k)
			if m == nil {
				return errors.New("dependency entry")
			}
			fields := []string{"ref", "commit", "owner_id", "repo_id"}
			if len(e.uses) > 0 {
				fields = append(fields, "uses")
			}
			if !same(m.keys, fields) || m.str("ref") != e.ref || m.str("commit") != "sha1-"+e.commit ||
				m.str("owner_id") != strconv.FormatInt(e.ownerID, 10) || m.str("repo_id") != strconv.FormatInt(e.repoID, 10) {
				return errors.New("dependency fields")
			}
			if len(e.uses) > 0 {
				if l, ok := list(m.get("uses")); !ok || !same(l, e.uses) {
					return errors.New("dependency uses")
				}
			}
		}
	}
	return nil
}

// closure returns every key reachable from roots through uses, roots
// excluded unless reachable from another root.
func (lf *lockFile) closure(roots []string) map[string]bool {
	out := map[string]bool{}
	var walk func(k string)
	walk = func(k string) {
		e := lf.deps[k]
		if e == nil {
			return
		}
		for _, u := range e.uses {
			if !out[u] {
				out[u] = true
				walk(u)
			}
		}
	}
	for _, r := range roots {
		walk(r)
	}
	return out
}

// lockBump is one tag (or SHA) change of a step-level uses: line in an
// onboarded workflow, as lockfile keys.
type lockBump struct {
	workflow       string
	oldKey, newKey string
}

// lockFinding is a lockfile problem; update is the action name it concerns
// ("" for the file as a whole).
type lockFinding struct {
	route  model.Route
	code   string
	update string
	detail string
}

// lockDelta checks that the lockfile change is exactly what the bumps
// explain: in each bumped workflow's list the old key gives way to the new
// one, the new key's entry is added (or was already there, unchanged),
// and an old key nothing references any more is dropped. A change to an
// entry the bumped actions reach through uses (a transitive action) is
// accepted only when wk (from transitiveWalk) accounts for that key
// (its commit is then analyzed as a transitive pair, or it was dropped);
// otherwise it goes to a human, as does every other change. walked says
// the walk ran, so a bumped action's changed uses list is its business.
// Disagreement between the workflows and the lockfile (a bumped workflow
// whose list lacks the new key or never had the old one, a missing entry)
// is refused.
func lockDelta(old, new *lockFile, bumps []lockBump, wk *walkKeys) []lockFinding {
	if wk == nil {
		wk = &walkKeys{}
	}
	walked := wk.pairNew != nil
	var out []lockFinding
	add := func(route model.Route, code, update, format string, args ...any) {
		out = append(out, lockFinding{route, code, update, fmt.Sprintf(format, args...)})
	}
	nameOf := func(k string) string {
		n, _, _ := splitPin(k)
		return n
	}
	// Onboarding is never Dependabot's: the set of workflows must not change.
	if !strictlySortedEqual(sortedMapKeys(old.workflows), sortedMapKeys(new.workflows)) {
		add(model.RouteRefuse, "actions.lock-onboarding-changed", "", "the set of workflows in actions.lock changed (Dependabot never onboards or drops a workflow)")
	}
	byWF := map[string][]lockBump{}
	oldKeys, newKeys := map[string]bool{}, map[string]bool{}
	for _, b := range bumps {
		byWF[b.workflow] = append(byWF[b.workflow], b)
		oldKeys[b.oldKey], newKeys[b.newKey] = true, true
		if old.deps[b.oldKey] == nil || !contains(old.workflows[b.workflow], b.oldKey) {
			add(model.RouteRefuse, "actions.lock-uses-mismatch", nameOf(b.oldKey), "%s: the base actions.lock does not list %s for this workflow", safePath(b.workflow), safePin(b.oldKey))
		}
		if new.deps[b.newKey] == nil || !contains(new.workflows[b.workflow], b.newKey) {
			add(model.RouteRefuse, "actions.lock-uses-mismatch", nameOf(b.newKey), "%s: the new actions.lock does not list %s for this workflow", safePath(b.workflow), safePin(b.newKey))
		}
	}
	oldTrans := old.closure(sortedMapKeys(oldKeys))
	newTrans := new.closure(sortedMapKeys(newKeys))
	transitive := func(k string) bool { return oldTrans[k] || newTrans[k] }
	// Only an entry that is itself a transitive pair's new entry (analyzed
	// like a bump) may be added or changed; a dropped pin or a pair's old
	// key explains only its own removal.
	analyzedNew := func(k string) bool { return transitive(k) && wk.pairNew[k] }
	listAdd := func(k string) bool { return transitive(k) && (wk.pairNew[k] || wk.kept[k]) }
	gone := func(k string) bool { return transitive(k) && new.deps[k] == nil && (wk.pairOld[k] || wk.dropped[k]) }

	// Workflow lists.
	for _, wf := range sortedMapKeys(new.workflows) {
		ol, ok := old.workflows[wf]
		if !ok {
			continue // reported above
		}
		nl := new.workflows[wf]
		for _, k := range setMinus(nl, ol) {
			switch {
			case bumpHas(byWF[wf], func(b lockBump) bool { return b.newKey == k }), listAdd(k):
			case transitive(k):
				add(model.RouteHuman, "actions.lock-transitive-changed", nameOf(k), "%s: transitive pin %s added to the workflow's list", safePath(wf), k)
			default:
				add(model.RouteHuman, "actions.lock-unexplained-change", nameOf(k), "%s: pin %s added to the workflow's list, but no uses: line of this workflow was bumped to it", safePath(wf), k)
			}
		}
		for _, k := range setMinus(ol, nl) {
			switch {
			case bumpHas(byWF[wf], func(b lockBump) bool { return b.oldKey == k }), gone(k):
			case transitive(k):
				add(model.RouteHuman, "actions.lock-transitive-changed", nameOf(k), "%s: transitive pin %s dropped from the workflow's list", safePath(wf), k)
			default:
				add(model.RouteHuman, "actions.lock-unexplained-change", nameOf(k), "%s: pin %s dropped from the workflow's list, but no uses: line of this workflow was bumped from it", safePath(wf), k)
			}
		}
	}

	// Dependency entries.
	for _, k := range sortedMapKeys(new.deps) {
		ne, oe := new.deps[k], old.deps[k]
		switch {
		case oe != nil && oe.equal(ne):
		case analyzedNew(k) && !newKeys[k]:
		case oe != nil:
			if newKeys[k] || transitive(k) {
				add(model.RouteHuman, "actions.lock-entry-moved", nameOf(k), "the entry for %s changed (commit %s -> %s): the same ref now resolves elsewhere", k, short(oe.commit), short(ne.commit))
			} else {
				add(model.RouteHuman, "actions.lock-unexplained-change", nameOf(k), "the entry for %s changed, but no bumped action uses it", k)
			}
		case newKeys[k]:
		case transitive(k):
			add(model.RouteHuman, "actions.lock-transitive-changed", nameOf(k), "transitive pin %s added (%s), and the gate did not analyze it as a transitive pair", k, short(ne.commit))
		default:
			add(model.RouteHuman, "actions.lock-unexplained-change", nameOf(k), "pin %s added, but no bumped action uses it", k)
		}
	}
	for _, k := range sortedMapKeys(old.deps) {
		if new.deps[k] != nil || oldKeys[k] || gone(k) {
			continue
		}
		if transitive(k) {
			add(model.RouteHuman, "actions.lock-transitive-changed", nameOf(k), "transitive pin %s removed", k)
		} else {
			add(model.RouteHuman, "actions.lock-unexplained-change", nameOf(k), "pin %s removed, but no bumped action used it", k)
		}
	}
	// A bumped action's own uses (its composite steps) must stay the same:
	// then every transitive pin it reaches is one the base already locked.
	for _, b := range bumps {
		oe, ne := old.deps[b.oldKey], new.deps[b.newKey]
		if oe == nil || ne == nil {
			continue
		}
		if !walked && strings.Join(oe.uses, "\n") != strings.Join(ne.uses, "\n") {
			add(model.RouteHuman, "actions.lock-transitive-changed", nameOf(b.newKey), "%s uses %d pins, %s used %d: its transitive actions changed", b.newKey, len(ne.uses), b.oldKey, len(oe.uses))
		}
		if oe.ownerID != ne.ownerID || oe.repoID != ne.repoID {
			add(model.RouteHuman, "actions.lock-identity-changed", nameOf(b.newKey), "%s records owner/repo IDs %d/%d, %s recorded %d/%d: the repository behind the name changed", b.newKey, ne.ownerID, ne.repoID, b.oldKey, oe.ownerID, oe.repoID)
		}
	}
	return dedupLockFindings(out)
}

func dedupLockFindings(in []lockFinding) []lockFinding {
	seen := map[lockFinding]bool{}
	var out []lockFinding
	for _, f := range in {
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	return out
}

func strictlySortedEqual(a, b []string) bool { return strings.Join(a, "\n") == strings.Join(b, "\n") }

func setMinus(a, b []string) []string {
	in := map[string]bool{}
	for _, x := range b {
		in[x] = true
	}
	var out []string
	for _, x := range a {
		if !in[x] {
			out = append(out, x)
		}
	}
	return out
}

func bumpHas(bs []lockBump, f func(lockBump) bool) bool {
	for _, b := range bs {
		if f(b) {
			return true
		}
	}
	return false
}

// transPair is a transitive action whose locked commit a bump changed:
// the same repository, under the same parent, at another commit (or at the
// same commit under another key, which needs only its identity checked).
type transPair struct {
	nwo                string
	oldKey, newKey     string
	oldEntry, newEntry *lockEntry
	parentNewKey       string // the entry whose uses list names newKey
	via                string // bumped key > ... > newKey, for evidence
	sameCommit         bool
}

// transitiveWalk pairs the transitive entries a bump changed. Starting at
// each bumped (old key, new key), it matches the old and new entries' uses
// lists by repository: one old and one new pin of a repository is a pair
// (walked further, so a composite's own changed pins pair up too); a pin
// of a repository the old list did not have is new code with no baseline
// and goes to a human, unless the base already locked that exact entry;
// two pins of one repository on a side are ambiguous and go to a human; a
// pin dropped from the list needs no review. The lockfile is flat, so the
// walk visits each entry pair once and reads no action.yml.
//
// The returned walkKeys record which keys the walk accounts for, for
// lockDelta.
func transitiveWalk(old, new *lockFile, bumps []lockBump) ([]*transPair, *walkKeys, []lockFinding) {
	var pairs []*transPair
	var out []lockFinding
	wk := &walkKeys{pairNew: map[string]bool{}, pairOld: map[string]bool{}, dropped: map[string]bool{}, kept: map[string]bool{}}
	add := func(route model.Route, code, update, format string, args ...any) {
		out = append(out, lockFinding{route, code, update, fmt.Sprintf(format, args...)})
	}
	type node struct{ oldKey, newKey, via string }
	var queue []node
	seen := map[[2]string]bool{}    // entry pairs walked
	emitted := map[[3]string]bool{} // parent, old key, new key
	for _, b := range bumps {
		if old.deps[b.oldKey] != nil && new.deps[b.newKey] != nil && !seen[[2]string{b.oldKey, b.newKey}] {
			seen[[2]string{b.oldKey, b.newKey}] = true
			queue = append(queue, node{b.oldKey, b.newKey, b.newKey})
		}
	}
	byRepo := func(keys []string) (map[string][]string, []string) {
		m := map[string][]string{}
		var order []string
		for _, k := range keys {
			n, _, _ := splitPin(k)
			if m[n] == nil {
				order = append(order, n)
			}
			m[n] = append(m[n], k)
		}
		return m, order
	}
	for len(queue) > 0 {
		nd := queue[0]
		queue = queue[1:]
		oe, ne := old.deps[nd.oldKey], new.deps[nd.newKey]
		om, _ := byRepo(oe.uses)
		nm, norder := byRepo(ne.uses)
		for n, ks := range om {
			if nm[n] == nil {
				for _, k := range ks {
					wk.dropped[k] = true // dropped: nothing to review
				}
			}
		}
		for _, n := range norder {
			olds, news := om[n], nm[n]
			switch {
			case len(olds) == 0:
				for _, k := range news {
					if oe2 := old.deps[k]; oe2 != nil && oe2.equal(new.deps[k]) {
						wk.kept[k] = true // already locked as is
						continue
					}
					add(model.RouteHuman, "actions.lock-transitive-added", n, "%s now uses %s, a repository its old version did not use: no baseline to diff", nd.newKey, k)
				}
			case len(olds) > 1 || len(news) > 1:
				add(model.RouteHuman, "actions.lock-transitive-ambiguous", n, "%s uses %d pins of %s, its old version %d: the gate cannot pair them", nd.newKey, len(news), n, len(olds))
			default:
				ok, nk := olds[0], news[0]
				o2, n2 := old.deps[ok], new.deps[nk]
				if ok == nk && o2.equal(n2) {
					if !seen[[2]string{ok, nk}] {
						seen[[2]string{ok, nk}] = true
						queue = append(queue, node{ok, nk, nd.via + " > " + nk})
					}
					continue
				}
				wk.pairOld[ok], wk.pairNew[nk] = true, true
				// One transPair per parent, even for a pair that is also a
				// bump or that another parent reached: each parent may run
				// another subpath of it, which Fetch must analyze.
				if e := [3]string{nd.newKey, ok, nk}; !emitted[e] {
					emitted[e] = true
					if o2.ownerID != n2.ownerID || o2.repoID != n2.repoID {
						add(model.RouteHuman, "actions.lock-identity-changed", n, "%s records owner/repo IDs %d/%d, %s recorded %d/%d: the repository behind the name changed", nk, n2.ownerID, n2.repoID, ok, o2.ownerID, o2.repoID)
					}
					pairs = append(pairs, &transPair{nwo: n, oldKey: ok, newKey: nk, oldEntry: o2, newEntry: n2,
						parentNewKey: nd.newKey, via: nd.via + " > " + nk, sameCommit: o2.commit == n2.commit})
				}
				if !seen[[2]string{ok, nk}] {
					seen[[2]string{ok, nk}] = true
					queue = append(queue, node{ok, nk, nd.via + " > " + nk})
				}
			}
		}
	}
	return pairs, wk, out
}

// walkKeys is what transitiveWalk accounts for: the new and old keys of
// its pairs, pins a bumped entry no longer uses, and pins it newly uses
// that the base locked identically. A nil pairNew means no walk.
type walkKeys struct {
	pairNew, pairOld, dropped, kept map[string]bool
}

// checkActionsLock reads actions.lock at both commits. Without one on
// either side it does nothing, and the PR is checked as before. Otherwise
// it resolves each rewritten step-level uses: line of an onboarded
// workflow through the lockfiles (setting all[i].lock) and checks the
// lockfile delta against those lines. It returns the transitive pairs the
// caller must analyze; above maxTrans of them it returns none and the
// transitive changes go to a human.
func checkActionsLock(ctx context.Context, caller git, env fetch.Env, base, head string, lockChanged bool, all []usesChange, maxTrans int, fs *findings, sum *strings.Builder) ([]*transPair, error) {
	read := func(rev string) ([]byte, error) {
		b, err := caller.show(ctx, rev, actionsLockPath)
		if errors.Is(err, errMissing) {
			return nil, nil
		}
		return b, err
	}
	oldText, err := read(base)
	if err != nil {
		return nil, fmt.Errorf("reading %s at base: %w", actionsLockPath, err)
	}
	newText, err := read(head)
	if err != nil {
		return nil, fmt.Errorf("reading %s at head: %w", actionsLockPath, err)
	}
	if oldText == nil || newText == nil {
		return nil, nil // none, or added or deleted: refused as actions.unexpected-file
	}
	parse := func(side string, b []byte) *lockFile {
		lf, err := parseActionsLock(b)
		if err == nil {
			return lf
		}
		code := "actions.lock-unparsed"
		if errors.Is(err, errLineBreak) {
			code = codeLineBreak
		}
		fs.add(model.RouteRefuse, code, "", "%s at %s: %s", actionsLockPath, side, err)
		return nil
	}
	oldLock, newLock := parse("base", oldText), parse("head", newText)
	if oldLock == nil || newLock == nil {
		sum.WriteString("actions.lock: refused, not read\n\n")
		return nil, nil
	}

	var bumps []lockBump
	var trans []*transPair
	for i := range all {
		c := &all[i]
		_, inOld := oldLock.workflows[c.file]
		_, inNew := newLock.workflows[c.file]
		if c.kind != kindWorkflow || c.job || (!inOld && !inNew) {
			continue // not covered by the lockfile: SHA pins, as before
		}
		if !inOld || !inNew {
			continue // onboarding changed: lockDelta refuses
		}
		owner, repo, _, err := splitAction(c.new.action)
		if err != nil {
			continue // groupPairs refuses
		}
		exact := true
		for _, r := range []string{c.old.ref, c.new.ref} {
			if _, ok := parseTag(r); !ok && !shaRx.MatchString(r) {
				exact = false
			}
		}
		if !exact {
			fs.add(model.RouteRefuse, "actions.lock-ref-not-exact", owner+"/"+repo, "%s:%d: a locked step names a ref that is neither a vX.Y.Z tag nor a full commit SHA (a floating tag or branch accepts any commit in its history)", safePath(c.file), c.line)
		}
		b := lockBump{workflow: c.file, oldKey: pinKey(owner, repo, c.old.ref), newKey: pinKey(owner, repo, c.new.ref)}
		bumps = append(bumps, b)
		l := &usesLock{oldKey: b.oldKey, newKey: b.newKey, oldEntry: oldLock.deps[b.oldKey], newEntry: newLock.deps[b.newKey]}
		if l.oldEntry != nil {
			l.oldCommit = l.oldEntry.commit
		}
		if l.newEntry != nil {
			l.newCommit = l.newEntry.commit
		}
		c.lock = l
	}

	switch {
	case len(bumps) > 0 && !lockChanged:
		fs.add(model.RouteRefuse, "actions.lock-not-updated", "", "the PR rewrites uses: lines of workflows onboarded to %s but does not change it", actionsLockPath)
	case len(bumps) == 0 && lockChanged:
		fs.add(model.RouteRefuse, "actions.lock-unexpected-change", "", "the PR changes %s but no uses: line of an onboarded workflow", actionsLockPath)
	case lockChanged:
		var walked []lockFinding
		var wk *walkKeys
		trans, wk, walked = transitiveWalk(oldLock, newLock, bumps)
		distinct := map[[2]string]bool{}
		for _, t := range trans {
			distinct[[2]string{t.oldKey, t.newKey}] = true
		}
		if len(distinct) > maxTrans {
			fs.add(model.RouteHuman, "actions.lock-transitive-cap", "", "the bump changes %d transitive actions in %s, more than the gate analyzes (MaxTransitive %d)", len(distinct), actionsLockPath, maxTrans)
			trans, wk, walked = nil, nil, nil
		}
		for _, x := range walked {
			fs.add(x.route, x.code, x.update, "%s", x.detail)
		}
		for _, x := range lockDelta(oldLock, newLock, bumps, wk) {
			fs.add(x.route, x.code, x.update, "%s", x.detail)
		}
	}
	if lockChanged {
		if err := env.Evidence.AddUntrusted("actions/actions-lock.diff", "diff of "+actionsLockPath+" (written by gh-actions-lock from upstream tag names)", []byte(unifiedDiff("a/"+actionsLockPath, "b/"+actionsLockPath, string(oldText), string(newText), 3))); err != nil {
			return nil, err
		}
	}
	fmt.Fprintf(sum, "actions.lock: %d onboarded workflows; %d rewritten locked uses: lines; lockfile changed: %t; transitive pairs: %d\n\n", len(newLock.workflows), len(bumps), lockChanged, len(trans))
	return trans, nil
}
