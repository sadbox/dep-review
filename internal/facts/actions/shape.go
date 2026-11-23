package actions

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/sadbox/dep-review/internal/facts"
	"github.com/sadbox/dep-review/internal/gh"
)

// This file reads the change set. There is no YAML parser here, on
// purpose. The rule is: base and head have the same number of lines, and
// every line that differs is one of a few exact shapes at both commits,
// byte for byte equal once its version and commit tokens are set aside.
// Whatever the runner made of the base file, the head file is the same
// text with those tokens replaced, and the facts are then established for
// exactly those tokens. The regular expressions only find the tokens; the
// safety is in the equality of everything else.

// lockPath is the workflow lockfile `gh actions-lock` writes.
const lockPath = ".github/workflows/actions.lock"

// reusableWorkflowDir starts the path of a `uses:` that calls a reusable
// workflow: a file in the called repository's .github/workflows. A
// workflow is not an action. It runs as jobs of its own, with whatever
// secrets and permissions the caller passes, and the gate's own workflow
// is one, so a change to such a pin is never granted (spec section 11,
// amendment 6): Shape does not hold, whatever the facts about the commit
// would be. Anything under that directory counts, not only *.yml, so that
// nothing a runner might still take for a workflow slips by.
const reusableWorkflowDir = "/.github/workflows/"

// regularFile is the only git mode a changed file may have, at both
// commits. A symlink, a submodule, an executable bit, or a file that is
// added or deleted is not a pin update.
const regularFile = "100644"

// The token shapes. A version is a plain vX.Y.Z release tag: no
// pre-release, no build suffix, no leading zeros, no two-part "v4.6".
const (
	shaPat     = `[0-9a-f]{40}`
	versionPat = `v(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})`
	// namePat is owner/repo as GitHub allows them; lockNamePat is the same
	// in the lower case the lockfile writes its keys in.
	namePat     = `[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}`
	lockNamePat = `[a-z0-9][a-z0-9-]{0,38}/[a-z0-9._-]{1,100}`
	subPathPat  = `(?:/[A-Za-z0-9._-]+)*`
)

var (
	// A workflow as GitHub reads it (top level of .github/workflows only),
	// and a local action's metadata file anywhere in the repository.
	workflowPathRe = regexp.MustCompile(`^\.github/workflows/[A-Za-z0-9._-]{1,200}\.ya?ml$`)
	actionPathRe   = regexp.MustCompile(`^(?:[A-Za-z0-9._-]+/)*action\.ya?ml$`)

	// The two pin lines of a workflow or action file. Spaces only, one
	// optional "- ", no quotes. The commit form carries its version in the
	// comment, and nothing else. The tag form is for a workflow onboarded
	// to actions.lock, where the lockfile holds the commit; it may end in
	// a comment of printable ASCII, which must be the same at both
	// commits like everything else that is not a token.
	//
	//	      - uses: actions/setup-go@<40 hex> # v7.1.0
	//	    uses: owner/repo/dir/of/an/action@<40 hex> # v0.2.0
	//	      - uses: actions/setup-go@v7.1.0
	//	      - uses: actions/checkout@v7.0.1 # why this step is here
	usesCommitRe = regexp.MustCompile(`^( *(?:- )?uses: )(` + namePat + `)(` + subPathPat + `)@(` + shaPat + `) # (` + versionPat + `)$`)
	usesTagRe    = regexp.MustCompile(`^( *(?:- )?uses: )(` + namePat + `)(` + subPathPat + `)@(` + versionPat + `)( +#[ -~]*)?$`)

	// The lines of actions.lock that a bump rewrites (schema v0.0.3, as
	// yaml.v3 writes it: four-space indent, single quotes):
	//
	//	workflows:
	//	    '.github/workflows/ci.yml':
	//	        - 'actions/setup-go@v7.1.0'        list line
	//	dependencies:
	//	    'actions/setup-go@v7.1.0':             key line
	//	        ref: 'v7.1.0'
	//	        commit: 'sha1-<40 hex>'
	//	        owner_id: 44036562
	//	        repo_id: 192624594
	//	        uses:
	//	            - 'actions/attest@<40 hex>'    list line
	//
	// A key names a tag, or a commit for an action that another action
	// uses. The four lines under a key are always these, in this order.
	lockListRe   = regexp.MustCompile(`^((?:    ){2,3}- )'(` + lockNamePat + `)@(` + versionPat + `|` + shaPat + `)'$`)
	lockKeyRe    = regexp.MustCompile(`^    '(` + lockNamePat + `)@(` + versionPat + `|` + shaPat + `)':$`)
	lockRefRe    = regexp.MustCompile(`^        ref: '(` + versionPat + `)'$`)
	lockCommitRe = regexp.MustCompile(`^        commit: 'sha1-(` + shaPat + `)'$`)
	lockOwnerRe  = regexp.MustCompile(`^        owner_id: ([1-9][0-9]{0,17})$`)
	lockRepoRe   = regexp.MustCompile(`^        repo_id: ([1-9][0-9]{0,17})$`)

	shaRe      = regexp.MustCompile(`^` + shaPat + `$`)
	safePathRe = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,200}$`)
	modeRe     = regexp.MustCompile(`^[0-7]{6}$`)
)

// pin is one update: an action repository moving from one commit to
// another, with the version each commit is labelled as.
type pin struct {
	// name is owner/repo as the workflow line spells it, or as the
	// lockfile does (lower case) for an entry no changed workflow line
	// names.
	name string
	// from and to are vX.Y.Z tags.
	from, to string
	// oldCommit and newCommit are 40 hex digits.
	oldCommit, newCommit string
	// locked says a changed actions.lock entry records this pin. Only
	// then are ownerID and repoID set: they are the repository's numeric
	// IDs as the lockfile has them at the base commit (the shape requires
	// the two lines to be unchanged).
	locked          bool
	ownerID, repoID int64
	// where is the first changed line that names the pin, "path:line".
	where string
}

// usesLine is one parsed pin line of a workflow or action file.
type usesLine struct {
	prefix  string // indentation, the optional "- ", and "uses: "
	name    string // owner/repo
	subPath string // "/dir/file" after the repository, or ""
	commit  string // 40 hex; "" in the tag form
	version string // vX.Y.Z
	comment string // a tag line's trailing " # ...", or ""
}

func parseUses(line string) (usesLine, bool) {
	var u usesLine
	if m := usesCommitRe.FindStringSubmatch(line); m != nil {
		u = usesLine{prefix: m[1], name: m[2], subPath: m[3], commit: m[4], version: m[5]}
	} else if m := usesTagRe.FindStringSubmatch(line); m != nil {
		u = usesLine{prefix: m[1], name: m[2], subPath: m[3], version: m[4], comment: m[5]}
	} else {
		return usesLine{}, false
	}
	// ValidRepo also refuses "." and ".." as a repository name.
	return u, gh.ValidRepo(u.name)
}

// lockName is the owner/repo@token of a lockfile key or list line.
type lockName struct {
	name     string // lower-case owner/repo
	token    string // vX.Y.Z or 40 hex
	isCommit bool
}

func (n lockName) key() string { return n.name + "@" + n.token }

func newLockName(name, token string) (lockName, bool) {
	return lockName{name: name, token: token, isCommit: shaRe.MatchString(token)}, gh.ValidRepo(name)
}

// lockEntry is one dependencies entry of actions.lock whose key changed.
type lockEntry struct {
	where                string
	old, new             lockName
	from, to             string // the ref lines
	oldCommit, newCommit string // the commit lines
	ownerID, repoID      int64
	// listed: a changed list line names this change. used: a changed
	// workflow line resolves to it.
	listed, used bool
}

// lockListChange is one changed list line of actions.lock.
type lockListChange struct {
	where    string
	old, new string // keys
}

// tagChange and commitChange are the changed lines of workflow and action
// files, in the tag form and in the commit form.
type tagChange struct {
	where, name, from, to string
}

type commitChange struct {
	where, name, from, to, oldCommit, newCommit string
}

// changes is everything the changed lines say, before the files are
// checked against each other.
type changes struct {
	tags    []tagChange
	commits []commitChange
	lists   []lockListChange
	entries []*lockEntry
}

// readChangeSet reads the pull request's files and returns the pins it
// moves. The second result is empty when the Shape fact holds; otherwise
// it says, in the gate's own words, what is not a pin update, and there
// are no pins. It never quotes a changed line: only validated tokens,
// paths and line numbers go into it.
func readChangeSet(files []facts.File) ([]pin, string) {
	if len(files) == 0 {
		return nil, "no file changed"
	}
	var ch changes
	for _, f := range files {
		isLock := f.Path == lockPath
		if !isLock && !workflowPathRe.MatchString(f.Path) && !actionPathRe.MatchString(f.Path) {
			return nil, "a changed file is not a workflow, an action.yml or actions.lock: " + safePath(f.Path)
		}
		if f.BaseMode != regularFile || f.HeadMode != regularFile {
			return nil, fmt.Sprintf("%s: not a regular file at both commits (mode %s at base, %s at head)", f.Path, safeMode(f.BaseMode), safeMode(f.HeadMode))
		}
		base := strings.Split(string(f.Base), "\n")
		head := strings.Split(string(f.Head), "\n")
		if len(base) != len(head) {
			return nil, f.Path + ": base and head have a different number of lines; a pin update replaces lines in place"
		}
		var problem string
		if isLock {
			problem = ch.readLock(f.Path, base, head)
		} else {
			problem = ch.readUses(f.Path, base, head)
		}
		if problem != "" {
			return nil, problem
		}
	}
	return ch.pins()
}

// readUses reads the changed lines of one workflow or action file. It
// returns the problem, or "".
func (ch *changes) readUses(path string, base, head []string) string {
	for i := range base {
		if base[i] == head[i] {
			continue
		}
		where := fmt.Sprintf("%s:%d", path, i+1)
		b, okBase := parseUses(base[i])
		h, okHead := parseUses(head[i])
		if !okBase || !okHead {
			return where + ": the changed line is not an action pin in an accepted shape at both commits"
		}
		if (b.commit == "") != (h.commit == "") {
			return where + ": the line changed between a commit pin and a tag pin"
		}
		if b.prefix != h.prefix || b.name != h.name || b.subPath != h.subPath || b.comment != h.comment {
			return where + ": more than the commit and version changed on the line"
		}
		if strings.HasPrefix(b.subPath, reusableWorkflowDir) {
			return where + ": the line pins a reusable workflow, which never merges without a person (the gate's own pin included)"
		}
		if b.commit == "" {
			ch.tags = append(ch.tags, tagChange{where: where, name: b.name, from: b.version, to: h.version})
		} else {
			ch.commits = append(ch.commits, commitChange{where: where, name: b.name, from: b.version, to: h.version, oldCommit: b.commit, newCommit: h.commit})
		}
	}
	return ""
}

// readLock reads the changed lines of actions.lock. A changed key line
// starts an entry, read by fixed offset; a changed ref or commit line is
// accepted nowhere else, so a commit that changes under an unchanged key
// (a tag that moved) is not a shape. It returns the problem, or "".
func (ch *changes) readLock(path string, base, head []string) string {
	inEntry := map[int]bool{} // ref and commit lines an entry accounted for
	for i := range base {
		if base[i] == head[i] || inEntry[i] {
			continue
		}
		where := fmt.Sprintf("%s:%d", path, i+1)

		if b := lockKeyRe.FindStringSubmatch(base[i]); b != nil {
			h := lockKeyRe.FindStringSubmatch(head[i])
			if h == nil {
				return where + ": a dependency key changed into something else"
			}
			e, problem := readLockEntry(where, base, head, i, b, h)
			if problem != "" {
				return problem
			}
			ch.entries = append(ch.entries, e)
			inEntry[i+1], inEntry[i+2] = true, true
			continue
		}

		if b := lockListRe.FindStringSubmatch(base[i]); b != nil {
			h := lockListRe.FindStringSubmatch(head[i])
			if h == nil {
				return where + ": a list line changed into something else"
			}
			old, okOld := newLockName(b[2], b[3])
			new, okNew := newLockName(h[2], h[3])
			if !okOld || !okNew || b[1] != h[1] || old.name != new.name || old.isCommit != new.isCommit {
				return where + ": more than the version or commit changed on the list line"
			}
			ch.lists = append(ch.lists, lockListChange{where: where, old: old.key(), new: new.key()})
			continue
		}

		return where + ": the changed line is not one a pin update rewrites (a list line, or a dependency key with its ref and commit)"
	}
	return ""
}

// readLockEntry reads the entry whose key line is line i (b and h are the
// key's matches at base and head).
func readLockEntry(where string, base, head []string, i int, b, h []string) (*lockEntry, string) {
	old, okOld := newLockName(b[1], b[2])
	new, okNew := newLockName(h[1], h[2])
	if !okOld || !okNew || old.name != new.name || old.isCommit != new.isCommit {
		return nil, where + ": more than the version or commit changed in the dependency key"
	}
	if i+4 >= len(base) {
		return nil, where + ": the dependency entry is cut short"
	}
	bRef, hRef := lockRefRe.FindStringSubmatch(base[i+1]), lockRefRe.FindStringSubmatch(head[i+1])
	bCommit, hCommit := lockCommitRe.FindStringSubmatch(base[i+2]), lockCommitRe.FindStringSubmatch(head[i+2])
	bOwner, bRepo := lockOwnerRe.FindStringSubmatch(base[i+3]), lockRepoRe.FindStringSubmatch(base[i+4])
	if bRef == nil || hRef == nil || bCommit == nil || hCommit == nil || bOwner == nil || bRepo == nil {
		return nil, where + ": the lines under the dependency key are not ref (a vX.Y.Z tag), commit, owner_id and repo_id"
	}
	// The IDs are the repository's identity. They are compared with what
	// GitHub reports now, so they must be the base commit's own.
	if base[i+3] != head[i+3] || base[i+4] != head[i+4] {
		return nil, where + ": owner_id or repo_id changed: the name would belong to another repository"
	}
	e := &lockEntry{where: where, old: old, new: new, from: bRef[1], to: hRef[1], oldCommit: bCommit[1], newCommit: hCommit[1]}
	if e.from == e.to {
		return nil, where + ": the dependency key changed and its ref did not"
	}
	if e.oldCommit == e.newCommit {
		return nil, where + ": the dependency key changed and its commit did not"
	}
	if old.isCommit {
		if old.token != e.oldCommit || new.token != e.newCommit {
			return nil, where + ": the commit in the dependency key is not the entry's commit"
		}
	} else if old.token != e.from || new.token != e.to {
		return nil, where + ": the tag in the dependency key is not the entry's ref"
	}
	var err error
	if e.ownerID, err = strconv.ParseInt(bOwner[1], 10, 64); err != nil {
		return nil, where + ": owner_id is not a number"
	}
	if e.repoID, err = strconv.ParseInt(bRepo[1], 10, 64); err != nil {
		return nil, where + ": repo_id is not a number"
	}
	return e, ""
}

// pins checks the changed lines against each other and returns one pin
// per (name, from, to), or the problem.
func (ch *changes) pins() ([]pin, string) {
	var pins []pin
	// Every changed list line must name exactly one changed entry, and
	// every changed entry must be named by one: an entry nothing lists is
	// not something the runner would use, and a list line that points at
	// an entry that did not change points at a commit this pull request
	// gives no old and new for.
	for _, l := range ch.lists {
		n := 0
		for _, e := range ch.entries {
			if e.old.key() == l.old && e.new.key() == l.new {
				e.listed = true
				n++
			}
		}
		if n != 1 {
			return nil, l.where + ": the list line does not match exactly one changed dependency entry"
		}
	}
	for _, e := range ch.entries {
		if !e.listed {
			return nil, e.where + ": the dependency entry changed and no workflow or uses list names the change"
		}
	}

	// add records a pin once. Two lines may name the same move; they must
	// then agree on the commits. A commit line that no lockfile entry
	// records takes the IDs of a tag line's entry for the same move: the
	// IDs belong to the repository name, and the name is the same.
	add := func(p pin) string {
		for i := range pins {
			q := &pins[i]
			if q.name != p.name || q.from != p.from || q.to != p.to {
				continue
			}
			if q.oldCommit != p.oldCommit || q.newCommit != p.newCommit {
				return p.where + ": the same action and versions are pinned to other commits elsewhere in this pull request"
			}
			if q.locked && p.locked && (q.ownerID != p.ownerID || q.repoID != p.repoID) {
				return p.where + ": two actions.lock entries record different IDs for the same action"
			}
			if p.locked && !q.locked {
				q.locked, q.ownerID, q.repoID = true, p.ownerID, p.repoID
			}
			return ""
		}
		pins = append(pins, p)
		return ""
	}

	// A tag line has no commit of its own: a changed lockfile entry under
	// the same tags must give it.
	for _, t := range ch.tags {
		name := strings.ToLower(t.name)
		var found *lockEntry
		n := 0
		for _, e := range ch.entries {
			if !e.old.isCommit && e.old.key() == name+"@"+t.from && e.new.key() == name+"@"+t.to {
				found = e
				n++
			}
		}
		if n != 1 {
			return nil, t.where + ": the line names a tag, and no changed actions.lock entry gives the commits for it"
		}
		found.used = true
		if problem := add(pin{name: t.name, from: t.from, to: t.to, oldCommit: found.oldCommit, newCommit: found.newCommit, locked: true, ownerID: found.ownerID, repoID: found.repoID, where: t.where}); problem != "" {
			return nil, problem
		}
	}

	// A commit line stands on its own. When the lockfile also records the
	// move (a commit-pinned step of an onboarded workflow), the two must
	// agree on the versions, and the entry supplies the repository's IDs.
	for _, c := range ch.commits {
		name := strings.ToLower(c.name)
		var found *lockEntry
		n := 0
		for _, e := range ch.entries {
			if e.old.isCommit && e.old.key() == name+"@"+c.oldCommit && e.new.key() == name+"@"+c.newCommit {
				found = e
				n++
			}
		}
		p := pin{name: c.name, from: c.from, to: c.to, oldCommit: c.oldCommit, newCommit: c.newCommit, where: c.where}
		switch {
		case n > 1:
			return nil, c.where + ": more than one changed actions.lock entry matches the line"
		case n == 1 && (found.from != c.from || found.to != c.to):
			return nil, c.where + ": the line's version comment and the actions.lock entry for the same commits name different versions"
		case n == 1:
			found.used = true
			p.locked, p.ownerID, p.repoID = true, found.ownerID, found.repoID
		}
		if problem := add(p); problem != "" {
			return nil, problem
		}
	}

	// An entry no changed workflow line resolves to is an action that a
	// bumped action uses, moved in place. It is an update like any other.
	for _, e := range ch.entries {
		if e.used {
			continue
		}
		if problem := add(pin{name: e.old.name, from: e.from, to: e.to, oldCommit: e.oldCommit, newCommit: e.newCommit, locked: true, ownerID: e.ownerID, repoID: e.repoID, where: e.where}); problem != "" {
			return nil, problem
		}
	}

	if len(pins) == 0 {
		return nil, "no line changed"
	}
	sort.SliceStable(pins, func(i, j int) bool {
		a, b := pins[i], pins[j]
		if a.name != b.name {
			return a.name < b.name
		}
		if a.from != b.from {
			return a.from < b.from
		}
		return a.to < b.to
	})
	return pins, ""
}

// safePath returns p when it is plain enough to show; a changed path is
// the pull request's text.
func safePath(p string) string {
	if safePathRe.MatchString(p) {
		return p
	}
	return "(a path with unusual characters)"
}

// safeMode returns a git mode for a message; an absent file has none.
func safeMode(m string) string {
	switch {
	case m == "":
		return "absent"
	case modeRe.MatchString(m):
		return m
	}
	return "unreadable"
}
