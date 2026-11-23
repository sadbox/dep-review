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
// The regular expressions only find the tokens; the safety is in the
// equality of everything else. Lines that did not change are not judged.
// Of actions.lock's, the section lines and the workflow keys are read all
// the same, because they say whose list a changed list line is in (spec
// section 11, amendment 42).

// lockPath is the workflow lockfile `gh actions-lock` writes.
const lockPath = ".github/workflows/actions.lock"

// lockSchema is the first line after the comments of an actions.lock in
// the one schema the entry shapes below were written for. A file that
// declares another may lay its entries out differently, and is not read.
const lockSchema = "version: 'v0.0.3'"

// reusableWorkflowDir starts the path of a `uses:` that calls a reusable
// workflow: a file in the called repository's .github/workflows. A
// workflow is not an action. It runs as jobs of its own, with whatever
// secrets and permissions the caller passes, and the gate's own workflow
// is one, so a change to such a pin is never granted (spec section 11,
// amendment 6). Anything under that directory counts, not only *.yml, so
// that nothing a runner might still take for a workflow slips by.
const reusableWorkflowDir = "/.github/workflows/"

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
	// A workflow as GitHub reads it: top level of .github/workflows only.
	workflowPathRe = regexp.MustCompile(`^\.github/workflows/[A-Za-z0-9._-]{1,200}\.ya?ml$`)

	// The pin line of a workflow. Spaces only, one optional "- ", no
	// quotes. A tag pin is the one form that is read: actions.lock holds
	// its commit. It may end in a comment of printable ASCII, which must
	// be the same at both commits like everything else that is not a
	// token. A commit pin with its version in the comment is recognised
	// only to say why it is refused.
	//
	//	      - uses: actions/setup-go@v7.1.0
	//	      - uses: actions/checkout@v7.0.1 # why this step is here
	//	    uses: owner/repo/.github/workflows/ci.yml@<40 hex> # v0.2.0
	usesRe = regexp.MustCompile(`^( *(?:- )?uses: )(` + namePat + `)(` + subPathPat + `)@(?:(` + versionPat + `)( +#[ -~]*)?|` + shaPat + ` # ` + versionPat + `)$`)

	// The lines of actions.lock that a bump rewrites (as yaml.v3 writes
	// them: four-space indent, single quotes), and the workflow key that
	// says whose list a list line is in:
	//
	//	workflows:
	//	    '.github/workflows/ci.yml':            workflow key
	//	        - 'actions/setup-go@v7.1.0'        list line
	//	    '.github/workflows/notify.yml': []     workflow key, no action used
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
	// uses. The four lines under a key are always these, in this order. A
	// workflow key is never a changed line; it takes the paths that
	// workflowPathRe does.
	lockListRe     = regexp.MustCompile(`^((?:    ){2,3}- )'(` + lockNamePat + `)@(` + versionPat + `|` + shaPat + `)'$`)
	lockWorkflowRe = regexp.MustCompile(`^    '(\.github/workflows/[A-Za-z0-9._-]{1,200}\.ya?ml)':( \[\])?$`)
	lockKeyRe      = regexp.MustCompile(`^    '(` + lockNamePat + `)@(` + versionPat + `|` + shaPat + `)':$`)
	lockRefRe      = regexp.MustCompile(`^        ref: '(` + versionPat + `)'$`)
	lockCommitRe   = regexp.MustCompile(`^        commit: 'sha1-(` + shaPat + `)'$`)
	lockOwnerRe    = regexp.MustCompile(`^        owner_id: ([1-9][0-9]{0,17})$`)
	lockRepoRe     = regexp.MustCompile(`^        repo_id: ([1-9][0-9]{0,17})$`)

	shaRe = regexp.MustCompile(`^` + shaPat + `$`)
)

// workflowList is the indentation of a list line under `workflows:`, and
// usesList that of one under a dependency's `uses:`.
const (
	workflowList = "        - "
	usesList     = "            - "
)

// The two sections of actions.lock, each opened by its own line at the
// left margin.
const (
	workflowsSection    = "workflows:"
	dependenciesSection = "dependencies:"
)

// pin is one update: an action repository moving from one commit to
// another, with the version each commit is labelled as.
type pin struct {
	// name is owner/repo as the workflow line spells it, or as the
	// lockfile does (lower case) for an entry no workflow line names.
	name string
	// from and to are vX.Y.Z tags.
	from, to string
	// oldCommit and newCommit are 40 hex digits.
	oldCommit, newCommit string
	// ownerID and repoID are the repository's numeric IDs as actions.lock
	// has them at the base commit (the shape requires the two lines to be
	// unchanged).
	ownerID, repoID int64
	// where is the first changed line that names the pin, "path:line".
	where string
}

// usesLine is one parsed pin line of a workflow.
type usesLine struct {
	prefix  string // indentation, the optional "- ", and "uses: "
	name    string // owner/repo
	subPath string // "/dir/file" after the repository, or ""
	version string // vX.Y.Z; "" for a commit pin
	comment string // a tag pin's trailing " # ...", or ""
}

func parseUses(line string) (usesLine, bool) {
	m := usesRe.FindStringSubmatch(line)
	if m == nil {
		return usesLine{}, false
	}
	// ValidRepo also refuses "." and ".." as a repository name.
	return usesLine{prefix: m[1], name: m[2], subPath: m[3], version: m[4], comment: m[5]}, gh.ValidRepo(m[2])
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
	// workflow is the path of the workflow whose list the line is in, as
	// the lockfile keys it. It is empty for a line of a dependency's uses
	// list.
	workflow string
	// entry is the one changed dependency entry the line names.
	entry *lockEntry
}

// tagChange is one changed pin line of a workflow.
type tagChange struct {
	where string
	// path is the workflow file the line is in.
	path           string
	name, from, to string
}

// changes is everything the changed lines say, before the files are
// checked against each other.
type changes struct {
	tags    []tagChange
	lists   []lockListChange
	entries []*lockEntry
	// workflows is every workflow path the lockfile's workflows section
	// has a key for. It is nil when actions.lock is not a changed file.
	workflows map[string]bool
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
		if !isLock && !workflowPathRe.MatchString(f.Path) {
			return nil, "a changed file is not a workflow or actions.lock: " + facts.Show(f.Path)
		}
		if problem := facts.NotRegular(f); problem != "" {
			return nil, problem
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

// readUses reads the changed lines of one workflow. It returns the
// problem, or "".
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
		if b.prefix != h.prefix || b.name != h.name || b.subPath != h.subPath || b.comment != h.comment {
			return where + ": more than the commit and version changed on the line"
		}
		if strings.HasPrefix(b.subPath, reusableWorkflowDir) {
			return where + ": the line pins a reusable workflow, which never merges without a person (the gate's own pin included)"
		}
		if b.version == "" || h.version == "" {
			// A workflow line records no repository IDs, and the IDs are
			// the defence against a name that someone else registered
			// again. Only a tag pin has an actions.lock entry to give them.
			return where + ": the line pins a commit; only a tag pin that actions.lock records is read"
		}
		ch.tags = append(ch.tags, tagChange{where: where, path: path, name: b.name, from: b.version, to: h.version})
	}
	return ""
}

// schemaLine is the first line of an actions.lock that is not a comment.
func schemaLine(lines []string) string {
	for _, line := range lines {
		if !strings.HasPrefix(line, "#") {
			return line
		}
	}
	return ""
}

// readLock reads actions.lock. Of the lines that did not change it takes
// only where they are: which section, and in the workflows section under
// which workflow's key. A changed key line starts an entry, read by fixed
// offset; a changed ref or commit line is accepted nowhere else, so a
// commit that changes under an unchanged key (a tag that moved) is not a
// shape. A changed list line is in the list of the workflow whose key is
// above it, or in a dependency's uses list. It returns the problem, or "".
func (ch *changes) readLock(path string, base, head []string) string {
	if schemaLine(base) != lockSchema || schemaLine(head) != lockSchema {
		return path + ": the file does not start with " + lockSchema + ", the one lockfile schema the gate reads"
	}
	ch.workflows = map[string]bool{}
	// section is the section line the walk is below: "" before the first,
	// and after any other line at the left margin. workflow is the path
	// in the workflow key the walk is below, "" when the lines here are
	// not known to be one workflow's list. Only unchanged lines move
	// either: a changed line is a list line or a dependency entry, which
	// open nothing, or it is refused.
	var section, workflow string
	opened := map[string]bool{}
	inEntry := map[int]bool{} // ref and commit lines an entry accounted for
	for i := range base {
		line := base[i]
		where := fmt.Sprintf("%s:%d", path, i+1)
		if line == head[i] {
			switch {
			case line == workflowsSection || line == dependenciesSection:
				if opened[line] {
					return where + ": the file has the same section twice"
				}
				opened[line] = true
				section, workflow = line, ""
			case line != "" && line[0] != ' ' && line[0] != '#':
				section, workflow = "", ""
			case section == workflowsSection:
				if m := lockWorkflowRe.FindStringSubmatch(line); m != nil {
					if ch.workflows[m[1]] {
						return where + ": the workflows section has the same workflow twice"
					}
					ch.workflows[m[1]] = true
					workflow = m[1]
					if m[2] != "" {
						// The empty list is on the key's line: no line
						// below is in it.
						workflow = ""
					}
				} else if !strings.HasPrefix(line, workflowList) {
					// Not an item of the list above: what follows is no
					// longer known to be in it.
					workflow = ""
				}
			}
			continue
		}
		if inEntry[i] {
			continue
		}

		if b := lockKeyRe.FindStringSubmatch(line); b != nil {
			h := lockKeyRe.FindStringSubmatch(head[i])
			if h == nil {
				return where + ": a dependency key changed into something else"
			}
			e, problem := readLockEntry(where, base, head, i, b, h)
			if problem != "" {
				return problem
			}
			if section != dependenciesSection {
				return where + ": a dependency key changed outside the dependencies section"
			}
			ch.entries = append(ch.entries, e)
			inEntry[i+1], inEntry[i+2] = true, true
			continue
		}

		if b := lockListRe.FindStringSubmatch(line); b != nil {
			h := lockListRe.FindStringSubmatch(head[i])
			if h == nil {
				return where + ": a list line changed into something else"
			}
			old, okOld := newLockName(b[2], b[3])
			new, okNew := newLockName(h[2], h[3])
			if !okOld || !okNew || b[1] != h[1] || old.name != new.name || old.isCommit != new.isCommit {
				return where + ": more than the version or commit changed on the list line"
			}
			l := lockListChange{where: where, old: old.key(), new: new.key()}
			switch {
			case b[1] == workflowList && section == workflowsSection && workflow != "":
				if old.isCommit {
					// Workflow lines are read as tag pins only, so no line
					// the gate reads could name this commit.
					return where + ": a workflow's list names a commit; only tag pins are read"
				}
				l.workflow = workflow
			case b[1] == usesList && section == dependenciesSection:
			default:
				// Whose list the line is in decides what it pins, and
				// the indentation alone does not say.
				return where + ": the list line is neither in the list of a workflow the workflows section names nor in a dependency's uses list"
			}
			ch.lists = append(ch.lists, l)
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
	// Every changed list line must name exactly one changed entry, and
	// every changed entry must be named by one: an entry nothing lists is
	// not something the runner would use, and a list line that points at
	// an entry that did not change points at a commit this pull request
	// gives no old and new for.
	for i := range ch.lists {
		l := &ch.lists[i]
		n := 0
		for _, e := range ch.entries {
			if e.old.key() == l.old && e.new.key() == l.new {
				e.listed = true
				l.entry = e
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

	// add records a pin once. A tag-keyed and a commit-keyed entry may
	// record the same move; they must then agree.
	var pins []pin
	add := func(e *lockEntry, name, where string) string {
		p := pin{name: name, from: e.from, to: e.to, oldCommit: e.oldCommit, newCommit: e.newCommit, ownerID: e.ownerID, repoID: e.repoID, where: where}
		for _, q := range pins {
			if q.name != p.name || q.from != p.from || q.to != p.to {
				continue
			}
			if q.oldCommit != p.oldCommit || q.newCommit != p.newCommit {
				return where + ": the same action and versions are pinned to other commits elsewhere in this pull request"
			}
			if q.ownerID != p.ownerID || q.repoID != p.repoID {
				return where + ": two actions.lock entries record different IDs for the same action"
			}
			return ""
		}
		pins = append(pins, p)
		return ""
	}

	// A workflow line has no commit of its own: a changed lockfile entry
	// under the same tags must give it.
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
		// The lockfile says what a workflow runs in that workflow's own
		// list. An entry with the line's name and versions that only
		// another workflow's list moves to is not this line's: the
		// lockfile would not say that this workflow runs the commit Bound
		// is checked for, and for a workflow it does not list at all it
		// says nothing.
		if !ch.workflows[t.path] {
			return nil, t.where + ": actions.lock has no list for this workflow, so no lock entry is tied to the line"
		}
		tied := false
		for _, l := range ch.lists {
			if l.workflow == t.path && l.entry == found {
				tied = true
			}
		}
		if !tied {
			return nil, t.where + ": this workflow's own list in actions.lock does not move to the tag the line names"
		}
		found.used = true
		if problem := add(found, t.name, t.where); problem != "" {
			return nil, problem
		}
	}

	for _, e := range ch.entries {
		if e.used {
			continue
		}
		if !e.old.isCommit {
			// The lockfile would say a workflow runs a version that the
			// workflow's own file does not name.
			return nil, e.where + ": the dependency entry moves a tag that no changed workflow line names"
		}
		// A commit-keyed entry is an action that a bumped action uses,
		// moved in place. It is an update like any other.
		if problem := add(e, e.old.name, e.where); problem != "" {
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
