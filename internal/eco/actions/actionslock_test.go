package actions

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/sadbox/dep-review/internal/fetch"
	"github.com/sadbox/dep-review/internal/model"
)

const lockFixtures = "testdata/lockfile"

func readLockFixture(t *testing.T, parts ...string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(append([]string{lockFixtures}, parts...)...))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// lockRun commits before/after into a caller repository and runs the
// lockfile check on the uses: changes, as Fetch does.
func lockRun(t *testing.T, before, after map[string]string) (*findings, []usesChange) {
	fs, all, _ := lockRunMax(t, before, after, 8)
	return fs, all
}

func lockRunMax(t *testing.T, before, after map[string]string, maxTrans int) (*findings, []usesChange, []*transPair) {
	t.Helper()
	caller := t.TempDir()
	gitIn(t, caller, "init", "-q")
	base := commitTree(t, caller, before, "base")
	head := commitTree(t, caller, after, "head")
	var fs findings
	var all []usesChange
	lockChanged := false
	for p, nt := range after {
		ot := before[p]
		if ot == nt {
			continue
		}
		kind := fileKind(p)
		if kind == kindLock {
			lockChanged = true
			continue
		}
		ch, errs := usesChanges(p, kind, ot, nt)
		for _, e := range errs {
			fs.add(model.RouteRefuse, "actions.non-uses-change", "", "%s: %s", e.file, e.reason)
		}
		all = append(all, ch...)
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].file != all[j].file {
			return all[i].file < all[j].file
		}
		return all[i].line < all[j].line
	})
	var sum strings.Builder
	trans, err := checkActionsLock(context.Background(), git{bin: "git", dir: caller}, fetch.Env{Evidence: &memEvidence{}}, base, head, lockChanged, all, maxTrans, &fs, &sum)
	if err != nil {
		t.Fatal(err)
	}
	return &fs, all, trans
}

func fixtureTrees(t *testing.T, dir string) (before, after map[string]string) {
	before, after = map[string]string{}, map[string]string{}
	ents, err := os.ReadDir(filepath.Join(lockFixtures, dir, "old"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		before[".github/workflows/"+e.Name()] = readLockFixture(t, dir, "old", e.Name())
		after[".github/workflows/"+e.Name()] = readLockFixture(t, dir, "new", e.Name())
	}
	return before, after
}

func codesOf(fs *findings) (map[string]model.Route, string) {
	m := map[string]model.Route{}
	var lines []string
	for _, x := range fs.list {
		m[x.Code] = model.Worse(m[x.Code], x.Route)
		lines = append(lines, string(x.Route)+" "+x.Code+": "+x.Detail)
	}
	return m, strings.Join(lines, "\n")
}

// TestActionsLockRealPRs runs the lockfile check on lockfiles and
// workflows trimmed from public Dependabot github-actions PRs: each one
// raises nothing and resolves every locked line to the lockfile's commits.
// subpath: two codeql-action subpaths are one pin; two-old-versions: two
// workflows move from two checkout versions to one.
func TestActionsLockRealPRs(t *testing.T) {
	cases := []struct {
		dir   string
		locks int // locked uses: lines expected
	}{
		{dir: "simple", locks: 1},
		{dir: "subpath", locks: 2},
		{dir: "two-old-versions", locks: 2},
	}
	for _, tc := range cases {
		t.Run(tc.dir, func(t *testing.T) {
			before, after := fixtureTrees(t, tc.dir)
			fs, all, trans := lockRunMax(t, before, after, 8)
			if got, lines := codesOf(fs); len(got) != 0 {
				t.Errorf("findings %v\n%s", got, lines)
			}
			if len(trans) != 0 {
				t.Errorf("%d transitive pairs", len(trans))
			}
			n := 0
			for _, c := range all {
				if c.lock == nil {
					t.Errorf("%s:%d not resolved through actions.lock", c.file, c.line)
					continue
				}
				n++
				if !shaRx.MatchString(c.lock.oldCommit) || !shaRx.MatchString(c.lock.newCommit) || c.lock.oldCommit == c.lock.newCommit {
					t.Errorf("%s:%d: commits %q -> %q", c.file, c.line, c.lock.oldCommit, c.lock.newCommit)
				}
			}
			if n != tc.locks {
				t.Errorf("%d locked lines, want %d", n, tc.locks)
			}
		})
	}
}

// TestActionsLockTransitiveReal is a real bump of a composite
// (cli/gh-extension-precompile 2.1.0 -> 2.2.0) whose own pins changed.
// As committed the base is a v0.0.2 lockfile, which is refused; with the
// base at v0.0.3 every changed transitive entry pairs with its old
// version and nothing goes to a human from the lockfile alone: the pairs
// are analyzed like bumps.
func TestActionsLockTransitiveReal(t *testing.T) {
	before, after := fixtureTrees(t, "transitive")
	fs, _, _ := lockRunMax(t, before, after, 8)
	if got, lines := codesOf(fs); len(got) != 1 || got["actions.lock-unparsed"] != model.RouteRefuse {
		t.Errorf("v0.0.2 base: findings %v\n%s", got, lines)
	}
	lp := ".github/workflows/actions.lock"
	before[lp] = strings.Replace(before[lp], "version: 'v0.0.2'", "version: 'v0.0.3'", 1)
	fs, all, trans := lockRunMax(t, before, after, 8)
	if got, lines := codesOf(fs); len(got) != 0 {
		t.Errorf("findings %v\n%s", got, lines)
	}
	if len(all) != 1 || all[0].lock == nil || all[0].lock.newCommit != "76961aa3bd1123d0a6fd42d0a41aca0696937c39" {
		t.Errorf("resolution %+v", all)
	}
	var got []string
	for _, p := range trans {
		got = append(got, p.oldKey+" -> "+p.newKey+" ("+p.via+")")
	}
	want := []string{
		"actions/attest-build-provenance@v1 -> actions/attest-build-provenance@a2bbfa25375fe432b6a289bc6b6cd05ecd0c4c32 (cli/gh-extension-precompile@v2.2.0 > actions/attest-build-provenance@a2bbfa25375fe432b6a289bc6b6cd05ecd0c4c32)",
		"actions/setup-go@v5 -> actions/setup-go@4a3601121dd01d1626a1e23e37211e3254c1c06c (cli/gh-extension-precompile@v2.2.0 > actions/setup-go@4a3601121dd01d1626a1e23e37211e3254c1c06c)",
		"actions/attest@67422f5511b7ff725f4dbd6fb9bd2cd925c65a8d -> actions/attest@59d89421af93a897026c735860bf21b6eb4f7b26 (cli/gh-extension-precompile@v2.2.0 > actions/attest-build-provenance@a2bbfa25375fe432b6a289bc6b6cd05ecd0c4c32 > actions/attest@59d89421af93a897026c735860bf21b6eb4f7b26)",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("pairs:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// Over the cap nothing is analyzed and the transitive changes go to a human.
	fs, _, trans = lockRunMax(t, before, after, 2)
	if got, lines := codesOf(fs); len(trans) != 0 || got["actions.lock-transitive-cap"] != model.RouteHuman || got["actions.lock-transitive-changed"] != model.RouteHuman {
		t.Errorf("cap: %d pairs, findings %v\n%s", len(trans), got, lines)
	}
}

const synthLock = `# This file is machine-generated by ` + "`gh actions-lock`" + `.
# Do not edit by hand; run ` + "`gh actions-lock`" + ` to update.
# Docs: https://gh.io/actions-lockfile
version: 'v0.0.3'
workflows:
    '.github/workflows/ci.yml':
        - 'acme/act@v1.0.0'
        - 'acme/helper@v2.0.0'
        - 'other/tool@v3.0.0'
    '.github/workflows/idle.yml': []
dependencies:
    'acme/act@v1.0.0':
        ref: 'v1.0.0'
        commit: 'sha1-1111111111111111111111111111111111111111'
        owner_id: 1
        repo_id: 2
        uses:
            - 'acme/helper@v2.0.0'
    'acme/helper@v2.0.0':
        ref: 'v2.0.0'
        commit: 'sha1-2222222222222222222222222222222222222222'
        owner_id: 1
        repo_id: 3
    'other/tool@v3.0.0':
        ref: 'v3.0.0'
        commit: 'sha1-3333333333333333333333333333333333333333'
        owner_id: 4
        repo_id: 5
`

// synthBumped is synthLock after a clean acme/act 1.0.0 -> 1.0.1.
func synthBumped() string {
	s := strings.Replace(synthLock, "        - 'acme/act@v1.0.0'", "        - 'acme/act@v1.0.1'", 1)
	return strings.Replace(s, `    'acme/act@v1.0.0':
        ref: 'v1.0.0'
        commit: 'sha1-1111111111111111111111111111111111111111'`, `    'acme/act@v1.0.1':
        ref: 'v1.0.1'
        commit: 'sha1-4444444444444444444444444444444444444444'`, 1)
}

const synthWF = "name: ci\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-26.04\n    steps:\n      - uses: acme/act@%s\n      - uses: acme/helper@v2.0.0\n      - uses: other/tool@v3.0.0\n"

func synthWorkflow(ref string) string { return strings.Replace(synthWF, "%s", ref, 1) }

func TestParseActionsLock(t *testing.T) {
	lf, err := parseActionsLock([]byte(synthLock))
	if err != nil {
		t.Fatal(err)
	}
	if len(lf.workflows) != 2 || len(lf.workflows[".github/workflows/idle.yml"]) != 0 || len(lf.deps) != 3 ||
		lf.deps["acme/act@v1.0.0"].commit != "1111111111111111111111111111111111111111" || lf.deps["other/tool@v3.0.0"].repoID != 5 {
		t.Errorf("parsed %+v", lf)
	}
	ents, _ := os.ReadDir(lockFixtures)
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		for _, side := range []string{"old", "new"} {
			b, err := os.ReadFile(filepath.Join(lockFixtures, e.Name(), side, "actions.lock"))
			if err != nil {
				t.Fatal(err)
			}
			_, err = parseActionsLock(b)
			v002 := strings.Contains(string(b), "version: 'v0.0.2'")
			if (err != nil) != v002 {
				t.Errorf("%s/%s: err %v (v0.0.2 %t)", e.Name(), side, err, v002)
			}
		}
	}
}

// TestParseActionsLockRefuses covers forms that a YAML parser (GitHub's,
// gh-actions-lock's yaml.v3) may read differently from the gate, or that
// gh-actions-lock never writes.
func TestParseActionsLockRefuses(t *testing.T) {
	r := func(old, new string) string {
		if !strings.Contains(synthLock, old) {
			t.Fatalf("fixture lacks %q", old)
		}
		return strings.Replace(synthLock, old, new, 1)
	}
	actEntry := "    'acme/act@v1.0.0':\n        ref: 'v1.0.0'\n        commit: 'sha1-1111111111111111111111111111111111111111'\n        owner_id: 1\n        repo_id: 2\n        uses:\n            - 'acme/helper@v2.0.0'\n"
	helperEntry := "    'acme/helper@v2.0.0':\n        ref: 'v2.0.0'\n        commit: 'sha1-2222222222222222222222222222222222222222'\n        owner_id: 1\n        repo_id: 3\n"
	entry := "    'other/tool@v3.0.0':\n        ref: 'v3.0.0'\n        commit: 'sha1-3333333333333333333333333333333333333333'\n        owner_id: 4\n        repo_id: 5\n"
	cases := map[string]string{
		"duplicate dependency key":  synthLock + entry,
		"duplicate key, other case": r("    'acme/act@v1.0.0':\n", "    'Acme/act@v1.0.0':\n        ref: 'v1.0.0'\n        commit: 'sha1-1111111111111111111111111111111111111111'\n        owner_id: 1\n        repo_id: 2\n    'acme/act@v1.0.0':\n"),
		"upper-case repo":           strings.ReplaceAll(synthLock, "other/tool", "other/Tool"),
		"duplicate workflow key":    r("    '.github/workflows/idle.yml': []\n", "    '.github/workflows/idle.yml': []\n    '.github/workflows/idle.yml': []\n"),
		"case-folded workflow keys": r("    '.github/workflows/ci.yml':\n", "    '.github/workflows/CI.yml': []\n    '.github/workflows/ci.yml':\n"),
		"duplicate field":           r("        repo_id: 5\n", "        repo_id: 5\n        repo_id: 6\n"),
		"unsorted keys":             r(actEntry+helperEntry, helperEntry+actEntry),
		"unsorted list":             r("        - 'acme/act@v1.0.0'\n        - 'acme/helper@v2.0.0'\n", "        - 'acme/helper@v2.0.0'\n        - 'acme/act@v1.0.0'\n"),
		"double-quoted key":         r("    'other/tool@v3.0.0':", `    "other/tool@v3.0.0":`),
		"escaped key":               r("    'other/tool@v3.0.0':", `    "other/t\x6fol@v3.0.0":`),
		"doubled single quote":      r("ref: 'v3.0.0'", "ref: 'v3''0.0'"),
		"plain scalar":              r("ref: 'v3.0.0'", "ref: v3.0.0"),
		"hostname":                  r("    'other/tool@v3.0.0':\n", "    'other/tool@v3.0.0':\n        hostname: 'github.com'\n"),
		"unknown field":             r("        repo_id: 5\n", "        repo_id: 5\n        path: 'x'\n"),
		"fields out of order":       r("        owner_id: 4\n        repo_id: 5\n", "        repo_id: 5\n        owner_id: 4\n"),
		"v0.0.2":                    r("version: 'v0.0.3'", "version: 'v0.0.2'"),
		"future version":            r("version: 'v0.0.3'", "version: 'v0.0.4'"),
		"sha256 commit":             r("'sha1-3333333333333333333333333333333333333333'", "'sha256-3333333333333333333333333333333333333333333333333333333333333333'"),
		"upper-case hex":            r("'sha1-3333333333333333333333333333333333333333'", "'sha1-333333333333333333333333333333333333333A'"),
		"leading-zero id":           r("owner_id: 4\n", "owner_id: 04\n"),
		"quoted id":                 r("owner_id: 4\n", "owner_id: '4'\n"),
		"hex id":                    r("owner_id: 4\n", "owner_id: 0x4\n"),
		"flow list":                 r("    '.github/workflows/idle.yml': []", "    '.github/workflows/idle.yml': ['other/tool@v3.0.0']"),
		"block list for idle":       r("    '.github/workflows/idle.yml': []", "    '.github/workflows/idle.yml':"),
		"comment mid-file":          r("dependencies:\n", "dependencies:\n    # hi\n"),
		"trailing comment":          r("ref: 'v3.0.0'", "ref: 'v3.0.0' # x"),
		"blank line":                r("dependencies:\n", "\ndependencies:\n"),
		"lone CR":                   r("        repo_id: 5\n", "        repo_id: 5\r        uses:\n"),
		"CRLF":                      strings.ReplaceAll(synthLock, "\n", "\r\n"),
		"NEL":                       r("ref: 'v3.0.0'", "ref: 'v3.0.0\u0085'"),
		"LS":                        r("ref: 'v3.0.0'", "ref: 'v3.0.0\u2028'"),
		"PS":                        r("ref: 'v3.0.0'", "ref: 'v3.0.0\u2029'"),
		"tab":                       r("        repo_id: 5\n", "        repo_id:\t5\n"),
		"BOM":                       "\ufeff" + synthLock,
		"anchor":                    r("    'other/tool@v3.0.0':", "    'other/tool@v3.0.0': &a"),
		"merge key":                 r("        repo_id: 5\n", "        repo_id: 5\n        <<: *a\n"),
		"tag":                       r("ref: 'v3.0.0'", "ref: !!str 'v3.0.0'"),
		"second document":           synthLock + "---\nversion: 'v0.0.3'\n",
		"no final newline":          strings.TrimSuffix(synthLock, "\n"),
		"dangling workflow pin":     r("        - 'other/tool@v3.0.0'\n", "        - 'other/tool@v3.0.0'\n        - 'zz/missing@v1.0.0'\n"),
		"dangling uses pin":         r("            - 'acme/helper@v2.0.0'\n", "            - 'acme/helper@v2.0.0'\n            - 'zz/missing@v1.0.0'\n"),
		"key ref differs from ref":  r("ref: 'v3.0.0'", "ref: 'v3.0.1'"),
		"sha key differs":           strings.ReplaceAll(synthLock, "other/tool@v3.0.0", "other/tool@5555555555555555555555555555555555555555"),
		"cycle":                     r("        repo_id: 3\n", "        repo_id: 3\n        uses:\n            - 'acme/act@v1.0.0'\n"),
		"workflow outside dir":      r("'.github/workflows/idle.yml'", "'.github/workflows/sub/idle.yml'"),
		"two-space indent":          strings.ReplaceAll(synthLock, "    ", "  "),
		"empty":                     "",
	}
	// Why each case is refused: the check that must catch it.
	why := map[string]string{
		"duplicate dependency key":  "dependency keys not sorted, or a duplicate",
		"duplicate key, other case": "not a canonical lower-case",
		"upper-case repo":           "not a canonical lower-case",
		"duplicate workflow key":    "workflow keys not sorted, or a duplicate",
		"case-folded workflow keys": "differ only in case",
		"duplicate field":           "unexpected line",
		"unsorted keys":             "dependency keys not sorted",
		"unsorted list":             "not sorted or not unique",
		"double-quoted key":         "double quote",
		"escaped key":               "double quote or backslash",
		"doubled single quote":      ": ref",
		"plain scalar":              ": ref",
		"hostname":                  "expected ref",
		"unknown field":             "unexpected line",
		"fields out of order":       "expected owner_id",
		"v0.0.2":                    "schema version is not v0.0.3",
		"future version":            "schema version is not v0.0.3",
		"sha256 commit":             "commit is not sha1-",
		"upper-case hex":            "commit is not sha1-",
		"leading-zero id":           "owner_id is not a positive integer",
		"quoted id":                 "owner_id is not a positive integer",
		"hex id":                    "owner_id is not a positive integer",
		"flow list":                 "workflow key",
		"block list for idle":       "empty list",
		"comment mid-file":          "empty dependencies",
		"trailing comment":          ": ref",
		"blank line":                "unexpected line",
		"lone CR":                   "CR without LF",
		"CRLF":                      "CR, tab",
		"NEL":                       "U+0085",
		"LS":                        "U+2028",
		"PS":                        "U+2029",
		"tab":                       "CR, tab",
		"BOM":                       "expected version",
		"anchor":                    "dependency key",
		"merge key":                 "unexpected line",
		"tag":                       ": ref",
		"second document":           "unexpected line",
		"no final newline":          "no final newline",
		"dangling workflow pin":     "names a pin with no dependencies entry",
		"dangling uses pin":         "uses a pin with no dependencies entry",
		"key ref differs from ref":  "ref differs from the ref in its key",
		"sha key differs":           "commit differs from the SHA in its key",
		"cycle":                     "uses cycle",
		"workflow outside dir":      "workflow path",
		"two-space indent":          "empty workflows",
		"empty":                     "no final newline",
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := parseActionsLock([]byte(text))
			if err == nil {
				t.Fatalf("accepted:\n%s", text)
			}
			if !errors.Is(err, errLockFormat) && !errors.Is(err, errLineBreak) {
				t.Errorf("error %v is neither a format nor a line-break error", err)
			}
			if w, ok := why[name]; !ok || !strings.Contains(err.Error(), w) {
				t.Errorf("refused for %q, want %q", err, w)
			}
		})
	}
	// The same key forms accepted: a SHA key whose commit agrees.
	sha := strings.ReplaceAll(strings.Replace(synthLock, "sha1-3333333333333333333333333333333333333333", "sha1-5555555555555555555555555555555555555555", 1), "other/tool@v3.0.0", "other/tool@5555555555555555555555555555555555555555")
	if _, err := parseActionsLock([]byte(sha)); err != nil {
		t.Errorf("SHA key: %v", err)
	}
}

func TestActionsLockDelta(t *testing.T) {
	const lp = ".github/workflows/actions.lock"
	const wfp = ".github/workflows/ci.yml"
	base := map[string]string{lp: synthLock, wfp: synthWorkflow("v1.0.0")}
	cases := []struct {
		name          string
		before, after map[string]string
		codes         map[string]model.Route
		pairs         []string // transitive pairs, "old key -> new key"
	}{
		{name: "clean", after: map[string]string{lp: synthBumped(), wfp: synthWorkflow("v1.0.1")}},
		{name: "mixed-case uses: maps to the lower-case key",
			before: map[string]string{lp: synthLock, wfp: strings.Replace(synthWorkflow("v1.0.0"), "uses: acme/act@", "uses: Acme/Act@", 1)},
			after:  map[string]string{lp: synthBumped(), wfp: strings.Replace(synthWorkflow("v1.0.1"), "uses: acme/act@", "uses: Acme/Act@", 1)}},
		{name: "uses and lockfile disagree", after: map[string]string{lp: synthBumped(), wfp: synthWorkflow("v1.0.2")},
			codes: map[string]model.Route{"actions.lock-uses-mismatch": model.RouteRefuse, "actions.lock-unexplained-change": model.RouteHuman}},
		{name: "lockfile not updated", after: map[string]string{lp: synthLock, wfp: synthWorkflow("v1.0.1")},
			codes: map[string]model.Route{"actions.lock-not-updated": model.RouteRefuse}},
		{name: "lockfile only", after: map[string]string{lp: synthBumped(), wfp: synthWorkflow("v1.0.0")},
			codes: map[string]model.Route{"actions.lock-unexpected-change": model.RouteRefuse}},
		{name: "unrelated entry moves", after: map[string]string{lp: strings.Replace(synthBumped(), "sha1-3333333333333333333333333333333333333333", "sha1-6666666666666666666666666666666666666666", 1), wfp: synthWorkflow("v1.0.1")},
			codes: map[string]model.Route{"actions.lock-unexplained-change": model.RouteHuman}},
		{name: "unrelated entry added", after: map[string]string{lp: strings.Replace(synthBumped(), "    'other/tool@v3.0.0':\n", "    'other/new@v1.0.0':\n        ref: 'v1.0.0'\n        commit: 'sha1-7777777777777777777777777777777777777777'\n        owner_id: 4\n        repo_id: 9\n    'other/tool@v3.0.0':\n", 1), wfp: synthWorkflow("v1.0.1")},
			codes: map[string]model.Route{"actions.lock-unexplained-change": model.RouteHuman}},
		// A transitive entry at a new commit is a pair Fetch analyzes.
		{name: "transitive entry moves", after: map[string]string{lp: strings.Replace(synthBumped(), "sha1-2222222222222222222222222222222222222222", "sha1-8888888888888888888888888888888888888888", 1), wfp: synthWorkflow("v1.0.1")},
			pairs: []string{"acme/helper@v2.0.0 -> acme/helper@v2.0.0"}},
		{name: "transitive entry moves to another repository's IDs", after: map[string]string{lp: strings.Replace(strings.Replace(synthBumped(), "sha1-2222222222222222222222222222222222222222", "sha1-8888888888888888888888888888888888888888", 1), "        repo_id: 3\n", "        repo_id: 30\n", 1), wfp: synthWorkflow("v1.0.1")},
			codes: map[string]model.Route{"actions.lock-identity-changed": model.RouteHuman}, pairs: []string{"acme/helper@v2.0.0 -> acme/helper@v2.0.0"}},
		// A pin the bumped entry dropped, or a pair's old key, explains only
		// its own removal: if it stays in the lockfile at another commit,
		// that change is not analyzed and must not be accepted.
		{name: "dropped transitive pin stays and moves", after: map[string]string{lp: strings.Replace(strings.Replace(synthBumped(), "        repo_id: 2\n        uses:\n            - 'acme/helper@v2.0.0'\n", "        repo_id: 2\n", 1), "sha1-2222222222222222222222222222222222222222", "sha1-8888888888888888888888888888888888888888", 1), wfp: synthWorkflow("v1.0.1")},
			codes: map[string]model.Route{"actions.lock-entry-moved": model.RouteHuman}},
		{name: "old key of a transitive pair stays and moves", after: map[string]string{lp: strings.Replace(strings.Replace(strings.Replace(synthBumped(),
			"            - 'acme/helper@v2.0.0'\n", "            - 'acme/helper@v2.0.1'\n", 1),
			"sha1-2222222222222222222222222222222222222222", "sha1-8888888888888888888888888888888888888888", 1),
			"    'other/tool@v3.0.0':\n", "    'acme/helper@v2.0.1':\n        ref: 'v2.0.1'\n        commit: 'sha1-9999999999999999999999999999999999999999'\n        owner_id: 1\n        repo_id: 3\n    'other/tool@v3.0.0':\n", 1), wfp: synthWorkflow("v1.0.1")},
			codes: map[string]model.Route{"actions.lock-entry-moved": model.RouteHuman}, pairs: []string{"acme/helper@v2.0.0 -> acme/helper@v2.0.1"}},
		// An entry the base locked as is: no new code, so no pair (the
		// composite's nested-uses finding still routes it at fetch time).
		{name: "bumped action gains an already locked pin", after: map[string]string{lp: strings.Replace(synthBumped(), "            - 'acme/helper@v2.0.0'\n", "            - 'acme/helper@v2.0.0'\n            - 'other/tool@v3.0.0'\n", 1), wfp: synthWorkflow("v1.0.1")}},
		{name: "bumped action gains a new repository", after: map[string]string{lp: strings.Replace(strings.Replace(synthBumped(), "            - 'acme/helper@v2.0.0'\n", "            - 'acme/helper@v2.0.0'\n            - 'other/new@v1.0.0'\n", 1), "    'other/tool@v3.0.0':\n", "    'other/new@v1.0.0':\n        ref: 'v1.0.0'\n        commit: 'sha1-7777777777777777777777777777777777777777'\n        owner_id: 4\n        repo_id: 9\n    'other/tool@v3.0.0':\n", 1), wfp: synthWorkflow("v1.0.1")},
			codes: map[string]model.Route{"actions.lock-transitive-added": model.RouteHuman, "actions.lock-transitive-changed": model.RouteHuman}},
		{name: "bumped action uses two pins of one repository", after: map[string]string{lp: strings.Replace(strings.Replace(synthBumped(), "            - 'acme/helper@v2.0.0'\n", "            - 'acme/helper@v2.0.0'\n            - 'acme/helper@v2.0.1'\n", 1), "    'other/tool@v3.0.0':\n", "    'acme/helper@v2.0.1':\n        ref: 'v2.0.1'\n        commit: 'sha1-7777777777777777777777777777777777777777'\n        owner_id: 1\n        repo_id: 3\n    'other/tool@v3.0.0':\n", 1), wfp: synthWorkflow("v1.0.1")},
			codes: map[string]model.Route{"actions.lock-transitive-ambiguous": model.RouteHuman, "actions.lock-transitive-changed": model.RouteHuman}},
		{name: "identity changes", after: map[string]string{lp: strings.Replace(synthBumped(), "        commit: 'sha1-4444444444444444444444444444444444444444'\n        owner_id: 1\n        repo_id: 2\n", "        commit: 'sha1-4444444444444444444444444444444444444444'\n        owner_id: 1\n        repo_id: 99\n", 1), wfp: synthWorkflow("v1.0.1")},
			codes: map[string]model.Route{"actions.lock-identity-changed": model.RouteHuman}},
		{name: "onboarding changes", after: map[string]string{lp: strings.Replace(synthBumped(), "    '.github/workflows/idle.yml': []\n", "", 1), wfp: synthWorkflow("v1.0.1")},
			codes: map[string]model.Route{"actions.lock-onboarding-changed": model.RouteRefuse}},
		{name: "floating tag", after: map[string]string{lp: strings.Replace(strings.ReplaceAll(synthLock, "acme/act@v1.0.0", "acme/act@v1"), "ref: 'v1.0.0'", "ref: 'v1'", 1), wfp: synthWorkflow("v1")},
			codes: map[string]model.Route{"actions.lock-ref-not-exact": model.RouteRefuse}},
		{name: "malformed head lockfile", after: map[string]string{lp: strings.Replace(synthBumped(), "ref: 'v3.0.0'", "ref: \"v3.0.0\"", 1), wfp: synthWorkflow("v1.0.1")},
			codes: map[string]model.Route{"actions.lock-unparsed": model.RouteRefuse}},
		{name: "duplicate key in head lockfile", after: map[string]string{lp: synthBumped() + "    'other/tool@v3.0.0':\n        ref: 'v3.0.0'\n        commit: 'sha1-9999999999999999999999999999999999999999'\n        owner_id: 4\n        repo_id: 5\n", wfp: synthWorkflow("v1.0.1")},
			codes: map[string]model.Route{"actions.lock-unparsed": model.RouteRefuse}},
		{name: "lone CR in head lockfile", after: map[string]string{lp: strings.Replace(synthBumped(), "        repo_id: 5\n", "        repo_id: 5\r", 1), wfp: synthWorkflow("v1.0.1")},
			codes: map[string]model.Route{codeLineBreak: model.RouteRefuse}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := base
			if tc.before != nil {
				before = tc.before
			}
			fs, all, trans := lockRunMax(t, before, tc.after, 8)
			var pairs []string
			for _, p := range trans {
				pairs = append(pairs, p.oldKey+" -> "+p.newKey)
			}
			if strings.Join(pairs, ",") != strings.Join(tc.pairs, ",") {
				t.Errorf("pairs %v, want %v", pairs, tc.pairs)
			}
			got, lines := codesOf(fs)
			want := tc.codes
			if want == nil {
				want = map[string]model.Route{}
			}
			if len(got) != len(want) {
				t.Errorf("findings %v, want %v\n%s", got, want, lines)
			}
			for c, r := range want {
				if got[c] != r {
					t.Errorf("finding %s = %q, want %q\n%s", c, got[c], r, lines)
				}
			}
			if (tc.name == "clean" || strings.HasPrefix(tc.name, "mixed-case")) && (len(all) != 1 || all[0].lock == nil || all[0].lock.newCommit != "4444444444444444444444444444444444444444" || all[0].lock.oldCommit != "1111111111111111111111111111111111111111") {
				t.Errorf("resolution %+v", all)
			}
		})
	}
}

// A job-level reusable-workflow call is not covered by the lockfile: in an
// onboarded workflow it stays SHA-pinned and needs no lockfile change.
func TestActionsLockSkipsJobLevelUses(t *testing.T) {
	const lp = ".github/workflows/actions.lock"
	const wfp = ".github/workflows/ci.yml"
	wf := func(sha string) string {
		return synthWorkflow("v1.0.0") + "  release:\n    uses: acme/flows/.github/workflows/release.yml@" + sha + " # v2.0.0\n"
	}
	fs, all := lockRun(t, map[string]string{lp: synthLock, wfp: wf("1111111111111111111111111111111111111111")},
		map[string]string{lp: synthLock, wfp: wf("2222222222222222222222222222222222222222")})
	if got, lines := codesOf(fs); len(got) != 0 {
		t.Errorf("findings %v\n%s", got, lines)
	}
	if len(all) != 1 || !all[0].job || all[0].lock != nil {
		t.Errorf("changes %+v", all)
	}
}
