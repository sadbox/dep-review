package gomod

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/module"

	"github.com/sadbox/dep-review/internal/advisory"
	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/artifact"
	"github.com/sadbox/dep-review/internal/facts"
)

// The pull request most of these tests gather for is pr(baseMod,
// headMod, baseSum, headSum) from shape_test.go: golang.org/x/text moves
// from v0.3.2 to v0.3.3 and golang.org/x/mod is new at v0.5.1. The go
// command's answers and the index pages for it are the recorded ones.

// goFixtures is the recorded go command for that pull request.
func goFixtures(t *testing.T) *fakeTool {
	return &fakeTool{t: t, files: map[string]string{
		"mod download -json -- golang.org/x/mod@v0.5.1 golang.org/x/text@v0.3.3":                      "download.json",
		"list -m -e -u -retracted -json -- golang.org/x/mod@v0.5.1 golang.org/x/text@v0.3.3":          "list_targets.json",
		"list -m -e -versions -json -- golang.org/x/mod golang.org/x/text":                            "list_versions.json",
		"list -m -e -json -- golang.org/x/mod@v0.1.0 golang.org/x/mod@v0.2.0 golang.org/x/mod@v0.3.0": "list_earliest.json",
	}, inline: map[string]string{}, errs: map[string]error{}}
}

// advisories is an advisory.Checker that answers the same for every
// update, and remembers what it was asked.
type advisories struct {
	result  advisory.Result
	err     error
	queries []advisory.Query
}

func (a *advisories) Check(ctx context.Context, q advisory.Query) (advisory.Result, error) {
	a.queries = append(a.queries, q)
	return a.result, a.err
}

// nothingKnown is the advisory database's answer for an update it has
// nothing on.
func nothingKnown() advisory.Result {
	return advisory.Result{
		SecurityFix:   allow.No("no advisory names this version as the fix", "advisories"),
		NoMalware:     allow.Yes("no malware advisory", "advisories"),
		NoNewAdvisory: allow.Yes("no new advisory", "advisories"),
	}
}

// testPolicy lists golang.org/x/text and not golang.org/x/mod, so the
// new module is an unlisted new name and its age is looked up.
func testPolicy() allow.Policy {
	return allow.Policy{
		MinAge:       72 * time.Hour,
		UnreadAge:    14 * 24 * time.Hour,
		MajorAge:     14 * 24 * time.Hour,
		NewNameAge:   365 * 24 * time.Hour,
		WaitDeadline: 7 * 24 * time.Hour,
		FastPath:     true,
		Companions:   allow.RideAlong,
		Listed:       map[string][]string{allow.GoModules: {"golang.org/x/text"}},
	}
}

var testNow = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

// input is a facts.Input for files with the recorded index behind it.
func input(t *testing.T, files []facts.File) (facts.Input, *indexFixtures, *advisories) {
	fixtures := &indexFixtures{t: t}
	adv := &advisories{result: nothingKnown()}
	return facts.Input{
		Repo:       "example/app",
		Base:       strings.Repeat("a", 40),
		Head:       strings.Repeat("b", 40),
		Files:      files,
		Policy:     testPolicy(),
		HTTP:       &http.Client{Transport: fixtures},
		Advisories: adv,
		Now:        func() time.Time { return testNow },
	}, fixtures, adv
}

func gatherer(tool goTool) *Gatherer {
	return &Gatherer{tool: tool, indexLimit: 100}
}

func TestGather(t *testing.T) {
	in, fixtures, adv := input(t, pr(baseMod, headMod, baseSum, headSum))
	tool := goFixtures(t)
	res, err := gatherer(tool).Gather(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}

	if !res.Shape.Holds() || !strings.Contains(res.Shape.Value, "2 require lines moved or added") {
		t.Errorf("Shape = %+v", res.Shape)
	}
	if len(res.Updates) != 2 {
		t.Fatalf("%d updates, want 2: %+v", len(res.Updates), res.Updates)
	}

	mod, text := res.Updates[0], res.Updates[1]

	// golang.org/x/text: an existing, listed requirement moves up a patch.
	if text.Name != "golang.org/x/text" || text.From != "v0.3.2" || text.To != "v0.3.3" {
		t.Errorf("x/text is %s %s to %s", text.Name, text.From, text.To)
	}
	for name, f := range map[string]allow.Fact{"Known": text.Known, "Listed": text.Listed, "Increase": text.Increase,
		"Bound": text.Bound, "Clean": text.Clean, "NoRegress": text.NoRegress} {
		if !f.Holds() {
			t.Errorf("x/text %s = %+v, want it to hold", name, f)
		}
	}
	for name, f := range map[string]allow.Fact{"NewName": text.NewName, "Major": text.Major, "SecurityFix": text.SecurityFix} {
		if !f.Gathered() || f.OK {
			t.Errorf("x/text %s = %+v, want a gathered no", name, f)
		}
	}
	if want := ts("2020-06-16T18:50:19.600867Z"); !text.FirstSeen.Known() || !text.FirstSeen.Time.Equal(want) {
		t.Errorf("x/text FirstSeen = %+v, want %v", text.FirstSeen, want)
	}
	// The commit time go list reports is 18:28:43, 21 minutes earlier. It
	// must not be the answer.
	if text.FirstSeen.Time.Equal(ts("2020-06-16T18:28:43Z")) {
		t.Error("x/text FirstSeen is the commit time")
	}
	if text.NameCreated.Source != "" {
		t.Errorf("x/text NameCreated = %+v, want it not gathered for a name that is not new", text.NameCreated)
	}
	if text.Read != "" || text.Veto != nil {
		t.Errorf("x/text Read %q, Veto %v: the caller sets these", text.Read, text.Veto)
	}

	// golang.org/x/mod: a new requirement that is not on the list.
	if mod.Name != "golang.org/x/mod" || mod.From != "" || mod.To != "v0.5.1" {
		t.Errorf("x/mod is %s %q to %s", mod.Name, mod.From, mod.To)
	}
	for name, f := range map[string]allow.Fact{"NewName": mod.NewName, "Increase": mod.Increase, "Bound": mod.Bound,
		"Clean": mod.Clean, "NoRegress": mod.NoRegress} {
		if !f.Holds() {
			t.Errorf("x/mod %s = %+v, want it to hold", name, f)
		}
	}
	for name, f := range map[string]allow.Fact{"Known": mod.Known, "Listed": mod.Listed, "Major": mod.Major, "SecurityFix": mod.SecurityFix} {
		if !f.Gathered() || f.OK {
			t.Errorf("x/mod %s = %+v, want a gathered no", name, f)
		}
	}
	if want := ts("2021-09-22T20:29:37.75807Z"); !mod.FirstSeen.Known() || !mod.FirstSeen.Time.Equal(want) {
		t.Errorf("x/mod FirstSeen = %+v, want %v", mod.FirstSeen, want)
	}
	// The name is dated by v0.1.0, the earliest version, not by v0.5.1.
	if want := ts("2019-05-31T18:28:44.591758Z"); !mod.NameCreated.Known() || !mod.NameCreated.Time.Equal(want) ||
		!strings.Contains(mod.NameCreated.Value, "v0.1.0") {
		t.Errorf("x/mod NameCreated = %+v, want %v", mod.NameCreated, want)
	}

	wantArtifacts := []artifact.Pair{
		{Ecosystem: allow.GoModules, Name: "golang.org/x/mod", From: "", To: "v0.5.1",
			New: artifact.Ref{Kind: artifact.GoModuleZip, Name: "golang.org/x/mod", Version: "v0.5.1", Hash: hMod051}},
		{Ecosystem: allow.GoModules, Name: "golang.org/x/text", From: "v0.3.2", To: "v0.3.3",
			Old: artifact.Ref{Kind: artifact.GoModuleZip, Name: "golang.org/x/text", Version: "v0.3.2", Hash: hText032},
			New: artifact.Ref{Kind: artifact.GoModuleZip, Name: "golang.org/x/text", Version: "v0.3.3", Hash: hText033}},
	}
	if got, want := mustJSON(res.Artifacts), mustJSON(wantArtifacts); got != want {
		t.Errorf("Artifacts =\n%s\nwant\n%s", got, want)
	}

	wantQueries := []advisory.Query{
		{Ecosystem: allow.GoModules, Name: "golang.org/x/mod", From: "", To: "v0.5.1"},
		{Ecosystem: allow.GoModules, Name: "golang.org/x/text", From: "v0.3.2", To: "v0.3.3"},
	}
	if got, want := mustJSON(adv.queries), mustJSON(wantQueries); got != want {
		t.Errorf("advisory queries = %s, want %s", got, want)
	}
	// x/mod v0.5.1 takes two pages, its name one, x/text one.
	if len(fixtures.requests) != 4 {
		t.Errorf("%d index requests: %v", len(fixtures.requests), fixtures.requests)
	}
	// The download runs first, into the empty module cache.
	if len(tool.calls) != 4 || !strings.HasPrefix(tool.calls[0], "mod download -json -- ") {
		t.Errorf("go commands: %q", tool.calls)
	}

	// The record is one allow.Decide can decide on: with the model's
	// read added, both updates are old enough and the name is old enough.
	prFacts := allow.PRFacts{
		Ecosystem:        allow.GoModules,
		Identity:         allow.Yes("dependabot", "test"),
		Shape:            res.Shape,
		ChecksConfigured: allow.Yes("required", "test"),
		Updates:          res.Updates,
	}
	for i := range prFacts.Updates {
		prFacts.Updates[i].Read = allow.ReadFull
	}
	if d := allow.Decide(prFacts, in.Policy, testNow); d.Outcome != allow.Merge {
		t.Errorf("Decide = %s %v, want merge", d.Outcome, d.Reasons)
	}
	// And one it refuses the moment the new name is too young.
	if d := allow.Decide(prFacts, in.Policy, ts("2020-01-01T00:00:00Z")); d.Outcome != allow.Person {
		t.Errorf("Decide before the name is a year old = %s, want person", d.Outcome)
	}
}

func mustJSON(v any) string {
	b, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		panic(err)
	}
	return string(b)
}

// find returns the update for name.
func find(t *testing.T, res facts.Result, name string) allow.UpdateFacts {
	t.Helper()
	for _, u := range res.Updates {
		if u.Name == name {
			return u
		}
	}
	t.Fatalf("no update for %s in %+v", name, res.Updates)
	return allow.UpdateFacts{}
}

func hasArtifact(res facts.Result, name string) bool {
	for _, p := range res.Artifacts {
		if p.Name == name {
			return true
		}
	}
	return false
}

func TestGatherBound(t *testing.T) {
	const download = "mod download -json -- golang.org/x/mod@v0.5.1 golang.org/x/text@v0.3.3"
	tests := []struct {
		name    string
		files   []facts.File
		tool    func(*fakeTool)
		want    string // substring of x/text's Bound value; empty: it holds
		unknown bool   // never gathered: no source, and the value says "not established:"
	}{
		{"go.sum pins what the checksum database has", pr(baseMod, headMod, baseSum, headSum), nil, "", false},
		{"go.sum pins another zip hash", pr(baseMod, headMod, baseSum, strings.Replace(headSum, hText033, hText032, 1)), nil,
			"go.sum pins " + hText032 + " for the module zip; the go command got " + hText033, false},
		{"go.sum pins another go.mod hash", pr(baseMod, headMod, baseSum, strings.Replace(headSum, hText033Mod, hText032Mod, 1)), nil,
			"go.sum pins " + hText032Mod + " for go.mod", false},
		{"go.sum has no zip hash", pr(baseMod, headMod, baseSum, strings.Replace(headSum, "golang.org/x/text v0.3.3 "+hText033+"\n", "", 1)), nil,
			"no hash for the module zip of golang.org/x/text@v0.3.3", false},
		{"go.sum has no go.mod hash", pr(baseMod, headMod, baseSum, strings.Replace(headSum, "golang.org/x/text v0.3.3/go.mod "+hText033Mod+"\n", "", 1)), nil,
			"no hash for the go.mod of golang.org/x/text@v0.3.3", false},
		{"go.sum does not change", pr(baseMod, headMod, baseSum, headSum)[:1], nil,
			"does not change go.sum", false},
		{"the go command could not download it", pr(baseMod, headMod, baseSum, headSum), func(f *fakeTool) {
			f.inline[download] = `{"Path":"golang.org/x/mod","Version":"v0.5.1","Sum":"` + hMod051 + `","GoModSum":"` + hMod051Mod + `"}
{"Path":"golang.org/x/text","Version":"v0.3.3","Error":"golang.org/x/text@v0.3.3: reading https://proxy.golang.org/golang.org/x/text/@v/v0.3.3.info: 410 Gone"}`
			f.errs[download] = errors.New("exit status 1")
		}, "go mod download failed: golang.org/x/text@v0.3.3: reading", false},
		{"the go command said nothing about it", pr(baseMod, headMod, baseSum, headSum), func(f *fakeTool) {
			f.inline[download] = `{"Path":"golang.org/x/mod","Version":"v0.5.1","Sum":"` + hMod051 + `","GoModSum":"` + hMod051Mod + `"}`
		}, "go mod download did not report golang.org/x/text@v0.3.3", true},
		{"the go command reports no hash", pr(baseMod, headMod, baseSum, headSum), func(f *fakeTool) {
			f.inline[download] = `{"Path":"golang.org/x/mod","Version":"v0.5.1","Sum":"` + hMod051 + `","GoModSum":"` + hMod051Mod + `"}
{"Path":"golang.org/x/text","Version":"v0.3.3"}`
		}, "for the module zip; the go command got ", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in, _, _ := input(t, tc.files)
			tool := goFixtures(t)
			if tc.tool != nil {
				tc.tool(tool)
			}
			res, err := gatherer(tool).Gather(context.Background(), in)
			if err != nil {
				t.Fatal(err)
			}
			if !res.Shape.Holds() {
				t.Fatalf("Shape = %+v", res.Shape)
			}
			bound := find(t, res, "golang.org/x/text").Bound
			if tc.want == "" {
				if !bound.Holds() || !hasArtifact(res, "golang.org/x/text") {
					t.Errorf("Bound = %+v, artifact %v; want both", bound, hasArtifact(res, "golang.org/x/text"))
				}
				return
			}
			// A "no" has a source; a fact nothing established has none.
			// Neither is an outage.
			if bound.OK || bound.Unavailable || bound.Gathered() == tc.unknown || !strings.Contains(bound.Value, tc.want) || strings.HasPrefix(bound.Value, "not established:") != tc.unknown {
				t.Errorf("Bound = %+v, want it not to hold with %q (never gathered: %v)", bound, tc.want, tc.unknown)
			}
			if hasArtifact(res, "golang.org/x/text") {
				t.Error("an artifact is named for an update that is not bound")
			}
			// The other update is unaffected, unless nothing is pinned at all.
			if len(tc.files) == 2 && !find(t, res, "golang.org/x/mod").Bound.Holds() {
				t.Errorf("x/mod Bound = %+v", find(t, res, "golang.org/x/mod").Bound)
			}
		})
	}
}

func TestGatherNoOldHash(t *testing.T) {
	// go.sum at base has no hash for the old zip: there is nothing to
	// verify the old artifact against, so no pair is named.
	in, _, _ := input(t, pr(baseMod, headMod, "", headSum))
	res, err := gatherer(goFixtures(t)).Gather(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if !find(t, res, "golang.org/x/text").Bound.Holds() || hasArtifact(res, "golang.org/x/text") || !hasArtifact(res, "golang.org/x/mod") {
		t.Errorf("Bound %+v, artifacts %+v", find(t, res, "golang.org/x/text").Bound, res.Artifacts)
	}
}

func TestGatherStopsAtShape(t *testing.T) {
	tests := []struct {
		name  string
		files []facts.File
	}{
		{"a replace is added", pr(baseMod, headMod+"replace golang.org/x/text => example.com/evil v0.3.3\n", baseSum, headSum)},
		{"another file changes", append(pr(baseMod, headMod, baseSum, headSum), facts.File{Path: ".github/workflows/ci.yml", BaseMode: facts.RegularFile, HeadMode: facts.RegularFile})},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in, fixtures, adv := input(t, tc.files)
			// A tool with no recorded command fails the test when run.
			res, err := gatherer(&fakeTool{t: t}).Gather(context.Background(), in)
			if err != nil {
				t.Fatal(err)
			}
			if res.Shape.OK || !res.Shape.Gathered() || len(res.Updates) != 0 || len(res.Artifacts) != 0 {
				t.Errorf("result = %+v", res)
			}
			if len(fixtures.requests) != 0 || len(adv.queries) != 0 {
				t.Error("something was looked up for a pull request without the Go shape")
			}
		})
	}
}

func TestGatherNoUpdates(t *testing.T) {
	// Only the go line goes up. The shape holds and nothing moves, which
	// allow.Decide sends to a person.
	in, _, _ := input(t, pr(baseMod, edit(baseMod, "go 1.22", "go 1.23.0"), "", "")[:1])
	res, err := gatherer(&fakeTool{t: t}).Gather(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Shape.Holds() || len(res.Updates) != 0 {
		t.Errorf("result = %+v", res)
	}
}

func TestGatherErrors(t *testing.T) {
	files := pr(baseMod, headMod, baseSum, headSum)
	const download = "mod download -json -- golang.org/x/mod@v0.5.1 golang.org/x/text@v0.3.3"

	t.Run("incomplete input", func(t *testing.T) {
		for _, strip := range []func(*facts.Input){
			func(in *facts.Input) { in.HTTP = nil },
			func(in *facts.Input) { in.Advisories = nil },
			func(in *facts.Input) { in.Now = nil },
		} {
			in, _, _ := input(t, files)
			strip(&in)
			if _, err := gatherer(goFixtures(t)).Gather(context.Background(), in); err == nil {
				t.Error("no error")
			}
		}
	})

	t.Run("the go command does not run", func(t *testing.T) {
		in, _, _ := input(t, files)
		tool := goFixtures(t)
		delete(tool.files, download)
		tool.errs[download] = errors.New("fork/exec go: no such file or directory")
		if _, err := gatherer(tool).Gather(context.Background(), in); err == nil {
			t.Error("no error")
		}
	})

	t.Run("go list fails", func(t *testing.T) {
		in, _, _ := input(t, files)
		tool := goFixtures(t)
		tool.errs["list -m -e -versions -json -- golang.org/x/mod golang.org/x/text"] = errors.New("exit status 2")
		if _, err := gatherer(tool).Gather(context.Background(), in); err == nil {
			t.Error("no error")
		}
	})

	t.Run("the context ends", func(t *testing.T) {
		in, _, _ := input(t, files)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		res, err := gatherer(goFixtures(t)).Gather(ctx, in)
		if !errors.Is(err, context.Canceled) || len(res.Updates) != 0 {
			t.Errorf("err = %v, result = %+v; want context.Canceled and no result", err, res)
		}
	})

	t.Run("the context ends while facts are gathered", func(t *testing.T) {
		in, _, _ := input(t, files)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		// The advisory checker is asked once per update.
		in.Advisories = checkerFunc(func(ctx context.Context, q advisory.Query) (advisory.Result, error) {
			cancel()
			return advisory.Result{}, ctx.Err()
		})
		res, err := gatherer(goFixtures(t)).Gather(ctx, in)
		if !errors.Is(err, context.Canceled) || len(res.Updates) != 0 {
			t.Errorf("err = %v, result = %+v; want context.Canceled and no result", err, res)
		}
	})
}

type checkerFunc func(context.Context, advisory.Query) (advisory.Result, error)

func (f checkerFunc) Check(ctx context.Context, q advisory.Query) (advisory.Result, error) {
	return f(ctx, q)
}

func TestGatherUnknowns(t *testing.T) {
	files := pr(baseMod, headMod, baseSum, headSum)

	t.Run("the index does not answer", func(t *testing.T) {
		in, _, _ := input(t, files)
		in.HTTP = &http.Client{Transport: roundTrip(func(req *http.Request) (*http.Response, error) {
			return respond(req, http.StatusBadGateway, ""), nil
		})}
		res, err := gatherer(goFixtures(t)).Gather(context.Background(), in)
		if err != nil {
			t.Fatal(err)
		}
		// An index that did not answer is unavailable, not unknown: the
		// next evaluation asks again.
		for _, u := range res.Updates {
			if u.FirstSeen.Known() || !u.FirstSeen.Unavailable || !strings.Contains(u.FirstSeen.Value, "the index did not answer: status 502") || u.FirstSeen.Source == "" {
				t.Errorf("%s FirstSeen = %+v", u.Name, u.FirstSeen)
			}
		}
		if nc := find(t, res, "golang.org/x/mod").NameCreated; nc.Known() || !nc.Unavailable || !strings.Contains(nc.Value, "v0.3.0: the index did not answer: status 502") {
			t.Errorf("NameCreated = %+v", nc)
		}
		// Bound does not depend on the index.
		if !find(t, res, "golang.org/x/text").Bound.Holds() {
			t.Error("Bound was lost with the index")
		}
		// With the code read, all that is missing is the index: a wait.
		updates := append([]allow.UpdateFacts(nil), res.Updates...)
		for i := range updates {
			updates[i].Read = allow.ReadFull
		}
		d := allow.Decide(allow.PRFacts{Ecosystem: allow.GoModules, Identity: allow.Yes("y", "t"), Shape: res.Shape,
			ChecksConfigured: allow.Yes("y", "t"), Opened: testNow.Add(-time.Hour), Updates: updates}, in.Policy, testNow)
		if d.Outcome != allow.Wait || !reflect.DeepEqual(d.Reasons, []allow.Reason{allow.ReasonSourceUnavailable}) {
			t.Errorf("Decide = %s %v, want wait [source_unavailable]", d.Outcome, d.Reasons)
		}
	})

	t.Run("the index answers something else than a page", func(t *testing.T) {
		in, _, _ := input(t, files)
		in.HTTP = &http.Client{Transport: roundTrip(func(req *http.Request) (*http.Response, error) {
			return respond(req, http.StatusOK, "<html>\n"), nil
		})}
		res, err := gatherer(goFixtures(t)).Gather(context.Background(), in)
		if err != nil {
			t.Fatal(err)
		}
		// An answer arrived. Asking again would get the same one.
		for _, u := range res.Updates {
			if u.FirstSeen.Known() || u.FirstSeen.Unavailable || !strings.Contains(u.FirstSeen.Value, "not established: the index could not be read") || u.FirstSeen.Source != "" {
				t.Errorf("%s FirstSeen = %+v", u.Name, u.FirstSeen)
			}
		}
	})

	t.Run("the index dates the version in the future", func(t *testing.T) {
		in, _, _ := input(t, files)
		in.Now = func() time.Time { return ts("2020-06-16T18:40:00Z") }
		res, err := gatherer(goFixtures(t)).Gather(context.Background(), in)
		if err != nil {
			t.Fatal(err)
		}
		if fs := find(t, res, "golang.org/x/text").FirstSeen; fs.Known() || !strings.Contains(fs.Value, "in the future") {
			t.Errorf("FirstSeen = %+v", fs)
		}
	})

	t.Run("go list has no commit time", func(t *testing.T) {
		in, fixtures, _ := input(t, files)
		tool := goFixtures(t)
		line := "list -m -e -u -retracted -json -- golang.org/x/mod@v0.5.1 golang.org/x/text@v0.3.3"
		delete(tool.files, line)
		tool.inline[line] = `{"Path":"golang.org/x/mod","Version":"v0.5.1","Time":"2021-09-22T20:26:12Z"}
{"Path":"golang.org/x/text","Version":"v0.3.3","Error":{"Err":"golang.org/x/text@v0.3.3: Get \"https://proxy.golang.org/golang.org/x/text/@v/v0.3.3.info\": dial tcp: i/o timeout"}}`
		res, err := gatherer(tool).Gather(context.Background(), in)
		if err != nil {
			t.Fatal(err)
		}
		text := find(t, res, "golang.org/x/text")
		if text.FirstSeen.Known() || !strings.Contains(text.FirstSeen.Value, "no commit time") {
			t.Errorf("FirstSeen = %+v", text.FirstSeen)
		}
		// The recorded error is the proxy not answering, so nothing is
		// said against the version: both facts are unavailable.
		if !text.FirstSeen.Unavailable {
			t.Errorf("FirstSeen = %+v, want it unavailable", text.FirstSeen)
		}
		if text.Clean.OK || !text.Clean.Unavailable || !strings.Contains(text.Clean.Value, "the module proxy did not answer") {
			t.Errorf("Clean = %+v", text.Clean)
		}
		for _, since := range fixtures.requests {
			if strings.HasPrefix(since, "2020-06") {
				t.Errorf("the index was read for x/text without a commit time: %v", fixtures.requests)
			}
		}
	})

	t.Run("the advisory database does not answer", func(t *testing.T) {
		in, _, adv := input(t, files)
		down := allow.Unavailable("GitHub's Advisory Database did not answer (HTTP 503, after retries)", "GET api.github.com/advisories")
		adv.result = advisory.Result{SecurityFix: down, NoMalware: down, NoNewAdvisory: down}
		res, err := gatherer(goFixtures(t)).Gather(context.Background(), in)
		if err != nil {
			t.Fatal(err)
		}
		// The checker's own state is passed on: a wait, not a person.
		text := find(t, res, "golang.org/x/text")
		if text.Clean != down || text.SecurityFix != down {
			t.Errorf("Clean = %+v, SecurityFix = %+v; want both unavailable as the checker said", text.Clean, text.SecurityFix)
		}
	})

	t.Run("a checker that fails without the context ending", func(t *testing.T) {
		in, _, adv := input(t, files)
		adv.result, adv.err = nothingKnown(), errors.New("boom")
		res, err := gatherer(goFixtures(t)).Gather(context.Background(), in)
		if err != nil {
			t.Fatal(err)
		}
		// Whatever came with the error is not used: nothing was
		// established, which is person.
		text := find(t, res, "golang.org/x/text")
		if text.Clean.Gathered() || text.Clean.Unavailable || !strings.Contains(text.Clean.Value, "not established: malware advisories were not checked") {
			t.Errorf("Clean = %+v", text.Clean)
		}
		if text.SecurityFix != (allow.Fact{}) {
			t.Errorf("SecurityFix = %+v, want it blank", text.SecurityFix)
		}
	})

	t.Run("a security fix is passed through", func(t *testing.T) {
		in, _, adv := input(t, files)
		adv.result.SecurityFix = allow.Yes("GHSA-xxxx-xxxx-xxxx", "advisories")
		res, err := gatherer(goFixtures(t)).Gather(context.Background(), in)
		if err != nil {
			t.Fatal(err)
		}
		if sf := find(t, res, "golang.org/x/text").SecurityFix; !sf.Holds() || sf.Value != "GHSA-xxxx-xxxx-xxxx" {
			t.Errorf("SecurityFix = %+v", sf)
		}
	})

	t.Run("a listed new name has no NameCreated", func(t *testing.T) {
		in, fixtures, _ := input(t, files)
		in.Policy.Listed[allow.GoModules] = []string{"golang.org/x/"}
		tool := goFixtures(t)
		res, err := gatherer(tool).Gather(context.Background(), in)
		if err != nil {
			t.Fatal(err)
		}
		mod := find(t, res, "golang.org/x/mod")
		if !mod.Known.Holds() || !mod.Listed.Holds() || !mod.NewName.Holds() || mod.NameCreated.Source != "" {
			t.Errorf("x/mod = %+v", mod)
		}
		if len(tool.calls) != 3 || len(fixtures.requests) != 3 {
			t.Errorf("go commands %q, index requests %v", tool.calls, fixtures.requests)
		}
	})
}

func TestManifestFacts(t *testing.T) {
	policy := allow.Policy{Listed: map[string][]string{allow.GoModules: {"golang.org/x/", "example.com/listed"}}}
	const (
		yes = "yes"
		no  = "no"
	)
	tests := []struct {
		name string
		up   update
		// expected answers, in order: NewName Listed Known Increase Major NoRegress
		want [6]string
	}{
		{"patch of an existing module", update{name: "example.com/m", from: "v1.2.3", to: "v1.2.4"}, [6]string{no, no, yes, yes, no, yes}},
		{"minor of a listed module", update{name: "golang.org/x/net", from: "v0.30.0", to: "v0.31.0"}, [6]string{no, yes, yes, yes, no, yes}},
		{"v0 to v1", update{name: "example.com/m", from: "v0.9.0", to: "v1.0.0"}, [6]string{no, no, yes, yes, yes, yes}},
		{"incompatible major", update{name: "example.com/m", from: "v2.1.0+incompatible", to: "v3.0.0+incompatible"}, [6]string{no, no, yes, yes, yes, yes}},
		{"incompatible minor", update{name: "example.com/m", from: "v2.1.0+incompatible", to: "v2.2.0+incompatible"}, [6]string{no, no, yes, yes, no, yes}},
		{"downgrade", update{name: "example.com/m", from: "v1.2.4", to: "v1.2.3"}, [6]string{no, no, yes, no, no, yes}},
		// Pseudo-versions (spec section 11, amendment 24). To a plain
		// release the old version's form does not matter.
		{"from a pseudo-version to a higher release", update{name: "example.com/m", from: "v0.0.0-20240101000000-aaaaaaaaaaaa", to: "v0.1.0"}, [6]string{no, no, yes, yes, no, yes}},
		{"from a pseudo-version to the release it is based on", update{name: "example.com/m", from: "v1.2.4-0.20240101000000-aaaaaaaaaaaa", to: "v1.2.3"}, [6]string{no, no, yes, no, no, yes}},
		{"from a pseudo-version to the release it leads up to", update{name: "example.com/m", from: "v1.2.4-0.20240101000000-aaaaaaaaaaaa", to: "v1.2.4"}, [6]string{no, no, yes, yes, no, yes}},
		{"from a pre-release to its release", update{name: "example.com/m", from: "v1.3.0-rc.1", to: "v1.3.0"}, [6]string{no, no, yes, yes, no, yes}},
		// To a pseudo-version: a listed module only, and only upwards.
		{"listed, to a later pseudo-version", update{name: "golang.org/x/exp", from: "v0.0.0-20240101000000-aaaaaaaaaaaa", to: "v0.0.0-20240201000000-bbbbbbbbbbbb"}, [6]string{no, yes, yes, yes, no, yes}},
		{"listed, to an earlier pseudo-version", update{name: "golang.org/x/exp", from: "v0.0.0-20240201000000-bbbbbbbbbbbb", to: "v0.0.0-20240101000000-aaaaaaaaaaaa"}, [6]string{no, yes, yes, no, no, yes}},
		{"listed, the same time and another commit", update{name: "golang.org/x/exp", from: "v0.0.0-20240201000000-bbbbbbbbbbbb", to: "v0.0.0-20240201000000-aaaaaaaaaaaa"}, [6]string{no, yes, yes, no, no, yes}},
		{"listed, from a release to a pseudo-version above it", update{name: "golang.org/x/net", from: "v0.30.0", to: "v0.30.1-0.20240201000000-bbbbbbbbbbbb"}, [6]string{no, yes, yes, yes, no, yes}},
		{"listed, from a release to a pseudo-version below it", update{name: "golang.org/x/net", from: "v0.30.0", to: "v0.0.0-20240201000000-bbbbbbbbbbbb"}, [6]string{no, yes, yes, no, no, yes}},
		{"not listed, to a later pseudo-version", update{name: "example.com/m", from: "v0.0.0-20240101000000-aaaaaaaaaaaa", to: "v0.0.0-20240201000000-bbbbbbbbbbbb"}, [6]string{no, no, yes, no, no, yes}},
		{"not listed, from a release to a pseudo-version above it", update{name: "example.com/m", from: "v1.2.3", to: "v1.2.4-0.20240201000000-bbbbbbbbbbbb"}, [6]string{no, no, yes, no, no, yes}},
		// A pre-release that is not a pseudo-version is never moved to.
		{"to a pre-release", update{name: "example.com/m", from: "v1.2.3", to: "v1.3.0-rc.1"}, [6]string{no, no, yes, no, no, yes}},
		{"listed, to a pre-release", update{name: "golang.org/x/net", from: "v0.30.0", to: "v0.31.0-rc.1"}, [6]string{no, yes, yes, no, no, yes}},
		{"new and listed", update{name: "golang.org/x/sync", from: "", to: "v0.8.0"}, [6]string{yes, yes, yes, yes, no, yes}},
		{"new and listed by exact name", update{name: "example.com/listed", from: "", to: "v1.0.0"}, [6]string{yes, yes, yes, yes, no, yes}},
		{"new, not listed", update{name: "example.com/new", from: "", to: "v1.0.0"}, [6]string{yes, no, no, yes, no, yes}},
		{"new, not listed, name only resembles a listed one", update{name: "example.com/listed-not", from: "", to: "v1.0.0"}, [6]string{yes, no, no, yes, no, yes}},
		{"new at a pseudo-version", update{name: "example.com/new", from: "", to: "v0.0.0-20240201000000-bbbbbbbbbbbb"}, [6]string{yes, no, no, no, no, yes}},
		{"new and listed at a pseudo-version", update{name: "golang.org/x/exp", from: "", to: "v0.0.0-20240201000000-bbbbbbbbbbbb"}, [6]string{yes, yes, yes, no, no, yes}},
		// A removed requirement never gets this far: Shape refuses it.
		{"another major added beside the old one", update{name: "example.com/m/v3", from: "", to: "v3.0.0"}, [6]string{yes, no, no, yes, no, yes}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var u allow.UpdateFacts
			setManifestFacts(&u, tc.up, policy)
			got := [6]allow.Fact{u.NewName, u.Listed, u.Known, u.Increase, u.Major, u.NoRegress}
			names := [6]string{"NewName", "Listed", "Known", "Increase", "Major", "NoRegress"}
			for i, f := range got {
				if !f.Gathered() || f.Value == "" {
					t.Errorf("%s was not gathered: %+v", names[i], f)
				}
				if answer := map[bool]string{true: yes, false: no}[f.OK]; answer != tc.want[i] {
					t.Errorf("%s = %s (%s), want %s", names[i], answer, f.Value, tc.want[i])
				}
			}
			// The record must never be one allow.Decide calls inconsistent
			// or incomplete.
			u.Name, u.From, u.To = tc.up.name, tc.up.from, tc.up.to
			u.Bound, u.Clean = allow.Yes("y", "t"), allow.Yes("y", "t")
			u.SecurityFix = allow.No("n", "t")
			u.FirstSeen = allow.At(testNow.Add(-1000*24*time.Hour), "t")
			u.NameCreated = allow.At(testNow.Add(-1000*24*time.Hour), "t")
			u.Read = allow.ReadFull
			p := testPolicy()
			p.Listed = policy.Listed
			d := allow.Decide(allow.PRFacts{Ecosystem: allow.GoModules, Identity: allow.Yes("y", "t"), Shape: allow.Yes("y", "t"),
				ChecksConfigured: allow.Yes("y", "t"), Updates: []allow.UpdateFacts{u}}, p, testNow)
			for _, r := range d.Reasons {
				if r == allow.ReasonInconsistent || r == allow.ReasonFactMissing || r == allow.ReasonListMismatch {
					t.Errorf("allow.Decide: %s", r)
				}
			}
		})
	}
}

// Indirect is go.mod's own "// indirect" marker at head, read by x/mod
// (spec section 11, amendment 23). Shape already refuses a marker that
// changes, so a requirement that was direct at base never becomes
// indirect here.
func TestIndirectFact(t *testing.T) {
	const base = `module example.com/app

go 1.22

require (
	example.com/direct v1.0.0
	example.com/old/v2 v2.3.0
)

require (
	example.com/behind v1.0.0 // indirect
	example.com/other/v2 v2.0.0 // indirect
)
`
	tests := []struct {
		name string
		head string
		// update is the module to look at; want is whether its Indirect
		// holds. shape is a piece of the Shape problem, when there is one.
		update string
		want   bool
		shape  string
	}{
		{"a direct requirement moves", edit(base, "example.com/direct v1.0.0", "example.com/direct v2.0.0+incompatible"), "example.com/direct", false, ""},
		{"an indirect requirement moves", edit(base, "example.com/behind v1.0.0 //", "example.com/behind v2.0.0+incompatible //"), "example.com/behind", true, ""},
		{"a new indirect requirement", edit(base, "\texample.com/behind v1.0.0 // indirect\n", "\texample.com/behind v1.0.0 // indirect\n\texample.com/new v1.0.0 // indirect\n"), "example.com/new", true, ""},
		{"a new direct requirement", edit(base, "\texample.com/direct v1.0.0\n", "\texample.com/direct v1.0.0\n\texample.com/new v1.0.0\n"), "example.com/new", false, ""},
		{"a comment that only looks like the marker", edit(base, "example.com/direct v1.0.0", "example.com/direct v1.1.0 // indirectly"), "example.com/direct", false, ""},
		// Shape's, not this fact's. The new path of an existing requirement
		// is not followed back: the removal is refused.
		{"a direct requirement comes back indirect under a new major path", edit(base, "\texample.com/old/v2 v2.3.0\n", "", "\texample.com/behind v1.0.0 // indirect\n", "\texample.com/behind v1.0.0 // indirect\n\texample.com/old/v3 v3.0.0 // indirect\n"), "", false, "no longer requires example.com/old/v2"},
		{"an indirect requirement moves to a new major path", edit(base, "example.com/other/v2 v2.0.0 //", "example.com/other/v3 v3.0.0 //"), "", false, "no longer requires example.com/other/v2"},
		{"a direct requirement gains the marker as it moves", edit(base, "example.com/direct v1.0.0", "example.com/direct v2.0.0+incompatible // indirect"), "", false, "changes the // indirect marker of example.com/direct"},
		{"an indirect requirement loses the marker as it moves", edit(base, "example.com/behind v1.0.0 // indirect", "example.com/behind v1.1.0"), "", false, "changes the // indirect marker of example.com/behind"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := Changes(pr(base, tc.head, "", "")[:1], testPolicy())
			if tc.shape != "" {
				if res.Shape.Holds() || !strings.Contains(res.Shape.Value, tc.shape) || len(res.Updates) != 0 {
					t.Fatalf("Shape = %+v with %d updates, want a no saying %q", res.Shape, len(res.Updates), tc.shape)
				}
				return
			}
			if !res.Shape.Holds() {
				t.Fatalf("Shape: %+v", res.Shape)
			}
			u := find(t, res, tc.update)
			if !u.Indirect.Gathered() || u.Indirect.OK != tc.want {
				t.Errorf("Indirect = %+v, want a gathered %v", u.Indirect, tc.want)
			}
		})
	}
}

// listedFixture returns one module from a recorded go list output.
func listedFixture(t *testing.T, file string, key module.Version) (listed, bool) {
	t.Helper()
	tool := &fakeTool{t: t, files: map[string]string{"list -m -e -json --": file}}
	got, err := list(context.Background(), tool, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	l, ok := got[key]
	return l, ok
}

// TestCleanRecorded checks the Clean fact against what the go command
// really printed for retracted, deprecated, missing and good versions.
func TestCleanRecorded(t *testing.T) {
	fsnotify := "github.com/fsnotify/fsnotify"
	tests := []struct {
		name         string
		target       module.Version
		infoFile     string
		versionsFile string
		want         string // substring of the value; empty: Clean holds
	}{
		{"a good version", mv(fsnotify, "v1.5.4"), "list_retracted.json", "list_versions_retracted.json", ""},
		{"a retracted version", mv(fsnotify, "v1.5.3"), "list_retracted.json", "list_versions_retracted.json",
			"retracted: Published an incorrect branch accidentally"},
		{"a version retracted by an interval", mv("google.golang.org/grpc", "v1.74.0"), "list_retracted.json", "list_versions_retracted.json",
			"retracted: v1.74.0 was published prematurely"},
		{"a deprecated module", mv("github.com/golang/protobuf", "v1.5.4"), "list_retracted.json", "list_versions_retracted.json",
			"the module is deprecated: Use the"},
		{"a version that does not exist", mv(fsnotify, "v1.5.99"), "list_retracted.json", "list_versions_retracted.json",
			"go list failed: github.com/fsnotify/fsnotify@v1.5.99: reading https://proxy.golang.org/"},
		// The go command printed no Retracted for v1.5.3 here, because the
		// proxy answered 404 for the go.mod that holds the retractions. The
		// version list is what gives it away.
		{"a retracted version whose retraction could not be loaded", mv(fsnotify, "v1.5.3"), "list_retracted_unloadable.json", "list_versions_unloadable.json",
			"the module's retractions could not be loaded"},
		{"the same, with a version list that did load", mv(fsnotify, "v1.5.3"), "list_retracted_unloadable.json", "list_versions_retracted.json",
			"v1.5.3 is not in the module's list of versions that are not retracted"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			info, infoOK := listedFixture(t, tc.infoFile, tc.target)
			versions, versionsOK := listedFixture(t, tc.versionsFile, mv(tc.target.Path, ""))
			up := update{name: tc.target.Path, from: "v1.0.0", to: tc.target.Version}
			got := cleanFact(up, downloaded{Sum: "h1:x", GoModSum: "h1:y"}, true, info, infoOK, versions, versionsOK, nothingKnown())
			checkFact(t, got, tc.want)
		})
	}
}

func checkFact(t *testing.T, got allow.Fact, want string) {
	t.Helper()
	switch {
	case !got.Gathered():
		t.Errorf("not gathered: %+v", got)
	case want == "" && !got.OK:
		t.Errorf("does not hold: %+v", got)
	case want != "" && (got.OK || !strings.Contains(got.Value, want)):
		t.Errorf("fact = %+v, want a no with %q", got, want)
	}
}

func TestClean(t *testing.T) {
	up := update{name: "example.com/m", from: "v1.0.0", to: "v1.1.0"}
	good := downloaded{Sum: "h1:x", GoModSum: "h1:y"}
	info := listed{Path: up.name, Version: up.to}
	versions := listed{Path: up.name, Versions: []string{"v1.0.0", "v1.1.0"}}
	goErr := &struct{ Err string }{"boom"}
	// The two shapes of a proxy that did not answer, as the go command
	// reports them for a module, and the one for the retractions.
	const (
		proxy503     = "example.com/m@v1.1.0: reading https://proxy.golang.org/example.com/m/@v/v1.1.0.info: 503 Service Unavailable"
		proxyTimeout = `example.com/m@v1.1.0: Get "https://proxy.golang.org/example.com/m/@v/v1.1.0.info": dial tcp: i/o timeout`
		retract502   = "loading module retractions for example.com/m@v1.0.0: reading https://proxy.golang.org/example.com/m/@v/v1.1.0.mod: 502 Bad Gateway"
	)
	advisoriesDown := advisory.Result{
		SecurityFix:   allow.Unavailable("GitHub's Advisory Database did not answer (HTTP 503, after retries)", "GET api.github.com/advisories"),
		NoMalware:     allow.Unavailable("GitHub's Advisory Database did not answer (HTTP 503, after retries)", "GET api.github.com/advisories"),
		NoNewAdvisory: allow.Unavailable("GitHub's Advisory Database did not answer (HTTP 503, after retries)", "GET api.github.com/advisories"),
	}

	// What a fact that does not hold is: a gathered no, a fact nothing
	// established (no source, "not established:"), or an unavailable one.
	const (
		no          = "no"
		unknown     = "unknown"
		unavailable = "unavailable"
	)
	tests := []struct {
		name  string
		call  func() allow.Fact
		state string // "" when Clean holds
		want  string // substring of the value
	}{
		{"everything fine", func() allow.Fact {
			return cleanFact(up, good, true, info, true, versions, true, nothingKnown())
		}, "", "served by the proxy, not retracted, not deprecated, no malware advisory, no new advisory"},
		{"not downloaded", func() allow.Fact {
			return cleanFact(up, downloaded{}, false, info, true, versions, true, nothingKnown())
		}, unknown, "not established: go mod download did not report"},
		{"download failed", func() allow.Fact {
			return cleanFact(up, downloaded{Error: "410 Gone"}, true, info, true, versions, true, nothingKnown())
		}, no, "the proxy did not serve the version: 410 Gone"},
		{"the proxy did not answer the download", func() allow.Fact {
			return cleanFact(up, downloaded{Error: proxy503}, true, info, true, versions, true, nothingKnown())
		}, unavailable, "the module proxy did not answer: example.com/m@v1.1.0: reading"},
		{"go list silent", func() allow.Fact {
			return cleanFact(up, good, true, listed{}, false, versions, true, nothingKnown())
		}, unknown, "not established: go list did not report the version"},
		{"go list error", func() allow.Fact {
			return cleanFact(up, good, true, listed{Error: goErr}, true, versions, true, nothingKnown())
		}, no, "go list failed: boom"},
		{"the proxy did not answer go list", func() allow.Fact {
			return cleanFact(up, good, true, listed{Error: &struct{ Err string }{proxyTimeout}}, true, versions, true, nothingKnown())
		}, unavailable, "the module proxy did not answer"},
		{"retracted", func() allow.Fact {
			return cleanFact(up, good, true, listed{Retracted: []string{"bad release", "really"}}, true, versions, true, nothingKnown())
		}, no, "retracted: bad release; really"},
		{"retraction text is escaped", func() allow.Fact {
			return cleanFact(up, good, true, listed{Retracted: []string{"line one\nline two"}}, true, versions, true, nothingKnown())
		}, no, `retracted: line one\nline two`},
		{"deprecated", func() allow.Fact {
			return cleanFact(up, good, true, listed{Deprecated: "use v2"}, true, versions, true, nothingKnown())
		}, no, "the module is deprecated: use v2"},
		{"no version list", func() allow.Fact {
			return cleanFact(up, good, true, info, true, listed{}, false, nothingKnown())
		}, unknown, "not established: go list did not report the module's versions"},
		{"version list error", func() allow.Fact {
			return cleanFact(up, good, true, info, true, listed{Error: goErr}, true, nothingKnown())
		}, no, "the module's retractions could not be loaded: boom"},
		{"the proxy did not answer for the retractions", func() allow.Fact {
			return cleanFact(up, good, true, info, true, listed{Error: &struct{ Err string }{retract502}}, true, nothingKnown())
		}, unavailable, "the module proxy did not answer: loading module retractions"},
		{"version not in the list", func() allow.Fact {
			return cleanFact(up, good, true, info, true, listed{Versions: []string{"v1.0.0"}}, true, nothingKnown())
		}, no, "v1.1.0 is not in the module's list"},
		// Increase can hold for a listed module's pseudo-version (spec
		// section 11, amendment 24). Clean still does not: no version
		// list vouches for a commit, here for a module that has no tagged
		// version at all. So such an update stays a person's.
		{"a pseudo-version, which no version list vouches for", func() allow.Fact {
			pseudo := update{name: "google.golang.org/genproto/googleapis/rpc", from: "v0.0.0-20240101000000-aaaaaaaaaaaa", to: "v0.0.0-20240201000000-bbbbbbbbbbbb"}
			return cleanFact(pseudo, good, true, listed{Path: pseudo.name, Version: pseudo.to}, true, listed{Path: pseudo.name}, true, nothingKnown())
		}, no, "is not a tagged version, so the version list cannot confirm it is not retracted"},
		{"advisory database down", func() allow.Fact {
			return cleanFact(up, good, true, info, true, versions, true, advisoriesDown)
		}, unavailable, "GitHub's Advisory Database did not answer (HTTP 503"},
		{"the checker returned nothing", func() allow.Fact {
			return cleanFact(up, good, true, info, true, versions, true, advisory.Result{})
		}, unknown, "not established: malware advisories were not checked"},
		{"malware", func() allow.Fact {
			adv := nothingKnown()
			adv.NoMalware = allow.No("GHSA-mal", "advisories")
			return cleanFact(up, good, true, info, true, versions, true, adv)
		}, no, "GHSA-mal"},
		{"malware not checked", func() allow.Fact {
			adv := nothingKnown()
			adv.NoMalware = allow.Fact{}
			return cleanFact(up, good, true, info, true, versions, true, adv)
		}, unknown, "not established: malware advisories were not checked"},
		{"malware could not be asked about", func() allow.Fact {
			adv := nothingKnown()
			adv.NoMalware = allow.Fact{Value: "the package name is not one the advisory query can carry; nothing was asked"}
			return cleanFact(up, good, true, info, true, versions, true, adv)
		}, unknown, "nothing was asked"},
		{"new advisory", func() allow.Fact {
			adv := nothingKnown()
			adv.NoNewAdvisory = allow.No("GHSA-new affects v1.1.0", "advisories")
			return cleanFact(up, good, true, info, true, versions, true, adv)
		}, no, "GHSA-new affects v1.1.0"},
		{"new advisories not checked", func() allow.Fact {
			adv := nothingKnown()
			adv.NoNewAdvisory = allow.Fact{}
			return cleanFact(up, good, true, info, true, versions, true, adv)
		}, unknown, "not established: new advisories were not checked"},

		// A "no" is the answer whatever else went unanswered, and an
		// outage is never reported where waiting could not help.
		{"retracted, and the advisory database is down", func() allow.Fact {
			return cleanFact(up, good, true, listed{Retracted: []string{"bad release"}}, true, versions, true, advisoriesDown)
		}, no, "retracted: bad release"},
		{"the proxy is down, and there is a malware advisory", func() allow.Fact {
			adv := nothingKnown()
			adv.NoMalware = allow.No("GHSA-mal", "advisories")
			return cleanFact(up, downloaded{Error: proxy503}, true, info, true, versions, true, adv)
		}, no, "GHSA-mal"},
		{"the advisory database is down, and go list said nothing", func() allow.Fact {
			return cleanFact(up, good, true, listed{}, false, versions, true, advisoriesDown)
		}, unknown, "not established: go list did not report the version"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.call()
			var state string
			switch {
			case got.Holds():
			case got.Unavailable:
				state = unavailable
			case got.Source == "":
				state = unknown
			default:
				state = no
			}
			if state != tc.state || !strings.Contains(got.Value, tc.want) {
				t.Errorf("fact = %+v (%s), want %q with %q", got, state, tc.state, tc.want)
			}
			if (state == unknown) != strings.HasPrefix(got.Value, "not established: ") && !strings.Contains(got.Value, "nothing was asked") {
				t.Errorf("the value's \"not established:\" does not go with its state %q: %q", state, got.Value)
			}
		})
	}
}

// The go command's errors are text. One exact shape of it is read as the
// module proxy not answering; everything else is a "no".
func TestProxyOutage(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		want       bool
	}{
		{"503", "github.com/fsnotify/fsnotify@v1.5.4: reading https://proxy.golang.org/github.com/fsnotify/fsnotify/@v/v1.5.4.zip: 503 Service Unavailable", true},
		{"500 with the server's text", "example.com/m@v1.0.0: reading https://proxy.golang.org/example.com/m/@v/v1.0.0.info: 500 Internal Server Error\n\tserver response: oops", true},
		{"429", "example.com/m@v1.0.0: reading https://proxy.golang.org/example.com/m/@v/v1.0.0.zip: 429 Too Many Requests", true},
		{"no response", `golang.org/x/text@v0.3.3: Get "https://proxy.golang.org/golang.org/x/text/@v/v0.3.3.info": dial tcp: i/o timeout`, true},
		{"the retractions, 502", "loading module retractions for example.com/m@v1.0.0: reading https://proxy.golang.org/example.com/m/@v/v1.1.0.mod: 502 Bad Gateway", true},
		// The two recorded answers for a version that does not exist.
		{"404", "github.com/fsnotify/fsnotify@v1.5.99: reading https://proxy.golang.org/github.com/fsnotify/fsnotify/@v/v1.5.99.info: 404 Not Found\n\tserver response: not found: github.com/fsnotify/fsnotify@v1.5.99: invalid version: unknown revision v1.5.99", false},
		{"the retractions, 404 (recorded against a local proxy)", "loading module retractions for github.com/fsnotify/fsnotify@v0.8.10: reading http://127.0.0.1:18482/github.com/fsnotify/fsnotify/@v/v1.10.1.mod: 404 Not Found\n\tserver response: not found", false},
		{"410", "example.com/m@v1.0.0: reading https://proxy.golang.org/example.com/m/@v/v1.0.0.info: 410 Gone", false},
		// The recorded answer for a module that fails the checksum database.
		{"checksum mismatch", "github.com/fsnotify/fsnotify@v1.5.4: verifying go.mod: checksum mismatch\n\tdownloaded: h1:KOil/w6cxr3ALagyF6SIPYeoV9XN+Pjkp5hICIRMzgM=\n\tsum.golang.org: h1:OVB6XrOHzAwXMpEM7uPOzcehqUV2UqJxmVXmkdnm1bU=\n\nSECURITY ERROR\n", false},
		{"a 503 quoted in a 404's text", "example.com/m@v1.0.0: reading https://proxy.golang.org/example.com/m/@v/v1.0.0.info: 404 Not Found\n\tserver response: example.com/m@v1.0.0: reading https://proxy.golang.org/x: 503 Service Unavailable", false},
		{"another host", "example.com/m@v1.0.0: reading https://proxy.golang.org.evil.example/example.com/m/@v/v1.0.0.zip: 503 Service Unavailable", false},
		{"no response from another host", `example.com/m@v1.0.0: Get "https://example.com/m?go-get=1": dial tcp: i/o timeout`, false},
		{"plain http", "example.com/m@v1.0.0: reading http://proxy.golang.org/example.com/m/@v/v1.0.0.zip: 503 Service Unavailable", false},
		{"not at the start", "go: example.com/m@v1.0.0: reading https://proxy.golang.org/example.com/m/@v/v1.0.0.zip: 503 Service Unavailable", false},
		{"boom", "boom", false},
		{"empty", "", false},
	} {
		if got := proxyOutageRE.MatchString(tc.text); got != tc.want {
			t.Errorf("%s: outage is %v, want %v", tc.name, got, tc.want)
		}
	}
	// The recorded errors themselves, not copies of them.
	for file, want := range map[string]bool{"download_missing.json": false, "download_tampered.json": false} {
		got, err := download(context.Background(), &fakeTool{t: t, files: map[string]string{"mod download -json --": file}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		failed := 0
		for _, d := range got {
			if d.Error == "" {
				continue
			}
			failed++
			if proxyOutageRE.MatchString(d.Error) != want {
				t.Errorf("%s: %q: outage is %v", file, d.Error, !want)
			}
			if f := goFailure("go mod download failed", d.Error, sourceDownload); !f.Gathered() || f.OK {
				t.Errorf("%s: %+v, want a gathered no", file, f)
			}
		}
		if failed == 0 {
			t.Errorf("%s has no failed module", file)
		}
	}
}

func TestNameCreated(t *testing.T) {
	ctx := context.Background()
	const earliest = "list -m -e -json -- golang.org/x/mod@v0.1.0 golang.org/x/mod@v0.2.0 golang.org/x/mod@v0.3.0"
	versions, ok := listedFixture(t, "list_versions.json", mv("golang.org/x/mod", ""))
	if !ok {
		t.Fatal("no version list in the fixture")
	}
	newIndex := func(t *testing.T) (*index, *indexFixtures) {
		fixtures := &indexFixtures{t: t}
		return &index{client: &http.Client{Transport: fixtures}, url: defaultIndexURL, limit: 100, perVersion: 2, left: 20}, fixtures
	}

	t.Run("dated by the earliest version", func(t *testing.T) {
		ix, _ := newIndex(t)
		got, err := nameCreated(ctx, goFixtures(t), ix, "golang.org/x/mod", versions, true, testNow)
		if err != nil || !got.Known() || !got.Time.Equal(ts("2019-05-31T18:28:44.591758Z")) {
			t.Errorf("got %+v, %v", got, err)
		}
	})

	t.Run("the earliest version is not found, the next one is tried", func(t *testing.T) {
		// Without v0.1.0's commit time the lookup moves on to v0.2.0 and
		// v0.3.0, whose index pages were not recorded: nothing is found,
		// and the reason names the last version tried.
		ix, fixtures := newIndex(t)
		tool := goFixtures(t)
		delete(tool.files, earliest)
		tool.inline[earliest] = `{"Path":"golang.org/x/mod","Version":"v0.1.0","Error":{"Err":"timeout"}}
{"Path":"golang.org/x/mod","Version":"v0.2.0","Time":"2020-01-02T17:33:45Z"}
{"Path":"golang.org/x/mod","Version":"v0.3.0","Time":"2020-04-29T17:28:58Z"}`
		got, err := nameCreated(ctx, tool, ix, "golang.org/x/mod", versions, true, testNow)
		if err != nil || got.Known() || !strings.Contains(got.Value, "not established: v0.3.0: the index could not be read") {
			t.Errorf("got %+v, %v", got, err)
		}
		if len(fixtures.requests) != 2 {
			t.Errorf("index requests: %v", fixtures.requests)
		}
	})

	t.Run("versions are tried in version order, whatever order they come in", func(t *testing.T) {
		ix, _ := newIndex(t)
		shuffled := versions
		shuffled.Versions = []string{"v0.3.0", "v0.43.0", "v0.1.0", "v0.2.0"}
		got, err := nameCreated(ctx, goFixtures(t), ix, "golang.org/x/mod", shuffled, true, testNow)
		if err != nil || !got.Known() || !got.Time.Equal(ts("2019-05-31T18:28:44.591758Z")) {
			t.Errorf("got %+v, %v", got, err)
		}
	})

	t.Run("no version list", func(t *testing.T) {
		ix, _ := newIndex(t)
		for _, v := range []struct {
			l  listed
			ok bool
		}{{listed{}, false}, {listed{Error: &struct{ Err string }{"x"}}, true}, {listed{Path: "golang.org/x/mod"}, true}} {
			got, err := nameCreated(ctx, &fakeTool{t: t}, ix, "golang.org/x/mod", v.l, v.ok, testNow)
			if err != nil || got.Known() || got.Unavailable || got.Source != "" || !strings.Contains(got.Value, "version list could not be read") {
				t.Errorf("got %+v, %v", got, err)
			}
		}
	})

	t.Run("go list fails", func(t *testing.T) {
		ix, _ := newIndex(t)
		tool := goFixtures(t)
		tool.errs[earliest] = errors.New("exit status 2")
		if _, err := nameCreated(ctx, tool, ix, "golang.org/x/mod", versions, true, testNow); err == nil {
			t.Error("no error")
		}
	})
}
