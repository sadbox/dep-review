package gather

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sadbox/dep-review/internal/advisory"
	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/facts"
	"github.com/sadbox/dep-review/internal/gh"
	"github.com/sadbox/dep-review/internal/model"
	"github.com/sadbox/dep-review/internal/wire"
)

// TestLiveFetch runs the fetch job as the command will, with nothing
// faked, on a real open pull request, and prints what publish would
// decide from it. It talks to GitHub and to the ecosystem's registries,
// and runs only when asked:
//
//	git clone https://github.com/OWNER/REPO /tmp/checkout
//	git -C /tmp/checkout fetch origin pull/N/head
//	DEP_REVIEW_LIVE=1 DEP_REVIEW_LIVE_PULL=OWNER/REPO#N DEP_REVIEW_LIVE_CHECKOUT=/tmp/checkout \
//	    go test ./internal/gather/ -run TestLiveFetch -v
//
// GH_TOKEN is used when set; without it GitHub's unauthenticated limit of
// 60 requests an hour applies. The classification is written by hand
// here: classify's identity proof is not part of this package, so the
// pull request is simply taken to be Dependabot's. No model is asked.
func TestLiveFetch(t *testing.T) {
	pullRef, checkout := os.Getenv("DEP_REVIEW_LIVE_PULL"), os.Getenv("DEP_REVIEW_LIVE_CHECKOUT")
	if os.Getenv("DEP_REVIEW_LIVE") == "" || pullRef == "" || checkout == "" {
		t.Skip("set DEP_REVIEW_LIVE=1, DEP_REVIEW_LIVE_PULL=owner/repo#N and DEP_REVIEW_LIVE_CHECKOUT to fetch a real pull request")
	}
	repo, n, ok := strings.Cut(pullRef, "#")
	number, err := strconv.Atoi(n)
	if !ok || err != nil || !gh.ValidRepo(repo) {
		t.Fatalf("DEP_REVIEW_LIVE_PULL is %q, want owner/repo#N", pullRef)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	github := gh.New(os.Getenv("GH_TOKEN"))
	var pr struct {
		Head struct{ SHA, Ref string }
		Base struct{ SHA, Ref string }
	}
	if err := github.Get(ctx, fmt.Sprintf("repos/%s/pulls/%d", repo, number), &pr); err != nil {
		t.Fatal(err)
	}
	eco, _ := model.EcosystemFromBranch(pr.Head.Ref)
	changes, err := ReadChanges(ctx, checkout, pr.Base.SHA, pr.Head.SHA)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%s, merge base %s, %d changed paths, refused %q", eco, changes.Base, len(changes.Files), changes.Refused)

	client := &http.Client{Timeout: 2 * time.Minute}
	preparer, err := NewPreparer(t.TempDir(), client, github)
	if err != nil {
		t.Fatal(err)
	}
	cfg := defaults(t)
	dir := filepath.Join(t.TempDir(), "facts")
	fetch := Fetch{
		Class: model.Classification{
			Repo: repo, PR: number, HeadSHA: pr.Head.SHA, BaseSHA: pr.Base.SHA,
			Kind: model.KindDependabot, Reason: "taken to be Dependabot's by the live test", Ecosystem: eco,
		},
		Changes: changes, Config: cfg, HTTP: client, GitHub: github, Advisories: advisory.New(github),
		Gatherers: Gatherers(), Preparer: preparer, Logf: t.Logf,
	}
	if _, err := fetch.Run(ctx, dir); err != nil {
		t.Fatal(err)
	}
	f := readBack(t, dir)

	show := func(name string, fact allow.Fact) {
		t.Logf("  %-18s ok=%-5v unavailable=%-5v %q (%s)", name, fact.OK, fact.Unavailable, fact.Value, fact.Source)
	}
	show("identity", f.Facts.Identity)
	show("shape", f.Facts.Shape)
	show("checks configured", f.Facts.ChecksConfigured)
	t.Logf("  opened %s", f.Facts.Opened.Format(time.RFC3339))
	for _, u := range f.Facts.Updates {
		t.Logf("update %s %s -> %s", u.Name, u.From, u.To)
		for _, row := range []struct {
			name string
			fact allow.Fact
		}{
			{"known", u.Known}, {"listed", u.Listed}, {"new name", u.NewName}, {"increase", u.Increase}, {"major", u.Major},
			{"bound", u.Bound}, {"clean", u.Clean}, {"no regress", u.NoRegress}, {"security fix", u.SecurityFix}, {"superseded", u.Superseded},
		} {
			show(row.name, row.fact)
		}
		t.Logf("  first seen         %q (%s)", u.FirstSeen.Value, u.FirstSeen.Source)
		t.Logf("  read               %s %q, state %q, %d chunks, %d unread", u.Prepared.Status, u.Prepared.Detail, u.Prepared.State, len(u.Prepared.Chunks), len(u.Prepared.Unread))
	}

	// What allow.Decide makes of the facts with no verdict at all, and
	// without publish's own clock for an update no registry dates.
	d := allow.Decide(wire.Join(f, wire.Verdicts{Version: wire.Version}, finger), cfg.Policy(), time.Now())
	t.Logf("decision without a model: %s %v, not before %s, deadline %s", d.Outcome, d.Reasons, d.NotBefore.Format(time.RFC3339), d.Deadline.Format(time.RFC3339))
}

// TestLivePseudoVersion runs the fetch job, with nothing of the Go side
// faked, for the update the pseudo-version rules are for (spec section
// 11, amendments 24 and 40): a module on the built-in list that publishes
// no release, from one real commit to a later one. The go command, the
// checksum database, the module index, GitHub's Advisory Database and the
// artifact reader are the real ones; only the pull request itself is the
// fake API's, since no public pull request stays open for this. Every
// fact a merge needs must hold, and a read must be prepared:
//
//	DEP_REVIEW_LIVE=1 go test ./internal/gather/ -run TestLivePseudoVersion -v
func TestLivePseudoVersion(t *testing.T) {
	if os.Getenv("DEP_REVIEW_LIVE") == "" {
		t.Skip("set DEP_REVIEW_LIVE=1 to ask the real proxy, checksum database, index and advisory database")
	}
	const (
		name   = "google.golang.org/genproto/googleapis/rpc"
		from   = "v0.0.0-20260917231906-eeb232e0883d"
		to     = "v0.0.0-20261118221215-c8830f628b3f"
		oldSum = "h1:cDmz0iu+zm7SfyudwKqfExdDAxoJWhT2VtYJ+pLi7GQ="
		newSum = "h1:aDW6Vb2T1K0xbAgW+ED8iz39WlgjjX/OKiNh6tXv/+g="
		modSum = "h1:OaIUM3+LpYcK2GXM4FTmhWoIq371Owdr+Cc7/BsYHHc="
	)
	file := func(path, base, head string) facts.File {
		return facts.File{Path: path, BaseMode: facts.RegularFile, HeadMode: facts.RegularFile, Base: []byte(base), Head: []byte(head)}
	}
	mod := func(v string) string { return "module example.com/app\n\ngo 1.26\n\nrequire " + name + " " + v + "\n" }
	sum := func(v, zip string) string {
		return name + " " + v + " " + zip + "\n" + name + " " + v + "/go.mod " + modSum + "\n"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	client := &http.Client{Timeout: 2 * time.Minute}
	github := gh.New(os.Getenv("GH_TOKEN"))
	preparer, err := NewPreparer(t.TempDir(), client, github)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "facts")
	fetch := Fetch{
		Class: model.Classification{
			Repo: testRepo, PR: testNumber, HeadSHA: headSHA, BaseSHA: baseSHA,
			Kind: model.KindDependabot, Reason: "taken to be Dependabot's by the live test", Ecosystem: model.GoModules,
		},
		Changes: Changes{Base: mergeSHA, Head: headSHA, Files: []facts.File{
			file("go.mod", mod(from), mod(to)), file("go.sum", sum(from, oldSum), sum(to, newSum)),
		}},
		Config: defaults(t), HTTP: client, GitHub: newFakeGitHub().client(t), Advisories: advisory.New(github),
		Gatherers: Gatherers(), Preparer: preparer, Logf: t.Logf,
	}
	if _, err := fetch.Run(ctx, dir); err != nil {
		t.Fatal(err)
	}
	f := readBack(t, dir)
	if !f.Facts.Shape.Holds() || len(f.Facts.Updates) != 1 {
		t.Fatalf("shape %+v, %d updates", f.Facts.Shape, len(f.Facts.Updates))
	}
	u := f.Facts.Updates[0]
	for fact, got := range map[string]allow.Fact{"Known": u.Known, "Listed": u.Listed, "Increase": u.Increase, "Bound": u.Bound, "Clean": u.Clean, "NoRegress": u.NoRegress} {
		t.Logf("%-10s %+v", fact, got)
		if !got.Holds() {
			t.Errorf("%s does not hold: %+v", fact, got)
		}
	}
	t.Logf("SecurityFix %+v", u.SecurityFix)
	if !u.SecurityFix.Gathered() {
		t.Errorf("SecurityFix was not gathered: %+v", u.SecurityFix)
	}
	t.Logf("FirstSeen  %+v", u.FirstSeen)
	t.Logf("read       %s %q, state %q, %d chunks, %d unread, hash %s", u.Prepared.Status, u.Prepared.Detail, u.Prepared.State, len(u.Prepared.Chunks), len(u.Prepared.Unread), u.Hash)
	if u.Prepared.Status != wire.Prepared || u.Hash != newSum {
		t.Errorf("no read was prepared against the pinned hash: %+v, hash %q", u.Prepared, u.Hash)
	}

	// With the model's answer and, where the index does not date the
	// commit, publish's own clock, nothing else stands between this update
	// and a merge: an old enough first-seen time is all that is stood in.
	if !u.FirstSeen.Known() {
		if u.FirstSeen.Unavailable {
			t.Skipf("the index did not answer: %+v", u.FirstSeen)
		}
		f.Facts.Updates[0].FirstSeen = allow.At(time.Now().Add(-30*24*time.Hour), "stand-in for publish's first evaluation of the pin")
	}
	d := allow.Decide(wire.Join(f, wire.Verdicts{Version: wire.Version, Verdicts: cleanVerdicts(f)}, finger), defaults(t).Policy(), time.Now())
	t.Logf("decision with a clean read: %s %v, not before %s", d.Outcome, d.Reasons, d.NotBefore.Format(time.RFC3339))
	if d.Outcome == allow.Person {
		t.Errorf("the update goes to a person: %v", d.Reasons)
	}
}
