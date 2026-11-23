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
			Repo: repo, PR: number, HeadSHA: pr.Head.SHA, BaseSHA: pr.Base.SHA, BaseRef: pr.Base.Ref,
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

	// The review job without a model, as the scheduled job runs it, and
	// then what publish would decide with no verdict at all.
	verdicts, err := Review{Fingerprint: finger}.Run(ctx, dir, filepath.Join(t.TempDir(), "verdicts"))
	if err != nil {
		t.Fatal(err)
	}
	d := allow.Decide(wire.Join(f, verdicts, finger), cfg.Policy(), time.Now())
	t.Logf("decision without a model: %s %v, not before %s, deadline %s", d.Outcome, d.Reasons, d.NotBefore.Format(time.RFC3339), d.Deadline.Format(time.RFC3339))
}
