package gomod

import (
	"context"
	"net/http"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/module"
)

// The tests in this file talk to proxy.golang.org, sum.golang.org and
// index.golang.org, and run only with DEP_REVIEW_LIVE=1:
//
//	DEP_REVIEW_LIVE=1 go test ./internal/facts/gomod/ -run Live -v
//
// They use old versions of public modules, so the answers do not change.

func live(t *testing.T) {
	t.Helper()
	if os.Getenv("DEP_REVIEW_LIVE") == "" {
		t.Skip("set DEP_REVIEW_LIVE=1 to talk to the real proxy, checksum database and index")
	}
}

// liveTool is the real go command in a scratch directory of its own.
func liveTool(t *testing.T) goCommand {
	t.Helper()
	bin, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	c, err := newGoCommand(bin, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestLiveGather gathers for the pull request of the recorded tests with
// nothing recorded: the real go command and the real index, at the real
// page size. Only the advisory checker is a stub; it belongs to another
// package.
func TestLiveGather(t *testing.T) {
	live(t)
	in, _, _ := input(t, pr(baseMod, headMod, baseSum, headSum))
	in.HTTP = &http.Client{Timeout: time.Minute}
	in.Now = time.Now
	start := time.Now()
	res, err := (&Gatherer{}).Gather(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("gathered in %s", time.Since(start).Round(time.Second))
	t.Logf("Shape: %+v", res.Shape)
	for _, u := range res.Updates {
		t.Logf("%s %q -> %s\n  Bound      %+v\n  Clean      %+v\n  FirstSeen  %+v\n  NameCreated %+v", u.Name, u.From, u.To, u.Bound, u.Clean, u.FirstSeen, u.NameCreated)
	}

	text, mod := find(t, res, "golang.org/x/text"), find(t, res, "golang.org/x/mod")
	if !text.Bound.Holds() || !mod.Bound.Holds() {
		t.Errorf("Bound: %+v, %+v", text.Bound, mod.Bound)
	}
	if !text.Clean.Holds() || !mod.Clean.Holds() {
		t.Errorf("Clean: %+v, %+v", text.Clean, mod.Clean)
	}
	if want := ts("2020-06-16T18:50:19.600867Z"); !text.FirstSeen.Time.Equal(want) {
		t.Errorf("x/text FirstSeen = %+v, want %v", text.FirstSeen, want)
	}
	if want := ts("2021-09-22T20:29:37.75807Z"); !mod.FirstSeen.Time.Equal(want) {
		t.Errorf("x/mod FirstSeen = %+v, want %v", mod.FirstSeen, want)
	}
	if want := ts("2019-05-31T18:28:44.591758Z"); !mod.NameCreated.Time.Equal(want) {
		t.Errorf("x/mod NameCreated = %+v, want %v", mod.NameCreated, want)
	}
	if len(res.Artifacts) != 2 {
		t.Errorf("artifacts: %+v", res.Artifacts)
	}
}

// TestLiveBoundMismatch checks that a go.sum pinning the wrong hash is
// caught by the real go command and checksum database.
func TestLiveBoundMismatch(t *testing.T) {
	live(t)
	wrong := strings.Replace(headSum, hText033, hText032, 1)
	in, _, _ := input(t, pr(baseMod, headMod, baseSum, wrong))
	in.HTTP = &http.Client{Timeout: time.Minute}
	in.Now = time.Now
	res, err := (&Gatherer{}).Gather(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if b := find(t, res, "golang.org/x/text").Bound; b.OK || !strings.Contains(b.Value, "the go command got "+hText033) {
		t.Errorf("Bound = %+v", b)
	}
}

// TestLiveRetraction is the experiment of docs/v0.2-spec.md section 10:
// what "go list -m -retracted -json" prints for a retracted version, and
// whether the version list without -retracted leaves it out.
func TestLiveRetraction(t *testing.T) {
	live(t)
	ctx := context.Background()
	tool := liveTool(t)
	fsnotify := "github.com/fsnotify/fsnotify"
	targets := []module.Version{mv(fsnotify, "v1.5.3"), mv(fsnotify, "v1.5.4"), mv("github.com/golang/protobuf", "v1.5.4")}

	infos, err := list(ctx, tool, []string{"-u", "-retracted"}, targets)
	if err != nil {
		t.Fatal(err)
	}
	versions, err := list(ctx, tool, []string{"-versions"}, []module.Version{mv(fsnotify, ""), mv("github.com/golang/protobuf", "")})
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range targets {
		info := infos[target]
		t.Logf("%s: Retracted=%q Deprecated=%q Error=%v in unretracted list=%v", target, info.Retracted, info.Deprecated, info.Error,
			slices.Contains(versions[mv(target.Path, "")].Versions, target.Version))
	}

	if l := infos[mv(fsnotify, "v1.5.3")]; len(l.Retracted) == 0 {
		t.Errorf("v1.5.3 is retracted and go list does not say so: %+v", l)
	}
	if l := infos[mv(fsnotify, "v1.5.4")]; len(l.Retracted) != 0 || l.Error != nil {
		t.Errorf("v1.5.4 = %+v", l)
	}
	if l := infos[mv("github.com/golang/protobuf", "v1.5.4")]; l.Deprecated == "" {
		t.Errorf("github.com/golang/protobuf is deprecated and go list -u does not say so: %+v", l)
	}
	list := versions[mv(fsnotify, "")].Versions
	if slices.Contains(list, "v1.5.3") || !slices.Contains(list, "v1.5.4") {
		t.Errorf("unretracted versions of fsnotify: %v", list)
	}

	adv := nothingKnown()
	good := downloaded{Sum: "h1:x", GoModSum: "h1:y"}
	retracted := cleanFact(update{name: fsnotify, from: "v1.5.2", to: "v1.5.3"}, good, true,
		infos[mv(fsnotify, "v1.5.3")], true, versions[mv(fsnotify, "")], true, adv)
	if retracted.OK || !strings.Contains(retracted.Value, "retracted:") {
		t.Errorf("Clean for the retracted version = %+v", retracted)
	}
	clean := cleanFact(update{name: fsnotify, from: "v1.5.3", to: "v1.5.4"}, good, true,
		infos[mv(fsnotify, "v1.5.4")], true, versions[mv(fsnotify, "")], true, adv)
	if !clean.Holds() {
		t.Errorf("Clean for the good version = %+v", clean)
	}
}

// TestLiveIndexNotFound is part of the other experiment of section 10.
// The commit golang.org/x/mod v0.2.0 points at is dated
// 2020-01-02T17:33:45Z, and the index has no line for that version in the
// 100,000 lines (50 pages) that follow. Why was not established; a tag
// made well after its commit would look like this. Whatever the reason,
// a version that is not found must come back unknown, with no time, and
// never with the commit time.
func TestLiveIndexNotFound(t *testing.T) {
	live(t)
	ctx := context.Background()
	infos, err := list(ctx, liveTool(t), nil, []module.Version{mv("golang.org/x/mod", "v0.2.0")})
	if err != nil {
		t.Fatal(err)
	}
	info := infos[mv("golang.org/x/mod", "v0.2.0")]
	if info.Time == nil {
		t.Fatalf("no commit time: %+v", info)
	}
	ix := &index{client: &http.Client{Timeout: time.Minute}, url: defaultIndexURL, limit: indexPageLimit, perVersion: 3, left: 3}
	got := seenFact(ctx, ix, "golang.org/x/mod", "v0.2.0", *info.Time, time.Now())
	t.Logf("commit time %s; FirstSeen = %+v", info.Time.Format(time.RFC3339), got)
	if got.Known() {
		t.Errorf("found within 3 pages: %+v; the experiment's premise no longer holds", got)
	}
	if got.OK || !got.Time.IsZero() || !strings.HasPrefix(got.Value, "unknown:") {
		t.Errorf("FirstSeen = %+v, want unknown with no time", got)
	}
}
