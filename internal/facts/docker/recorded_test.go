package docker

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/config"
	"github.com/sadbox/dep-review/internal/facts"
)

// The digests and times below are what the registries answered when
// testdata/recorded was written (see fixture_test.go).
const (
	golang126Bookworm  = "sha256:dc40a13b61304647ed7e5d581d246b86413dfc29d63c6d018310feb93cd98fc0"
	golang127Bookworm  = "sha256:4fa7c968ba93f1635670522dbb01a2c78150443e1385746924566079f36570ea"
	golang1270Bookworm = "sha256:ded31c68586d2e49e760acc2e65a884b23d032e9bbbed0ae0c55abd3fcaf4452"
	node22Slim         = "sha256:e9f565d32859f0cbfb52125eafe8be39390f24dac302dc3cdf566e8ba3ab21ee"
	node24Slim         = "sha256:dc26ae92c9fb15cf6b1d63e20f0944b2efe0f115b20e00be48fb23fceb061c54"
	// For both distroless repositories: the digest the nonroot tag had
	// before the current one, and the current one.
	debian12NonrootOld = "sha256:1b7b9f0f0e0a1d2155f531db587cc48ec26aaf97ab64364225f5bf18a054e66a"
	debian12Nonroot    = "sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab"
	debian13NonrootOld = "sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931"
	debian13Nonroot    = "sha256:8ce6dd87e9823c5b48dcfb2c8604714ccb351ce59607327bcc4957448da279b5"
	// No image has this digest.
	madeUpDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

	golang127Pushed   = "2026-11-10T18:33:44.343824Z"
	node24Pushed      = "2026-11-11T20:39:58.583762Z"
	debian12Upload    = "2026-08-21T18:12:16.959Z"
	debian13Upload    = "2026-11-22T21:10:10.799Z"
	recordedAtRFC3339 = "2026-11-23T04:00:00Z"
)

// defaultPolicy is the embedded policy, the one every repository starts
// from.
func defaultPolicy(t *testing.T) allow.Policy {
	t.Helper()
	c, err := config.Load(nil)
	if err != nil {
		t.Fatal(err)
	}
	return c.Policy()
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	at, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return at
}

// dockerfile is one changed Dockerfile, an ordinary file at both commits.
func dockerfile(path, base, head string) facts.File {
	return facts.File{Path: path, BaseMode: "100644", HeadMode: "100644", Base: []byte(base), Head: []byte(head)}
}

// summarise is one update's facts on one line: what each fact answers,
// without the wording of its value.
func summarise(u allow.UpdateFacts) string {
	answer := func(f allow.Fact) string {
		switch {
		case f.Source == "":
			return "ungathered"
		case f.Unavailable:
			return "unavailable"
		case f.OK:
			return "yes"
		}
		return "no"
	}
	seen := "unknown"
	if u.FirstSeen.Known() {
		seen = u.FirstSeen.Time.UTC().Format(time.RFC3339Nano)
	}
	return fmt.Sprintf("%s %s -> %s: listed=%s known=%s new=%s increase=%s major=%s bound=%s clean=%s noregress=%s securityfix=%s superseded=%s firstseen=%s",
		u.Name, shorten(u.From), shorten(u.To),
		answer(u.Listed), answer(u.Known), answer(u.NewName), answer(u.Increase), answer(u.Major),
		answer(u.Bound), answer(u.Clean), answer(u.NoRegress), answer(u.SecurityFix), answer(u.Superseded), seen)
}

// shorten cuts a version's digest to its first twelve hex digits.
func shorten(version string) string {
	tag, digest, found := strings.Cut(version, "@")
	if !found {
		tag, digest = "", version
	}
	return tag + "@" + strings.TrimPrefix(digest, "sha256:")[:12]
}

// checkExplained fails when a fact of u does not say what was seen. The
// facts read from the Dockerfiles and the list always have a source. The
// three the registry is asked for have one whenever the registry was
// asked, answered or not; without one, the value must say that nothing
// could be established and why.
func checkExplained(t *testing.T, u allow.UpdateFacts) {
	t.Helper()
	for name, f := range map[string]allow.Fact{
		"Known": u.Known, "Listed": u.Listed, "NewName": u.NewName, "Increase": u.Increase, "Major": u.Major,
		"NoRegress": u.NoRegress, "SecurityFix": u.SecurityFix,
	} {
		if f.Value == "" || !f.Gathered() {
			t.Errorf("%s %s: no value, or not an answer: %+v", u.Name, name, f)
		}
	}
	for name, f := range map[string]allow.Fact{"Bound": u.Bound, "Clean": u.Clean} {
		if f.Value == "" || (f.Source == "" && !strings.HasPrefix(f.Value, "not established: ")) {
			t.Errorf("%s %s: no value, or neither a source nor a reason: %+v", u.Name, name, f)
		}
	}
	if s := u.FirstSeen; s.Value == "" || (s.Source == "" && !strings.HasPrefix(s.Value, "not established: ")) {
		t.Errorf("%s FirstSeen: no value, or neither a source nor a reason: %+v", u.Name, s)
	}
	// Superseded is an answer whenever the registry named a digest for
	// the tag, and unset otherwise.
	if u.Superseded != (allow.Fact{}) && (!u.Superseded.Gathered() || u.Superseded.OK == u.Bound.OK) {
		t.Errorf("%s Superseded %+v beside Bound %+v", u.Name, u.Superseded, u.Bound)
	}
	// Read and Veto are the deciding job's to set, for Docker too.
	if u.NameCreated != (allow.TimeFact{}) || u.Veto != nil || u.Read != "" {
		t.Errorf("%s: NameCreated, Veto or Read set: %+v", u.Name, u)
	}
}

// decide is allow.Decide for a gathered result, as the deciding job would
// call it: with the two facts this gatherer does not gather holding, the
// read state Docker has by rule, and a pull request opened an hour ago.
func decide(res facts.Result, policy allow.Policy, now time.Time) allow.Decision {
	return decideOpened(res, policy, now.Add(-time.Hour), now)
}

// decideOpened is decide for a pull request opened at the given time.
func decideOpened(res facts.Result, policy allow.Policy, opened, now time.Time) allow.Decision {
	updates := append([]allow.UpdateFacts(nil), res.Updates...)
	for i := range updates {
		updates[i].Read = allow.ReadNotApplicable
	}
	return allow.Decide(allow.PRFacts{
		Ecosystem:        allow.Docker,
		Identity:         allow.Yes("assumed by the test", "test"),
		Shape:            res.Shape,
		ChecksConfigured: allow.Yes("assumed by the test", "test"),
		Opened:           opened,
		Updates:          updates,
	}, policy, now)
}

// An ordinary multi-stage Dockerfile.
const (
	appBase = "# syntax=docker/dockerfile:1\n" +
		"FROM golang:1.26-bookworm@" + golang126Bookworm + " AS build\n" +
		"WORKDIR /src\n" +
		"COPY . .\n" +
		"RUN CGO_ENABLED=0 go build -o /out/app .\n" +
		"\n" +
		"FROM gcr.io/distroless/static-debian13:nonroot@" + debian13NonrootOld + "\n" +
		"COPY --from=build /out/app /app\n" +
		"ENTRYPOINT [\"/app\"]\n"
	appHead = "# syntax=docker/dockerfile:1\n" +
		"FROM golang:1.27-bookworm@" + golang127Bookworm + " AS build\n" +
		"WORKDIR /src\n" +
		"COPY . .\n" +
		"RUN CGO_ENABLED=0 go build -o /out/app .\n" +
		"\n" +
		"FROM gcr.io/distroless/static-debian13:nonroot@" + debian13Nonroot + "\n" +
		"COPY --from=build /out/app /app\n" +
		"ENTRYPOINT [\"/app\"]\n"
)

// recordedCase is one pull request against the recorded registries.
type recordedCase struct {
	name  string
	files []facts.File
	// updates is summarise of each expected update, in order.
	updates []string
	// decisions is what allow.Decide makes of the result with the
	// embedded policy, at each of the given times.
	decisions []decisionAt
}

type decisionAt struct {
	now     string
	outcome allow.Outcome
	reasons []allow.Reason
	// notBefore is the decision's NotBefore; empty for person.
	notBefore string
}

var recordedCases = []recordedCase{
	{
		// The distroless tag was rebuilt seven hours before the recording,
		// so the pull request waits for it.
		name:  "golang minor and distroless refresh in one Dockerfile",
		files: []facts.File{dockerfile("Dockerfile", appBase, appHead)},
		updates: []string{
			"docker.io/library/golang 1.26-bookworm@dc40a13b6130 -> 1.27-bookworm@4fa7c968ba93: listed=yes known=yes new=no increase=yes major=no bound=yes clean=yes noregress=yes securityfix=no superseded=no firstseen=" + golang127Pushed,
			"gcr.io/distroless/static-debian13 nonroot@aafe993665bf -> nonroot@8ce6dd87e982: listed=yes known=yes new=no increase=yes major=no bound=yes clean=yes noregress=yes securityfix=no superseded=no firstseen=" + debian13Upload,
		},
		decisions: []decisionAt{
			{now: recordedAtRFC3339, outcome: allow.Wait, reasons: []allow.Reason{allow.ReasonAge}, notBefore: "2026-11-25T21:10:10.799Z"},
			// 72 h after the upload, to the millisecond.
			{now: "2026-11-25T21:10:10.798Z", outcome: allow.Wait, reasons: []allow.Reason{allow.ReasonAge}, notBefore: "2026-11-25T21:10:10.799Z"},
			{now: "2026-11-25T21:10:10.799Z", outcome: allow.Merge},
		},
	},
	{
		name: "the same update in two Dockerfiles is one update",
		files: []facts.File{
			dockerfile("Dockerfile", appBase, appHead),
			dockerfile("deploy/Dockerfile.dev", appBase, appHead),
		},
		updates: []string{
			"docker.io/library/golang 1.26-bookworm@dc40a13b6130 -> 1.27-bookworm@4fa7c968ba93: listed=yes known=yes new=no increase=yes major=no bound=yes clean=yes noregress=yes securityfix=no superseded=no firstseen=" + golang127Pushed,
			"gcr.io/distroless/static-debian13 nonroot@aafe993665bf -> nonroot@8ce6dd87e982: listed=yes known=yes new=no increase=yes major=no bound=yes clean=yes noregress=yes securityfix=no superseded=no firstseen=" + debian13Upload,
		},
		decisions: []decisionAt{{now: "2026-11-26T00:00:00Z", outcome: allow.Merge}},
	},
	{
		name: "golang same-tag digest refresh",
		files: []facts.File{dockerfile("Dockerfile",
			"FROM golang:1.27-bookworm@"+golang1270Bookworm+"\n",
			"FROM golang:1.27-bookworm@"+golang127Bookworm+"\n")},
		updates: []string{
			"docker.io/library/golang 1.27-bookworm@ded31c68586d -> 1.27-bookworm@4fa7c968ba93: listed=yes known=yes new=no increase=yes major=no bound=yes clean=yes noregress=yes securityfix=no superseded=no firstseen=" + golang127Pushed,
		},
		decisions: []decisionAt{
			{now: recordedAtRFC3339, outcome: allow.Merge},
			// 72 h after the tag was pushed, to the microsecond.
			{now: "2026-11-13T18:33:44.343823Z", outcome: allow.Wait, reasons: []allow.Reason{allow.ReasonAge}, notBefore: "2026-11-13T18:33:44.343824Z"},
			{now: "2026-11-13T18:33:44.343824Z", outcome: allow.Merge},
		},
	},
	{
		// Bound, three months old, and a person's: GCR marks every
		// manifest of static-debian12's last build deprecated.
		name: "distroless refresh of an image the registry marks deprecated",
		files: []facts.File{dockerfile("Dockerfile",
			"FROM gcr.io/distroless/static-debian12:nonroot@"+debian12NonrootOld+"\n",
			"FROM gcr.io/distroless/static-debian12:nonroot@"+debian12Nonroot+"\n")},
		updates: []string{
			"gcr.io/distroless/static-debian12 nonroot@1b7b9f0f0e0a -> nonroot@afa5c872c891: listed=yes known=yes new=no increase=yes major=no bound=yes clean=no noregress=yes securityfix=no superseded=no firstseen=" + debian12Upload,
		},
		decisions: []decisionAt{{now: recordedAtRFC3339, outcome: allow.Person, reasons: []allow.Reason{allow.ReasonNotClean}}},
	},
	{
		name: "node major with a platform flag",
		files: []facts.File{dockerfile("web/Dockerfile",
			"FROM --platform=$BUILDPLATFORM node:22-bookworm-slim@"+node22Slim+" AS assets\nRUN npm ci\n",
			"FROM --platform=$BUILDPLATFORM node:24-bookworm-slim@"+node24Slim+" AS assets\nRUN npm ci\n")},
		updates: []string{
			"docker.io/library/node 22-bookworm-slim@e9f565d32859 -> 24-bookworm-slim@dc26ae92c9fb: listed=yes known=yes new=no increase=yes major=yes bound=yes clean=yes noregress=yes securityfix=no superseded=no firstseen=" + node24Pushed,
		},
		decisions: []decisionAt{
			// A listed major needs 14 days.
			{now: recordedAtRFC3339, outcome: allow.Wait, reasons: []allow.Reason{allow.ReasonAge}, notBefore: "2026-11-25T20:39:58.583762Z"},
			{now: "2026-11-26T00:00:00Z", outcome: allow.Merge},
		},
	},
	{
		// The pin is a digest the tag had earlier: what a pull request
		// looks like once the publisher has rebuilt the tag again.
		name: "pin the tag has moved away from",
		files: []facts.File{dockerfile("Dockerfile",
			"FROM golang:1.27-bookworm@"+golang126Bookworm+"\n",
			"FROM golang:1.27-bookworm@"+golang1270Bookworm+"\n")},
		updates: []string{
			"docker.io/library/golang 1.27-bookworm@dc40a13b6130 -> 1.27-bookworm@ded31c68586d: listed=yes known=yes new=no increase=yes major=no bound=no clean=no noregress=yes securityfix=no superseded=yes firstseen=unknown",
		},
		// Not a person's: Dependabot refreshes the digest itself.
		decisions: []decisionAt{{now: recordedAtRFC3339, outcome: allow.Wait, reasons: []allow.Reason{allow.ReasonSuperseded}}},
	},
	{
		// golang:1.28-bookworm did not exist when this was recorded.
		name: "tag the registry does not have",
		files: []facts.File{dockerfile("Dockerfile",
			"FROM golang:1.27-bookworm@"+golang127Bookworm+"\n",
			"FROM golang:1.28-bookworm@"+madeUpDigest+"\n")},
		updates: []string{
			"docker.io/library/golang 1.27-bookworm@4fa7c968ba93 -> 1.28-bookworm@000000000000: listed=yes known=yes new=no increase=yes major=no bound=no clean=no noregress=yes securityfix=no superseded=ungathered firstseen=unknown",
		},
		decisions: []decisionAt{{now: recordedAtRFC3339, outcome: allow.Person,
			reasons: []allow.Reason{allow.ReasonNotBound, allow.ReasonNotClean, allow.ReasonFirstSeenUnknown}}},
	},
}

func TestRecorded(t *testing.T) {
	policy := defaultPolicy(t)
	recording := os.Getenv(recordEnv) != ""

	for _, tc := range recordedCases {
		t.Run(tc.name, func(t *testing.T) {
			replay := &replayer{}
			var transport http.RoundTripper = replay
			if recording {
				transport = &recorder{next: http.DefaultTransport, keepGCR: map[string]bool{
					"nonroot": true, debian12NonrootOld: true, debian12Nonroot: true, debian13NonrootOld: true, debian13Nonroot: true,
				}}
			}
			in := facts.Input{
				Files:  tc.files,
				Policy: policy,
				HTTP:   &http.Client{Transport: transport},
				Now:    func() time.Time { return mustTime(t, recordedAtRFC3339) },
			}
			res, err := New().Gather(context.Background(), in)
			if err != nil {
				t.Fatal(err)
			}
			if !res.Shape.Holds() {
				t.Fatalf("Shape: %+v", res.Shape)
			}
			if len(res.Artifacts) != 0 {
				t.Errorf("Artifacts: %+v, want none: nothing of an image is read", res.Artifacts)
			}

			var got []string
			for _, u := range res.Updates {
				checkExplained(t, u)
				got = append(got, summarise(u))
			}
			if !reflect.DeepEqual(got, tc.updates) {
				t.Errorf("updates:\n got  %s\n want %s", strings.Join(got, "\n      "), strings.Join(tc.updates, "\n      "))
			}

			for _, want := range tc.decisions {
				d := decide(res, policy, mustTime(t, want.now))
				if d.Outcome != want.outcome || !reflect.DeepEqual(d.Reasons, want.reasons) {
					t.Errorf("at %s: %s %v, want %s %v", want.now, d.Outcome, d.Reasons, want.outcome, want.reasons)
				}
				if want.notBefore != "" && !d.NotBefore.Equal(mustTime(t, want.notBefore)) {
					t.Errorf("at %s: not before %s, want %s", want.now, d.NotBefore.UTC().Format(time.RFC3339Nano), want.notBefore)
				}
			}

			// Nothing but the fixed endpoints, and never a manifest body,
			// a blob or a config.
			for _, asked := range replay.asked {
				method, rawURL, _ := strings.Cut(asked, " ")
				ok := false
				switch {
				case strings.HasPrefix(rawURL, "https://auth.docker.io/token?"),
					strings.HasPrefix(rawURL, "https://hub.docker.com/v2/repositories/"),
					strings.HasPrefix(rawURL, "https://gcr.io/v2/") && strings.HasSuffix(rawURL, "/tags/list"):
					ok = method == http.MethodGet
				case strings.HasPrefix(rawURL, "https://registry-1.docker.io/v2/") && strings.Contains(rawURL, "/manifests/"),
					strings.HasPrefix(rawURL, "https://gcr.io/v2/") && strings.Contains(rawURL, "/manifests/"):
					ok = method == http.MethodHead
				}
				if !ok {
					t.Errorf("asked %s", asked)
				}
			}
		})
	}
}

// TestRecordedValues pins the wording of the facts of one real update,
// since the pull request comment shows it.
func TestRecordedValues(t *testing.T) {
	if os.Getenv(recordEnv) != "" {
		t.Skip("recording")
	}
	in := facts.Input{
		Files:  []facts.File{dockerfile("Dockerfile", appBase, appHead)},
		Policy: defaultPolicy(t),
		HTTP:   &http.Client{Transport: &replayer{}},
	}
	res, err := New().Gather(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	wantShape := allow.Yes("2 FROM line(s) changed in 1 Dockerfile(s), in tag and digest only", shapeSource)
	if res.Shape != wantShape {
		t.Errorf("Shape:\n got  %+v\n want %+v", res.Shape, wantShape)
	}
	if len(res.Updates) != 2 {
		t.Fatalf("%d updates, want 2", len(res.Updates))
	}

	golang := res.Updates[0]
	const headTag = "HEAD https://registry-1.docker.io/v2/library/golang/manifests/1.27-bookworm"
	const hubTag = "GET https://hub.docker.com/v2/repositories/library/golang/tags/1.27-bookworm (tag_last_pushed)"
	want := allow.UpdateFacts{
		Name:        "docker.io/library/golang",
		From:        "1.26-bookworm@" + golang126Bookworm,
		To:          "1.27-bookworm@" + golang127Bookworm,
		Known:       allow.Yes("listed image", listSource),
		Listed:      allow.Yes("docker.io/library/golang is on the list", listSource),
		NewName:     allow.No("the image is in the Dockerfile at the base commit", shapeSource),
		Increase:    allow.Yes("1.26-bookworm to 1.27-bookworm", shapeSource),
		Major:       allow.No("leading version component stays 1", shapeSource),
		Bound:       allow.Yes("tag 1.27-bookworm resolves to the pinned "+golang127Bookworm+" now", headTag),
		FirstSeen:   allow.At(mustTime(t, golang127Pushed), hubTag),
		Clean:       allow.Yes("the registry serves the pinned digest as tag 1.27-bookworm now; Docker Hub has no deprecation mark to read, and no advisory source covers container images", headTag),
		NoRegress:   allow.Yes("nothing to compare: a base image has no install script, and its attestations are not read", "not applicable to Docker"),
		SecurityFix: allow.No("no advisory source covers container images", "not applicable to Docker"),
		Superseded:  allow.No("tag 1.27-bookworm still resolves to the pinned digest", headTag),
	}
	if !reflect.DeepEqual(golang, want) {
		t.Errorf("golang:\n got  %+v\n want %+v", golang, want)
	}

	distroless := res.Updates[1]
	const list = "GET https://gcr.io/v2/distroless/static-debian13/tags/list"
	wantSeen := allow.At(mustTime(t, debian13Upload), list+" (timeUploadedMs)")
	if distroless.FirstSeen != wantSeen {
		t.Errorf("distroless FirstSeen:\n got  %+v\n want %+v", distroless.FirstSeen, wantSeen)
	}
	wantBound := allow.Yes("tag nonroot resolves to the pinned "+debian13Nonroot+" now", "HEAD https://gcr.io/v2/distroless/static-debian13/manifests/nonroot")
	if distroless.Bound != wantBound {
		t.Errorf("distroless Bound:\n got  %+v\n want %+v", distroless.Bound, wantBound)
	}
	wantClean := allow.Yes("the registry serves the pinned digest as tag nonroot now and does not mark it deprecated; no advisory source covers container images", list)
	if distroless.Clean != wantClean {
		t.Errorf("distroless Clean:\n got  %+v\n want %+v", distroless.Clean, wantClean)
	}

	// The deprecated one, for the wording the owner will read.
	in.Files = []facts.File{dockerfile("Dockerfile",
		"FROM gcr.io/distroless/static-debian12:nonroot@"+debian12NonrootOld+"\n",
		"FROM gcr.io/distroless/static-debian12:nonroot@"+debian12Nonroot+"\n")}
	res, err = New().Gather(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	wantClean = allow.No("the registry marks the pinned digest deprecated (it carries the tag deprecated-public-image-<digest>)",
		"GET https://gcr.io/v2/distroless/static-debian12/tags/list")
	if len(res.Updates) != 1 || res.Updates[0].Clean != wantClean {
		t.Errorf("deprecated distroless:\n got  %+v\n want Clean %+v", res.Updates, wantClean)
	}
}
