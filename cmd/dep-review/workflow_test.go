package main

import (
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sadbox/dep-review/internal/land"
)

// The tests here read .github/workflows/gate.yml as text and pin its
// trust layout (the comment at its top). They are deliberately literal: a
// change to the workflow that moves a secret, drops a verification or
// widens a permission has to change a test in the same commit.

func readGate(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../../.github/workflows/gate.yml")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// gateJobs splits .github/workflows/gate.yml into its jobs' text.
func gateJobs(t *testing.T) map[string]string {
	t.Helper()
	s := readGate(t)
	i := strings.Index(s, "\njobs:\n")
	if i < 0 {
		t.Fatal("no jobs")
	}
	jobs := map[string]string{}
	re := regexp.MustCompile(`(?m)^  ([a-z][a-z0-9_-]*):\n`)
	body := s[i:]
	locs := re.FindAllStringSubmatchIndex(body, -1)
	for k, l := range locs {
		end := len(body)
		if k+1 < len(locs) {
			end = locs[k+1][0]
		}
		jobs[body[l[2]:l[3]]] = body[l[0]:end]
	}
	return jobs
}

// The jobs, and which of the two paths each runs on. A job added to the
// workflow has to be placed here, and with that in every test below.
func TestJobs(t *testing.T) {
	var names []string
	for name := range gateJobs(t) {
		names = append(names, name)
	}
	sort.Strings(names)
	if got, want := strings.Join(names, " "), "build classify fetch publish refresh reread review"; got != want {
		t.Fatalf("jobs %q, want %q", got, want)
	}
}

// permissionsOf is a job's own permissions, "name: level" each, sorted;
// "{}" for none.
func permissionsOf(t *testing.T, name, job string) string {
	t.Helper()
	if strings.Contains(job, "\n    permissions: {}\n") {
		return "{}"
	}
	i := strings.Index(job, "\n    permissions:\n")
	if i < 0 {
		t.Errorf("%s has no permissions of its own", name)
		return ""
	}
	var out []string
	for _, line := range strings.Split(job[i+len("\n    permissions:\n"):], "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !strings.HasPrefix(line, "      ") || strings.HasPrefix(line, "       ") {
			break
		}
		out = append(out, trimmed)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// Every job states its permissions, and they are exactly these. The
// workflow's own default is none. review and reread hold the OIDC token
// and have no access to the repository; publish gets nothing from the job
// token (it uses the app's).
func TestPermissions(t *testing.T) {
	if !strings.Contains(readGate(t), "\npermissions: {}\n") {
		t.Error("the workflow's default permissions are not {}")
	}
	want := map[string]string{
		"build":    "contents: read",
		"classify": "contents: read, pull-requests: read",
		"fetch":    "contents: read, pull-requests: read",
		"refresh":  "contents: read, pull-requests: read",
		"review":   "id-token: write",
		"reread":   "id-token: write",
		"publish":  "{}",
	}
	for name, job := range gateJobs(t) {
		if got := permissionsOf(t, name, job); got != want[name] {
			t.Errorf("%s has permissions %q, want %q", name, got, want[name])
		}
	}
}

// Every job has a timeout and runs on the pinned runner image.
func TestTimeoutsAndRunners(t *testing.T) {
	for name, job := range gateJobs(t) {
		if !regexp.MustCompile(`(?m)^    timeout-minutes: [0-9]+$`).MatchString(job) {
			t.Errorf("%s has no timeout-minutes", name)
		}
		if !strings.Contains(job, "\n    runs-on: ubuntu-26.04\n") {
			t.Errorf("%s does not run on ubuntu-26.04", name)
		}
	}
}

// publish does not decide on facts older than land.MaxFactsAge (spec
// section 11, amendment 52). A run that goes as it should must never meet
// that bound: from the moment the facts are gathered to the moment
// publish decides is at most the timeouts of the jobs in between, and an
// hour is left on top for runners to start and for the publishes queued
// ahead. Whoever raises a timeout here raises the bound with it.
func TestFactsAgeCoversARun(t *testing.T) {
	jobs := gateJobs(t)
	timeout := func(name string) time.Duration {
		t.Helper()
		m := regexp.MustCompile(`(?m)^    timeout-minutes: ([0-9]+)$`).FindStringSubmatch(jobs[name])
		if m == nil {
			t.Fatalf("%s has no timeout-minutes", name)
		}
		minutes, err := strconv.Atoi(m[1])
		if err != nil {
			t.Fatal(err)
		}
		return time.Duration(minutes) * time.Minute
	}
	const queue = time.Hour
	for path, run := range map[string]time.Duration{
		"an event's run":  timeout("fetch") + timeout("review") + timeout("publish"),
		"a scheduled run": timeout("refresh") + timeout("reread") + timeout("publish"),
	} {
		if land.MaxFactsAge < run+queue {
			t.Errorf("%s may take %s from gathering to deciding, and publish refuses facts older than %s: less than an hour is left for queues",
				path, run, land.MaxFactsAge)
		}
	}
	if want := 4 * time.Hour; land.MaxFactsAge != want {
		t.Errorf("the bound is %s; the comment a failed run gets, the README and the spec say %s", land.MaxFactsAge, want)
	}
}

// publish is the only job with the gate app's token, a secret or an
// environment. The jobs that read what a pull request, a dependency, a
// registry or the model wrote (classify, fetch, refresh, review, reread)
// hold no secret at all, and the two that ask the model not even the
// job's token for the repository.
func TestOnlyPublishHoldsSecrets(t *testing.T) {
	jobs := gateJobs(t)
	for name, job := range jobs {
		for _, secret := range []string{"secrets.", "create-github-app-token", "environment:", "vars.", "DEP_REVIEW_APP_KEY", "PUSHOVER"} {
			if has := strings.Contains(job, secret); has != (name == "publish") {
				t.Errorf("%s: has %q: %v", name, secret, has)
			}
		}
	}
	for _, name := range []string{"review", "reread"} {
		for _, token := range []string{"github.token", "GH_TOKEN", "actions/checkout"} {
			if strings.Contains(jobs[name], token) {
				t.Errorf("%s uses %q: it needs nothing of the repository", name, token)
			}
		}
	}
	// publish's GH_TOKEN is the app's, and the job token is used nowhere
	// in it.
	if !strings.Contains(jobs["publish"], "GH_TOKEN: ${{ steps.app.outputs.token }}") || strings.Contains(jobs["publish"], "github.token") {
		t.Error("publish does not run with the app's token alone")
	}
}

// The model is asked by two jobs and no other: review on an event's run
// and reread on a scheduled one. They alone have the OIDC token. Each
// condition names its one event and cannot be forced with always(). The
// two events are the ones the federation rule admits; a manual dispatch
// runs neither.
func TestOnlyTheReviewJobsAskTheModel(t *testing.T) {
	jobs := gateJobs(t)
	for name, job := range jobs {
		asks := name == "review" || name == "reread"
		if has := strings.Contains(job, "id-token"); has != asks {
			t.Errorf("%s: mentions id-token: %v", name, has)
		}
		if has := strings.Contains(job, "anthropic") || strings.Contains(job, "federation"); has != asks {
			t.Errorf("%s: is handed the federation IDs: %v", name, has)
		}
	}
	for name, want := range map[string]struct{ cond, needs string }{
		"review": {"github.event_name == 'workflow_run' && needs.fetch.outputs.review == 'true'", "[build, fetch]"},
		"reread": {"github.event_name == 'schedule' && needs.refresh.outputs.review == 'true'", "[build, refresh]"},
	} {
		job := jobs[name]
		if !strings.Contains(job, "\n    if: "+want.cond+"\n") {
			t.Errorf("%s's condition is not %q", name, want.cond)
		}
		if strings.Contains(job, "always()") || strings.Contains(job, "cancelled()") || strings.Contains(job, "failure()") {
			t.Errorf("%s's condition has a status function, which would run it when a job it needs was skipped", name)
		}
		if !strings.Contains(job, "\n    needs: "+want.needs+"\n") {
			t.Errorf("%s does not need %s", name, want.needs)
		}
	}
	// The scheduled path is build, refresh, reread and publish. refresh
	// runs for nothing else, asks no model, and says whether a read is
	// left for one.
	refresh := jobs["refresh"]
	if !strings.Contains(refresh, "\n    if: github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'\n") {
		t.Error("refresh's condition is not the schedule")
	}
	if strings.Contains(refresh, `dep-review" review`) || strings.Contains(refresh, `dep-review" reread`) {
		t.Error("refresh asks the model")
	}
	if !strings.Contains(refresh, "      review: ${{ steps.refresh.outputs.review }}\n") {
		t.Error("refresh does not say whether a read is left for the model")
	}
	// The event's jobs do not run on a schedule.
	if !strings.Contains(jobs["classify"], "\n    if: github.event_name == 'workflow_run'\n") {
		t.Error("classify's condition is not the workflow_run event")
	}
	if !strings.Contains(jobs["fetch"], "\n    needs: [build, classify]\n") {
		t.Error("fetch does not need classify")
	}
}

// The scheduled review job is the event's review job over again: the
// OIDC token and nothing else, the federation IDs through env, no token
// for the repository, and the refreshed artifact used only after it was
// checked against refresh's checksum. No job that parses what a pull
// request wrote (classify, fetch, refresh) holds a secret or the OIDC
// token, and neither review job is handed a verdict by one of them: what
// refresh says the comment remembers is a list of reads to skip, in a
// file publish never opens.
func TestScheduledReviewJob(t *testing.T) {
	jobs := gateJobs(t)
	reread := jobs["reread"]
	if got := permissionsOf(t, "reread", reread); got != "id-token: write" {
		t.Errorf("reread has permissions %q, want the OIDC token and nothing else", got)
	}
	for _, bad := range []string{"secrets.", "environment:", "vars.", "github.token", "GH_TOKEN", "actions/checkout", "app_slug", "app-slug", "setup-go", "setup-node"} {
		if strings.Contains(reread, bad) {
			t.Errorf("reread has %q", bad)
		}
	}
	step := stepOf(t, reread, "Review")
	for _, want := range []string{
		"RULE_ID: ${{ inputs.anthropic_federation_rule_id }}", "ORG_ID: ${{ inputs.anthropic_organization_id }}",
		`--refreshed "$RUNNER_TEMP/refreshed"`, `--out "$RUNNER_TEMP/reverdicts"`, `--federation-rule-id "$RULE_ID"`,
	} {
		if !strings.Contains(step, want) {
			t.Errorf("reread's review step lacks %q", want)
		}
	}
	// Its timeout is review's: a read is asked about whole, so a read
	// that fits an event's run has to fit a scheduled one.
	timeoutRE := regexp.MustCompile(`(?m)^    timeout-minutes: ([0-9]+)$`)
	if a, b := timeoutRE.FindString(reread), timeoutRE.FindString(jobs["review"]); a == "" || a != b {
		t.Errorf("reread has %q and review %q", a, b)
	}
	for _, name := range []string{"classify", "fetch", "refresh"} {
		for _, bad := range []string{"id-token", "secrets.", "environment:", "vars.", "anthropic"} {
			if strings.Contains(jobs[name], bad) {
				t.Errorf("%s parses what a pull request wrote and has %q", name, bad)
			}
		}
	}
	// publish takes the scheduled verdicts from reread's artifact, checked
	// against reread's own checksum, and runs whatever became of reread.
	publish := jobs["publish"]
	if !strings.Contains(stepOf(t, publish, "Verify the reverdicts artifact"), "SUMS: ${{ needs.reread.outputs.reverdicts_sums }}") {
		t.Error("publish does not check the scheduled verdicts against reread's sums")
	}
	if strings.Contains(publish, "needs.reread.result") {
		t.Error("publish's condition depends on how reread ended: a reread that failed leaves facts to decide on")
	}
}

// Nothing in the gate runs a container or installs a sandbox runtime:
// v0.2 executes nothing it downloads.
func TestNoContainers(t *testing.T) {
	gate := strings.ToLower(readGate(t))
	for _, bad := range []string{"docker", "gvisor", "runsc", "podman", "container:", "services:", "sandbox"} {
		if strings.Contains(gate, bad) {
			t.Errorf("gate.yml mentions %q", bad)
		}
	}
}

// runScripts is every run: script of the workflow.
func runScripts(t *testing.T, text string) []string {
	t.Helper()
	var out []string
	lines := strings.Split(text, "\n")
	for i := 0; i < len(lines); i++ {
		indent := len(lines[i]) - len(strings.TrimLeft(lines[i], " "))
		rest, ok := strings.CutPrefix(strings.TrimLeft(lines[i], " -"), "run:")
		if !ok {
			continue
		}
		script := rest
		for i+1 < len(lines) && (strings.TrimSpace(lines[i+1]) == "" || len(lines[i+1])-len(strings.TrimLeft(lines[i+1], " ")) > indent) {
			i++
			script += "\n" + lines[i]
		}
		out = append(out, script)
	}
	return out
}

// No expression is expanded inside a script: every value from an input,
// an event or another job reaches a shell through env, as data.
func TestNoExpressionInScripts(t *testing.T) {
	scripts := runScripts(t, readGate(t))
	if len(scripts) < 20 {
		t.Fatalf("found %d run: scripts; the extraction is broken", len(scripts))
	}
	for _, s := range scripts {
		if strings.Contains(s, "${{") {
			t.Errorf("a script expands an expression:\n%s", s)
		}
	}
	// Every expression that reads an input or the event is in a with: or
	// env: value, or in a job's if:.
	for _, line := range strings.Split(readGate(t), "\n") {
		if !strings.Contains(line, "${{") {
			continue
		}
		if !regexp.MustCompile(`^\s+[A-Za-z_-]+: \S*\$\{\{ [^{}]+ \}\}\S*$`).MatchString(line) {
			t.Errorf("an expression outside a plain key: value line: %q", line)
		}
	}
}

// Every job that runs anything from the gate-bin artifact checks it
// against the build job's checksums first: before setting up Go from its
// go.mod, minting the app token, or running the binary.
func TestGateBinVerified(t *testing.T) {
	jobs := gateJobs(t)
	build := jobs["build"]
	if !strings.Contains(build, "gate_sums: ${{ steps.sums.outputs.sums }}") || !strings.Contains(build, "sha256sum") {
		t.Fatal("the build job does not output the gate's checksums")
	}
	// The gate is built from the workflow's own commit, never the
	// caller's or the pull request's.
	if !strings.Contains(build, "repository: ${{ job.workflow_repository }}") || !strings.Contains(build, "ref: ${{ job.workflow_sha }}") {
		t.Error("build does not check out the workflow's own commit")
	}
	n := 0
	for name, job := range jobs {
		if name == "build" {
			continue
		}
		n++
		v := strings.Index(job, "- name: Verify the gate's files")
		if v < 0 {
			t.Errorf("%s does not verify gate-bin", name)
			continue
		}
		if !strings.Contains(job[v:], "GATE_SUMS: ${{ needs.build.outputs.gate_sums }}") || !strings.Contains(job[v:], "sha256sum --check --strict") {
			t.Errorf("%s: the verify step does not check the build job's sums", name)
		}
		for _, use := range []string{`/dep-review" `, "create-github-app-token", "bin/go.mod", "actions/checkout"} {
			if u := strings.Index(job, use); u >= 0 && u < v {
				t.Errorf("%s: %q comes before the verify step", name, use)
			}
		}
		if !strings.Contains(job, `/dep-review" `+name) {
			t.Errorf("%s does not run `dep-review %s`", name, name)
		}
	}
	if n != 6 {
		t.Errorf("%d jobs use gate-bin, want 6 (classify, fetch, review, refresh, reread, publish)", n)
	}
}

// The caller passes the gate exactly the secrets gate.yml declares, never
// `secrets: inherit`, and gate.yml uses no secret it does not declare.
func TestSecretsExplicit(t *testing.T) {
	g := readGate(t)
	example, err := os.ReadFile("../../examples/dep-review.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if regexp.MustCompile(`(?m)^\s*secrets:\s*inherit\b`).Match(example) {
		t.Error("examples/dep-review.yaml uses secrets: inherit")
	}
	call := g[strings.Index(g, "workflow_call:"):strings.Index(g, "\npermissions:")]
	declared := map[string]bool{}
	if i := strings.Index(call, "\n    secrets:\n"); i >= 0 {
		for _, m := range regexp.MustCompile(`(?m)^      ([A-Z][A-Z0-9_]*):$`).FindAllStringSubmatch(call[i:], -1) {
			declared[m[1]] = true
		}
	}
	for _, want := range []string{"DEP_REVIEW_APP_KEY", "PUSHOVER_APP_TOKEN", "PUSHOVER_USER_KEY"} {
		if !declared[want] {
			t.Errorf("gate.yml does not declare secret %s", want)
		}
		if !strings.Contains(string(example), want+": ${{ secrets."+want+" }}") {
			t.Errorf("the example does not pass %s explicitly", want)
		}
	}
	for _, m := range regexp.MustCompile(`secrets\.([A-Za-z0-9_]+)`).FindAllStringSubmatch(g, -1) {
		if !declared[m[1]] {
			t.Errorf("gate.yml uses undeclared secret %s", m[1])
		}
	}
}

// Every artifact passed between jobs is checked against its producer's
// job output before anything uses it: a job holding the run's runtime
// token could otherwise replace, say, the verdicts, and publish would
// merge on them.
func TestArtifactsVerified(t *testing.T) {
	jobs := gateJobs(t)
	for _, a := range []struct {
		name, producer string
		consumers      []string
	}{
		{"classification", "classify", []string{"fetch", "publish"}},
		{"facts", "fetch", []string{"review", "publish"}},
		{"verdicts", "review", []string{"publish"}},
		{"refreshed", "refresh", []string{"reread", "publish"}},
		{"reverdicts", "reread", []string{"publish"}},
	} {
		p := jobs[a.producer]
		out := a.name + "_sums: ${{ steps.sums.outputs.sums }}"
		sums := strings.Index(p, "- name: Checksum the artifact")
		up := strings.Index(p, "name: "+a.name+"\n")
		if !strings.Contains(p, out) || sums < 0 || up < 0 || sums > up {
			t.Errorf("%s does not output the %s artifact's checksums before uploading it", a.producer, a.name)
		}
		for name, job := range jobs {
			consumes := strings.Contains(job, "name: "+a.name+"\n") && name != a.producer
			if name == "publish" {
				consumes = true
			}
			if consumes != slices.Contains(a.consumers, name) {
				t.Errorf("%s downloads %s: %v", name, a.name, consumes)
			}
		}
		for _, c := range a.consumers {
			job := jobs[c]
			dl := strings.Index(job, "name: "+a.name+"\n")
			if c == "publish" {
				dl = strings.Index(job, "pattern: ")
				if dl < 0 || !strings.Contains(job[dl:strings.Index(job[dl:], "\n")+dl], a.name) {
					t.Errorf("publish does not download %s", a.name)
					continue
				}
			}
			v := strings.Index(job, "- name: Verify the "+a.name+" artifact")
			ref := "SUMS: ${{ needs." + a.producer + ".outputs." + a.name + "_sums }}"
			if dl < 0 || v < dl {
				t.Errorf("%s does not verify the %s artifact after downloading it", c, a.name)
				continue
			}
			step := job[v:]
			if next := strings.Index(step[1:], "\n      - "); next >= 0 {
				step = step[:next+1]
			}
			if !strings.Contains(step, ref) || !strings.Contains(step, "sha256sum --check --strict") || !strings.Contains(step, "diff <(find . -type f") {
				t.Errorf("%s: the step that verifies %s does not check the producer's sums and that nothing else is there", c, a.name)
			}
			for _, use := range []string{`/dep-review" `, "create-github-app-token"} {
				if u := strings.Index(job, use); u >= 0 && u < v {
					t.Errorf("%s: %q comes before verifying %s", c, use, a.name)
				}
			}
		}
	}
	// The manifest refresh puts beside the pull requests' directories is
	// the one file publish and reread skip there (sumsFile), and both
	// check every file against it. reread's own artifact has one too.
	if !strings.Contains(jobs["refresh"], `mv "$RUNNER_TEMP/`+sumsFile+`" ./`+sumsFile+"\n") ||
		!strings.Contains(stepOf(t, jobs["publish"], "Verify the refreshed artifact"), "sha256sum --check --strict --quiet ./"+sumsFile+"\n") ||
		!strings.Contains(stepOf(t, jobs["reread"], "Verify the refreshed artifact"), "sha256sum --check --strict --quiet ./"+sumsFile+"\n") {
		t.Errorf("refresh does not write, or publish or reread does not check, the manifest %s", sumsFile)
	}
	if !strings.Contains(jobs["reread"], `mv "$RUNNER_TEMP/`+sumsFile+`" ./`+sumsFile+"\n") ||
		!strings.Contains(stepOf(t, jobs["publish"], "Verify the reverdicts artifact"), "sha256sum --check --strict --quiet ./"+sumsFile) {
		t.Errorf("reread does not write, or publish does not check, the manifest %s", sumsFile)
	}
	// publish downloads these artifacts and no other.
	if !strings.Contains(jobs["publish"], `pattern: "{gate-bin,classification,facts,verdicts,refreshed,reverdicts}"`) {
		t.Error("publish's download pattern changed; so must this test")
	}
	// An artifact with no sums from its producer must not be there at
	// all: publish runs when jobs before it were skipped or failed.
	for _, name := range []string{"classification", "facts", "verdicts", "refreshed", "reverdicts"} {
		if !strings.Contains(jobs["publish"], `if [ -z "$SUMS" ]; then test ! -e "$RUNNER_TEMP/in/`+name+`"; exit; fi`) {
			t.Errorf("publish accepts a %s artifact without sums", name)
		}
	}
}

// stepOf is the step of a job that starts with "- name: <name>", up to
// the next step.
func stepOf(t *testing.T, job, name string) string {
	t.Helper()
	i := strings.Index(job, "\n      - name: "+name+"\n")
	if i < 0 {
		t.Fatalf("no step %q", name)
	}
	step := job[i+1:]
	if next := strings.Index(step, "\n      - "); next >= 0 {
		step = step[:next+1]
	}
	return step
}

// publish serves both paths, and it is the last job of each. On an
// event's run it runs whenever classify said the pull request is one the
// gate handles, whatever became of fetch and review: a run that cannot
// decide has to say so on the pull request, and only publish can. It is
// told how those jobs ended.
func TestPublishRunsOnBothPaths(t *testing.T) {
	publish := gateJobs(t)["publish"]
	if !strings.Contains(publish, "\n    needs: [build, classify, fetch, review, refresh, reread]\n") {
		t.Error("publish does not wait for every other job")
	}
	const cond = `
    if: >-
      !cancelled() && needs.build.result == 'success' &&
      ((needs.classify.result == 'success' &&
        (needs.classify.outputs.kind == 'dependabot' ||
         needs.classify.outputs.kind == 'dependabot-unverified' ||
         needs.classify.outputs.kind == 'dependabot-pending')) ||
       (needs.refresh.result == 'success' && needs.refresh.outputs.publish == 'true'))
`
	if !strings.Contains(publish, cond) {
		t.Errorf("publish's condition is not%s", cond)
	}
	// The kinds are the ones fetch runs for.
	for _, kind := range []string{"dependabot", "dependabot-unverified", "dependabot-pending"} {
		if !strings.Contains(gateJobs(t)["fetch"], "needs.classify.outputs.kind == '"+kind+"'") {
			t.Errorf("fetch does not run for %s", kind)
		}
	}
	decide := stepOf(t, publish, "Decide, comment, merge")
	for _, want := range []string{"FETCH_RESULT: ${{ needs.fetch.result }}", "REVIEW_RESULT: ${{ needs.review.result }}"} {
		if !strings.Contains(decide, want) {
			t.Errorf("the step that decides lacks %q", want)
		}
	}
	// With no facts artifact publish still gets to the step that reports
	// the failed run.
	if !strings.Contains(stepOf(t, publish, "Verify the facts artifact"), `if [ ! -e "$RUNNER_TEMP/in/facts" ]; then echo "no facts artifact"; exit; fi`) {
		t.Error("publish stops at a facts artifact that is not there")
	}
}

// The scheduled run fails when a pull request could not be refreshed, and
// the ones that could are decided first. refresh itself does not fail for
// one pull request: it leaves a directory that says the pull request was
// tried, so publish always runs then, never reads the outputs of a failed
// job, reports what only it can (a pull request with no decision that
// could not be evaluated, a wait past its deadline), and fails the run in
// its last step.
func TestIncompleteRefreshFailsTheRunLast(t *testing.T) {
	jobs := gateJobs(t)
	refresh, publish := jobs["refresh"], jobs["publish"]
	if !strings.Contains(refresh, "      incomplete: ${{ steps.refresh.outputs.incomplete }}\n") {
		t.Error("refresh does not output incomplete")
	}
	if n := strings.Count(refresh, "exit 1"); n != 0 {
		t.Errorf("refresh has %d steps that fail it, want none: publish reports and fails the run", n)
	}
	// What is uploaded and whether publish runs are two questions:
	// publish has work in a run in which refresh wrote nothing (an overdue
	// wait, a notification that was not delivered), and then there is no
	// artifact to sum or upload.
	for _, name := range []string{"Checksum the artifact"} {
		if !strings.Contains(stepOf(t, refresh, name), "        if: steps.refresh.outputs.upload == 'true'\n") {
			t.Errorf("refresh's step %q does not depend on something having been written", name)
		}
	}
	if !strings.Contains(refresh, "      - uses: actions/upload-artifact@v7.0.2\n        if: steps.refresh.outputs.upload == 'true'\n") {
		t.Error("refresh uploads although nothing was written")
	}
	if !strings.Contains(refresh, "      publish: ${{ steps.refresh.outputs.publish }}\n") {
		t.Error("refresh does not say whether publish has something to do")
	}
	last := publish[strings.LastIndex(publish, "\n      - "):]
	for _, want := range []string{"- name: Fail when a PR could not be refreshed\n", "        if: needs.refresh.outputs.incomplete == 'true'\n", "exit 1"} {
		if !strings.Contains(last, want) {
			t.Errorf("publish's last step lacks %q:%s", want, last)
		}
	}
	if strings.Contains(publish, "always()") || strings.Contains(publish, "failure()") {
		t.Error("publish has a status function besides !cancelled()")
	}
}

// One publish at a time in a repository, and none is dropped for it: the
// group is fixed, nothing in progress is cancelled, and more than one may
// wait (by default a group keeps one pending job and cancels it when the
// next arrives, which would lose a pull request's only decision).
func TestPublishIsSerialized(t *testing.T) {
	for name, job := range gateJobs(t) {
		has := strings.Contains(job, "concurrency:")
		if has != (name == "publish") {
			t.Errorf("%s: has a concurrency group: %v", name, has)
		}
	}
	const want = "\n    concurrency:\n      group: dep-review-publish\n      cancel-in-progress: false\n      queue: max\n"
	if !strings.Contains(gateJobs(t)["publish"], want) {
		t.Errorf("publish's concurrency is not%s", want)
	}
}

// The jobs that gather facts run npm, and the npm gatherer refuses a
// major it was not tested with. They take Node, and so npm, from a pinned
// major, not from whatever the runner image has, and restore no cache.
func TestNodePinned(t *testing.T) {
	pin := regexp.MustCompile(`\n      - name: Set up Node\n        uses: actions/setup-node@v[0-9]+\.[0-9]+\.[0-9]+\n        with:\n          node-version: "[0-9]+"\n          package-manager-cache: false\n`)
	n := 0
	for name, job := range gateJobs(t) {
		gathers := strings.Contains(job, `/dep-review" fetch`) || strings.Contains(job, `/dep-review" refresh`)
		loc := pin.FindStringIndex(job)
		if gathers {
			n++
		}
		switch {
		case gathers && (loc == nil || loc[0] > strings.Index(job, `/dep-review" `)):
			t.Errorf("%s gathers facts without a pinned Node before it", name)
		case !gathers && strings.Contains(job, "setup-node"):
			t.Errorf("%s sets up Node and runs no npm", name)
		}
	}
	if n != 2 {
		t.Errorf("%d jobs gather facts, want 2 (fetch, refresh)", n)
	}
}

// The scheduled job, which reads the gate's comment without the app's
// token, learns the app's name from the app_slug input, through env only;
// publish checks the input against the app whose key it holds before it
// decides anything; and the example sets it. No job of an event's run
// before publish looks at the gate's comment, so none is told the name:
// what the comment remembers does not reach the review job.
func TestAppSlugPassed(t *testing.T) {
	g := readGate(t)
	call := g[strings.Index(g, "workflow_call:"):strings.Index(g, "\n    secrets:\n")]
	if i := strings.Index(call, "\n      app_slug:\n"); i < 0 || !strings.Contains(call[i:i+500], "required: true") {
		t.Error("gate.yml does not declare a required app_slug input")
	}
	jobs := gateJobs(t)
	if job := jobs["refresh"]; !strings.Contains(job, "APP_SLUG: ${{ inputs.app_slug }}") || !strings.Contains(job, `--app-slug "$APP_SLUG"`) {
		t.Error("refresh does not get the app's slug from the input")
	}
	for _, name := range []string{"classify", "fetch", "review", "reread"} {
		if job := jobs[name]; job == "" || strings.Contains(job, "app_slug") || strings.Contains(job, "app-slug") {
			t.Errorf("%s is told the gate app's name, or is not a job", name)
		}
	}
	publish := jobs["publish"]
	check := strings.Index(publish, "- name: The app_slug input names this app")
	run := strings.Index(publish, `/dep-review" publish`)
	if check < 0 || run < check {
		t.Fatal("publish does not check the app_slug input before deciding")
	}
	step := publish[check:]
	step = step[:strings.Index(step[1:], "\n      - ")+1]
	for _, want := range []string{"INPUT_SLUG: ${{ inputs.app_slug }}", "        APP_SLUG: ${{ steps.app.outputs.app-slug }}", `if [ "$INPUT_SLUG" != "$APP_SLUG" ]; then`, "exit 1"} {
		if !strings.Contains(step, want) {
			t.Errorf("the step that checks the app_slug input lacks %q", want)
		}
	}

	// publish itself takes the name from the app, never from the input.
	if !strings.Contains(stepOf(t, publish, "Decide, comment, merge"), "DEP_REVIEW_APP_SLUG: ${{ steps.app.outputs.app-slug }}") {
		t.Error("publish does not take its own slug from the app token step")
	}
	example, err := os.ReadFile("../../examples/dep-review.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(example), "\n      app_slug: ") {
		t.Error("the example does not set app_slug")
	}
}

// The inputs are these and no others: the ones v0.1.9 had for its build
// analysis, its Docker comparison, its model session and its notes file
// mean nothing now, and a caller that still passes one should fail at the
// call, not be ignored.
func TestInputs(t *testing.T) {
	g := readGate(t)
	call := g[strings.Index(g, "    inputs:\n"):strings.Index(g, "\n    secrets:\n")]
	var got []string
	for _, m := range regexp.MustCompile(`(?m)^      ([a-z_]+):$`).FindAllStringSubmatch(call, -1) {
		got = append(got, m[1])
	}
	want := "trigger_workflow_path app_slug ignore_ecosystems anthropic_federation_rule_id anthropic_organization_id anthropic_workspace_id anthropic_service_account_id"
	if strings.Join(got, " ") != want {
		t.Errorf("inputs %q, want %q", strings.Join(got, " "), want)
	}
	example, err := os.ReadFile("../../examples/dep-review.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range regexp.MustCompile(`(?m)^      (?:# )?([a-z_]+): `).FindAllStringSubmatch(string(example[strings.Index(string(example), "    with:\n"):]), -1) {
		if !slices.Contains(got, m[1]) {
			t.Errorf("the example sets %s, which is not an input", m[1])
		}
	}
}

// The ignore_ecosystems input reaches classify (which ignores), and
// refresh and publish (which run the identity proof again on the
// scheduled path and must skip what classify ignores), through env only,
// and the example documents it commented out.
func TestIgnoreEcosystemsPassed(t *testing.T) {
	g := readGate(t)
	call := g[strings.Index(g, "workflow_call:"):strings.Index(g, "\n    secrets:\n")]
	if i := strings.Index(call, "\n      ignore_ecosystems:\n"); i < 0 || !strings.Contains(call[i:], `default: ""`) {
		t.Error("gate.yml does not declare an optional ignore_ecosystems input defaulting to empty")
	}
	jobs := gateJobs(t)
	for name, job := range jobs {
		uses := strings.Contains(job, "ignore_ecosystems")
		if uses != (name == "classify" || name == "refresh" || name == "publish") {
			t.Errorf("%s: uses ignore_ecosystems: %v; classify, refresh and publish should, and no other job", name, uses)
		}
		if !uses {
			continue
		}
		if !strings.Contains(job, "IGNORE_ECOSYSTEMS: ${{ inputs.ignore_ecosystems }}") || !strings.Contains(job, `--ignore-ecosystems "$IGNORE_ECOSYSTEMS"`) {
			t.Errorf("%s does not pass --ignore-ecosystems from the input", name)
		}
	}
	example, err := os.ReadFile("../../examples/dep-review.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(example), "      # ignore_ecosystems: submodules\n") {
		t.Error("the example does not show ignore_ecosystems commented out")
	}
}

// A skipped trigger run (another author's PR) runs no gate job: build is
// skipped, and every other job needs it.
func TestSkippedTriggerRunsNothing(t *testing.T) {
	jobs := gateJobs(t)
	const cond = "if: github.event_name != 'workflow_run' || github.event.workflow_run.conclusion != 'skipped'"
	if !strings.Contains(jobs["build"], cond) {
		t.Errorf("build lacks %q", cond)
	}
	for name, job := range jobs {
		if name != "build" && !regexp.MustCompile(`(?m)^    needs: (build|\[build[],])`).MatchString(job) {
			t.Errorf("%s does not need build, so a skipped trigger would still run it", name)
		}
	}
}

// What fetch and refresh check out is data: no credential stays in the
// clone, and neither job runs anything but the gate.
func TestCheckoutsAreData(t *testing.T) {
	jobs := gateJobs(t)
	for name, job := range jobs {
		n := strings.Count(job, "uses: actions/checkout@")
		if n != strings.Count(job, "persist-credentials: false") {
			t.Errorf("%s: a checkout keeps its credentials", name)
		}
		if want := map[string]int{"build": 1, "fetch": 1, "refresh": 1}[name]; n != want {
			t.Errorf("%s has %d checkouts, want %d", name, n, want)
		}
	}
	for _, name := range []string{"fetch", "refresh"} {
		if !strings.Contains(jobs[name], "fetch-depth: 0") {
			t.Errorf("%s does not fetch the history the change set is read from", name)
		}
		for _, s := range runScripts(t, jobs[name]) {
			for _, line := range strings.Split(s, "\n") {
				word := strings.Fields(strings.TrimSpace(line) + " x")[0]
				if word == "npm" || word == "go" || word == "make" || word == "bash" || word == "sh" || word == "node" || strings.HasPrefix(word, "./") || strings.HasPrefix(word, "pr/") || strings.HasPrefix(word, "repo/") {
					t.Errorf("%s runs %q", name, strings.TrimSpace(line))
				}
			}
		}
	}
}
