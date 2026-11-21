package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// gateJobs splits .github/workflows/gate.yml into its jobs' text.
func gateJobs(t *testing.T) map[string]string {
	t.Helper()
	b, err := os.ReadFile("../../.github/workflows/gate.yml")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
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

// Every job that runs anything from the gate-bin artifact checks it
// against the build job's checksums first: before setting up Go from its
// go.mod, minting the app token, or running the binary.
func TestGateBinVerified(t *testing.T) {
	jobs := gateJobs(t)
	build := jobs["build"]
	if !strings.Contains(build, "gate_sums: ${{ steps.sums.outputs.sums }}") || !strings.Contains(build, "sha256sum") {
		t.Fatal("the build job does not output the gate's checksums")
	}
	n := 0
	for name, job := range jobs {
		if name == "build" || !strings.Contains(job, "gate-bin") {
			continue
		}
		n++
		v := strings.Index(job, "- name: Verify the gate's files")
		if v < 0 {
			t.Errorf("%s uses gate-bin without verifying it", name)
			continue
		}
		if !strings.Contains(job[v:], "GATE_SUMS: ${{ needs.build.outputs.gate_sums }}") || !strings.Contains(job[v:], "sha256sum --check --strict") {
			t.Errorf("%s: the verify step does not check the build job's sums", name)
		}
		for _, use := range []string{`/dep-review" `, "create-github-app-token", "bin/go.mod", "install-gvisor.sh", "docker build"} {
			if u := strings.Index(job, use); u >= 0 && u < v {
				t.Errorf("%s: %q comes before the verify step", name, use)
			}
		}
	}
	if n != 5 {
		t.Errorf("%d jobs use gate-bin, want 5 (classify, fetch, review, publish, sweep)", n)
	}
}

// The caller passes the gate exactly the secrets gate.yml declares, never
// `secrets: inherit`, and gate.yml uses no secret it does not declare.
func TestSecretsExplicit(t *testing.T) {
	gate, err := os.ReadFile("../../.github/workflows/gate.yml")
	if err != nil {
		t.Fatal(err)
	}
	example, err := os.ReadFile("../../examples/dep-review.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if regexp.MustCompile(`(?m)^\s*secrets:\s*inherit\b`).Match(example) {
		t.Error("examples/dep-review.yaml uses secrets: inherit")
	}
	g := string(gate)
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
// job output: a compromised job holding the run's runtime token could
// otherwise replace, say, the verdict, and publish would merge on it.
func TestArtifactsVerified(t *testing.T) {
	jobs := gateJobs(t)
	for _, a := range []struct {
		name, producer string
		consumers      []string
	}{
		{"classification", "classify", []string{"fetch", "publish"}},
		{"evidence", "fetch", []string{"review", "publish"}},
		{"verdict", "review", []string{"publish"}},
	} {
		p := jobs[a.producer]
		out := a.name + "_sums: ${{ steps.sums.outputs.sums }}"
		sums := strings.Index(p, "- name: Checksum the artifact")
		up := strings.Index(p, "name: "+a.name+"\n")
		if !strings.Contains(p, out) || sums < 0 || up < 0 || sums > up {
			t.Errorf("%s does not output the %s artifact's checksums before uploading it", a.producer, a.name)
		}
		for _, c := range a.consumers {
			job := jobs[c]
			dl := strings.Index(job, "name: "+a.name+"\n")
			if c == "publish" {
				dl = strings.Index(job, "pattern: ")
				if !strings.Contains(job[dl:], a.name) {
					t.Errorf("publish does not download %s", a.name)
				}
			}
			v := strings.Index(job, "- name: Verify the "+a.name+" artifact")
			ref := "SUMS: ${{ needs." + a.producer + ".outputs." + a.name + "_sums }}"
			if dl < 0 || v < dl || !strings.Contains(job[v:], ref) || !strings.Contains(job[v:], "sha256sum --check --strict") {
				t.Errorf("%s does not verify the %s artifact after downloading it", c, a.name)
				continue
			}
			for _, use := range []string{`/dep-review" `, "create-github-app-token", "install-gvisor.sh"} {
				if u := strings.Index(job, use); u >= 0 && u < v {
					t.Errorf("%s: %q comes before verifying %s", c, use, a.name)
				}
			}
		}
	}
}

// publish and sweep must know the caller's trigger workflow, or its no-op
// check run could count as green CI.
func TestTriggerPathPassed(t *testing.T) {
	jobs := gateJobs(t)
	for name, cmd := range map[string]string{"publish": `dep-review" publish`, "sweep": `dep-review" sweep`} {
		job := jobs[name]
		if !strings.Contains(job, "TRIGGER_PATH: ${{ inputs.trigger_workflow_path }}") {
			t.Errorf("%s does not get the trigger path in its env", name)
		}
		i := strings.Index(job, cmd)
		if i < 0 {
			t.Fatalf("%s does not run %s", name, cmd)
		}
		// The command runs to the end of its run: block.
		run := job[i:]
		if j := strings.Index(run, "\n      - "); j >= 0 {
			run = run[:j]
		}
		if !strings.Contains(run, `--trigger-path "$TRIGGER_PATH"`) {
			t.Errorf("%s runs %s without --trigger-path", name, cmd)
		}
	}
}
