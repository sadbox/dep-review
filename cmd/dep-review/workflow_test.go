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
