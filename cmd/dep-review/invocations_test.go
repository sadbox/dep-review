package main

import (
	"errors"
	"flag"
	"io"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/sadbox/dep-review/internal/sandbox"
)

// flagsOf returns the flags subcommand cmd defines and the ones whose
// usage marks them required, from its real FlagSet: the command runs with
// -h, which stops it at Parse, before it does anything.
func flagsOf(t *testing.T, cmd string) (defined, required map[string]bool) {
	t.Helper()
	run, ok := commands[cmd]
	if !ok {
		t.Fatalf("gate.yml runs unknown subcommand %q", cmd)
	}
	var got *flag.FlagSet
	flagSetHook = func(fs *flag.FlagSet) {
		fs.SetOutput(io.Discard)
		if got == nil {
			got = fs
		}
	}
	defer func() { flagSetHook = nil }()
	if err := run([]string{"-h"}); !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("%s -h: %v", cmd, err)
	}
	defined, required = map[string]bool{}, map[string]bool{}
	got.VisitAll(func(f *flag.Flag) {
		defined[f.Name] = true
		if strings.Contains(f.Usage, requiredMark) {
			required[f.Name] = true
		}
	})
	return defined, required
}

// invocation is one `dep-review <cmd> --flag value ...` from a workflow.
type invocation struct {
	where string
	cmd   string
	flags []string
}

var invocationRe = regexp.MustCompile(`"\$RUNNER_TEMP/(?:bin|in/gate-bin)/dep-review" ([a-z][a-z-]*)((?:[^\n]*\\\n)*[^\n]*)`)

func gateInvocations(t *testing.T) []invocation {
	t.Helper()
	var out []invocation
	for job, text := range gateJobs(t) {
		for _, m := range invocationRe.FindAllStringSubmatch(text, -1) {
			inv := invocation{where: job, cmd: m[1]}
			for _, tok := range strings.Fields(strings.ReplaceAll(m[2], "\\\n", " ")) {
				if name, ok := strings.CutPrefix(tok, "--"); ok {
					name, _, _ = strings.Cut(name, "=")
					inv.flags = append(inv.flags, name)
				}
			}
			out = append(out, inv)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].where+out[i].cmd < out[j].where+out[j].cmd })
	return out
}

// Every `dep-review` command gate.yml runs passes only flags that
// subcommand defines, and every flag it marks required. A mismatch (a
// flag the binary at this commit lacks, or a required one left out) would
// otherwise surface only when the gate runs in a caller's repository.
func TestGateInvocations(t *testing.T) {
	invs := gateInvocations(t)
	seen := map[string]bool{}
	for _, inv := range invs {
		seen[inv.cmd] = true
		defined, required := flagsOf(t, inv.cmd)
		passed := map[string]bool{}
		for _, f := range inv.flags {
			passed[f] = true
			if !defined[f] {
				t.Errorf("gate.yml (%s) runs `dep-review %s --%s`, which %s does not define", inv.where, inv.cmd, f, inv.cmd)
			}
		}
		for f := range required {
			if !passed[f] {
				t.Errorf("gate.yml (%s) runs `dep-review %s` without its required --%s", inv.where, inv.cmd, f)
			}
		}
	}
	for _, want := range []string{"classify", "fetch", "review-prep", "review", "publish", "sweep"} {
		if !seen[want] {
			t.Errorf("found no `dep-review %s` in gate.yml; the extraction is broken", want)
		}
	}
}

// The proxy is started by internal/sandbox, not by gate.yml; its argv
// gets the same check.
func TestProxyInvocation(t *testing.T) {
	c := sandbox.Config{Model: "m", MaxRequests: 1, MaxTokens: 1,
		Federation: sandbox.Federation{RuleID: "r", OrganizationID: "o", WorkspaceID: "w", ServiceAccountID: "s"}}
	args := c.ProxyArgs()
	i := 0
	for i < len(args) && args[i] != "proxy" {
		i++
	}
	if i == len(args) {
		t.Fatal("no proxy command in ProxyArgs")
	}
	defined, required := flagsOf(t, "proxy")
	passed := map[string]bool{}
	for _, a := range args[i+1:] {
		if name, ok := strings.CutPrefix(a, "--"); ok {
			passed[name] = true
			if !defined[name] {
				t.Errorf("the sandbox runs `dep-review proxy --%s`, which proxy does not define", name)
			}
		}
	}
	for f := range required {
		if !passed[f] {
			t.Errorf("the sandbox runs `dep-review proxy` without its required --%s", f)
		}
	}
}

// The extraction itself, on a known snippet.
func TestInvocationRe(t *testing.T) {
	s := "        run: |\n          \"$RUNNER_TEMP/bin/dep-review\" fetch \\\n            --a \"$X\" \\\n            --b=c\n          echo --not-a-flag\n"
	m := invocationRe.FindStringSubmatch(s)
	if m == nil || m[1] != "fetch" {
		t.Fatalf("no match: %q", m)
	}
	var got []string
	for _, tok := range strings.Fields(strings.ReplaceAll(m[2], "\\\n", " ")) {
		if n, ok := strings.CutPrefix(tok, "--"); ok {
			n, _, _ = strings.Cut(n, "=")
			got = append(got, n)
		}
	}
	if strings.Join(got, ",") != "a,b" {
		t.Errorf("flags %v", got)
	}
}
