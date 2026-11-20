//go:build sandboxtest

// The sandboxtest build is for CI's sandbox job only: it adds a fake
// upstream for the proxy and the review command, and the probe mode. The
// gate builds without the tag and has none of this.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sadbox/dep-review/internal/fakeanthropic"
	"github.com/sadbox/dep-review/internal/sandbox"
)

func init() {
	testUpstream = func(fs *flag.FlagSet) *string {
		return fs.String("test-upstream", "", "TEST ONLY: upstream base URL instead of https://api.anthropic.com")
	}
	extraCommands["fake-anthropic"] = runFakeAnthropic
	reviewTestFlags = func(fs *flag.FlagSet) func(*sandbox.Config) error {
		fake := fs.String("test-fake-upstream", "", "TEST ONLY: run the fake upstream with this verdict JSON file")
		record := fs.String("test-fake-record", "", "TEST ONLY: directory where the fake upstream records request bodies")
		probe := fs.String("test-probe", "", "TEST ONLY: run this probe script (node) instead of claude")
		gateBin := fs.String("test-gate-binary", "", "TEST ONLY: linux dep-review binary for the containers (default: this one)")
		runtime := fs.String("test-runtime", "", "TEST ONLY: container runtime instead of runsc (local runs without gVisor)")
		var probeArgs stringList
		fs.Var(&probeArgs, "test-probe-arg", "TEST ONLY: probe argument (repeatable)")
		return func(c *sandbox.Config) error {
			if *gateBin != "" {
				c.GateBinary = *gateBin
			}
			if *runtime != "" {
				c.Runtime = *runtime
			}
			if *fake != "" {
				v, err := filepath.Abs(*fake)
				if err != nil {
					return err
				}
				fakeName := c.Name + "-fake"
				c.EgressSidecars = append(c.EgressSidecars, sandbox.Sidecar{Name: fakeName, Args: []string{
					"--runtime", "runc", "--read-only", "--cap-drop", "ALL",
					"--user", "65532:65532",
					"--mount", "type=bind,src=" + c.GateBinary + ",dst=/dep-review,readonly",
					"--mount", "type=bind,src=" + v + ",dst=/verdict.json,readonly",
					"--entrypoint", "/dep-review", c.ProxyImage,
					"fake-anthropic", "--listen", ":9000", "--verdict", "/verdict.json",
					"--model", c.Model, "--federation-rule-id", c.Federation.RuleID, "--organization-id", c.Federation.OrganizationID,
				}})
				if *record != "" {
					r, err := filepath.Abs(*record)
					if err != nil {
						return err
					}
					sc := &c.EgressSidecars[len(c.EgressSidecars)-1]
					sc.Args = append(sc.Args[:len(sc.Args):len(sc.Args)], "--record", "/record")
					sc.Args = append([]string{"--mount", "type=bind,src=" + r + ",dst=/record"}, sc.Args...)
				}
				c.ProxyExtraArgs = append(c.ProxyExtraArgs, "--test-upstream", "http://"+fakeName+":9000")
				// The docker CLI hands these to the proxy container by name.
				os.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "http://"+fakeName+":9000/oidc/token?api-version=2.0")
				os.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", fakeanthropic.OIDCRequestToken)
			}
			if *probe != "" {
				p, err := filepath.Abs(*probe)
				if err != nil {
					return err
				}
				c.ExtraMounts = append(c.ExtraMounts, sandbox.Mount{Src: p, Dst: "/probe/probe.mjs"})
				c.Command = append([]string{"node", "/probe/probe.mjs", "--proxy", c.ProxyAddr(), "--model", c.Model}, probeArgs...)
			}
			return nil
		}
	}
}

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, " ") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

// runFakeAnthropic: dep-review fake-anthropic --listen :9000 --verdict <file> --model <m> ...
func runFakeAnthropic(args []string) error {
	fs := flag.NewFlagSet("fake-anthropic", flag.ContinueOnError)
	listen := fs.String("listen", ":9000", "listen address")
	verdict := fs.String("verdict", "", "StructuredOutput the script returns")
	model := fs.String("model", "", "expected model")
	rule := fs.String("federation-rule-id", "", "expected rule")
	org := fs.String("organization-id", "", "expected organization")
	ttl := fs.Duration("token-ttl", 10*time.Minute, "minted token lifetime")
	record := fs.String("record", "", "directory to record Messages request bodies in")
	if err := fs.Parse(args); err != nil {
		return err
	}
	v, err := os.ReadFile(*verdict)
	if err != nil {
		return err
	}
	if !json.Valid(v) {
		return errors.New("fake-anthropic: verdict is not JSON")
	}
	s := &fakeanthropic.Server{Model: *model, RuleID: *rule, OrganizationID: *org, Verdict: v, TokenTTL: *ttl, RecordDir: *record,
		Logf: log.New(os.Stderr, "", log.LUTC|log.Ltime).Printf}
	log.Printf("fake-anthropic: listening on %s", *listen)
	return http.ListenAndServe(*listen, s.Handler())
}
