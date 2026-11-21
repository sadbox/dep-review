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
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sadbox/dep-review/internal/fakeanthropic"
	"github.com/sadbox/dep-review/internal/proxy"
	"github.com/sadbox/dep-review/internal/sandbox"
)

func init() {
	testUpstream = func(fs *flag.FlagSet) *string {
		return fs.String("test-upstream", "", "TEST ONLY: upstream base URL instead of https://api.anthropic.com")
	}
	extraCommands["fake-anthropic"] = runFakeAnthropic
	extraCommands["probe"] = runProbe
	reviewTestFlags = func(fs *flag.FlagSet) func(*sandbox.Config) error {
		fake := fs.String("test-fake-upstream", "", "TEST ONLY: run the fake upstream with this verdict JSON file")
		record := fs.String("test-fake-record", "", "TEST ONLY: directory where the fake upstream records request bodies")
		probe := fs.Bool("test-probe", false, "TEST ONLY: run the isolation probes (dep-review probe) instead of claude")
		gateBin := fs.String("test-gate-binary", "", "TEST ONLY: linux dep-review binary for the containers (default: this one)")
		runtime := fs.String("test-runtime", "", "TEST ONLY: container runtime instead of runsc (local runs without gVisor)")
		var probeArgs stringList
		fs.Var(&probeArgs, "test-probe-arg", "TEST ONLY: probe argument (repeatable)")
		return func(c *sandbox.Config) error {
			if *gateBin != "" {
				abs, err := filepath.Abs(*gateBin)
				if err != nil {
					return err
				}
				c.GateBinary = abs
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
				// A fake GitHub OIDC endpoint on the host's loopback, for the
				// real host-side helper (proxy.GitHubOIDC) to call.
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					return err
				}
				go http.Serve(ln, (&fakeanthropic.Server{}).Handler())
				c.Identity = proxy.GitHubOIDC{
					RequestURL:   "http://" + ln.Addr().String() + "/oidc/token?api-version=2.0",
					RequestToken: fakeanthropic.OIDCRequestToken,
					Client:       http.DefaultClient,
				}.Token
			}
			if *probe {
				// This (static, linux) binary, since the reviewer image has
				// no shell or interpreter to run a script with.
				c.ExtraMounts = append(c.ExtraMounts, sandbox.Mount{Src: c.GateBinary, Dst: "/probe/dep-review"})
				c.Command = append([]string{"/probe/dep-review", "probe", "--proxy", c.ProxyAddr(), "--model", c.Model}, probeArgs...)
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
	fs := newFlagSet("fake-anthropic")
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
