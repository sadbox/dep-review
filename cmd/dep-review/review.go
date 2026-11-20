package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sadbox/dep-review/internal/proxy"
	"github.com/sadbox/dep-review/internal/sandbox"
)

// reviewTestFlags lets the sandboxtest build (testonly.go) add the fake
// upstream and the probe mode; the gate's binary has neither.
var reviewTestFlags = func(*flag.FlagSet) func(*sandbox.Config) error {
	return func(*sandbox.Config) error { return nil }
}

// runReview: dep-review review --prep-dir <dir> --evidence <dir> --repo <dir> --out <verdict.json> ...
//
// Runs the reviewer sandbox (internal/sandbox) and writes verdict.json
// only when the reviewer exited 0, in time, under gVisor, with a result
// that passed validation. Anything else exits non-zero with no verdict,
// which publish treats as "needs a human".
func runReview(args []string) error {
	fs := flag.NewFlagSet("review", flag.ContinueOnError)
	prep := fs.String("prep-dir", "", "review-prep's output (prompt.md, settings.json, schema.json)")
	evidence := fs.String("evidence", "", "evidence directory (read-only in the sandbox)")
	repo := fs.String("repo", "", "default-branch checkout (read-only in the sandbox)")
	out := fs.String("out", "", "verdict.json to write")
	reviewer := fs.String("reviewer-image", "", "reviewer image (sandbox/Dockerfile)")
	proxyImage := fs.String("proxy-image", "", "proxy image (sandbox/Dockerfile, target proxy)")
	model := fs.String("model", "", "model")
	rule := fs.String("federation-rule-id", "", "workload identity federation rule (fdrl_...)")
	org := fs.String("organization-id", "", "Anthropic organization ID")
	ws := fs.String("workspace-id", "", "workspace (wrkspc_...), optional")
	svac := fs.String("service-account-id", "", "service account (svac_...), optional")
	maxReq := fs.Int("max-requests", proxy.DefaultMaxRequests, "Messages requests the proxy allows")
	maxTurns := fs.Int("max-turns", 80, "claude --max-turns")
	timeout := fs.Duration("timeout", 15*time.Minute, "reviewer wall clock")
	subnet := fs.String("subnet", "10.213.7.0/24", "internal network")
	applyTest := reviewTestFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *prep == "" || *evidence == "" || *repo == "" || *reviewer == "" || *proxyImage == "" || *model == "" || fs.NArg() > 0 {
		return errors.New("review: --prep-dir, --evidence, --repo, --reviewer-image, --proxy-image and --model are required")
	}
	pfx, err := netip.ParsePrefix(*subnet)
	if err != nil {
		return fmt.Errorf("review: --subnet: %w", err)
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	schema, err := os.ReadFile(filepath.Join(*prep, "schema.json"))
	if err != nil {
		return err
	}
	var rnd [4]byte
	rand.Read(rnd[:])
	c := sandbox.Config{
		Name:          "dep-review-" + hex.EncodeToString(rnd[:]),
		ReviewerImage: *reviewer,
		ProxyImage:    *proxyImage,
		GateBinary:    self,
		EvidenceDir:   *evidence,
		RepoDir:       *repo,
		SettingsFile:  filepath.Join(*prep, "settings.json"),
		PromptFile:    filepath.Join(*prep, "prompt.md"),
		Schema:        strings.TrimSpace(string(schema)),
		Model:         *model,
		MaxTurns:      *maxTurns,
		MaxRequests:   *maxReq,
		Federation:    sandbox.Federation{RuleID: *rule, OrganizationID: *org, WorkspaceID: *ws, ServiceAccountID: *svac},
		Subnet:        pfx,
		Timeout:       *timeout,
	}
	if err := applyTest(&c); err != nil {
		return err
	}
	if c.Command == nil && *out == "" {
		return errors.New("review: --out is required")
	}
	res, err := sandbox.Run(context.Background(), c)
	if err != nil {
		return fmt.Errorf("review: %w", err)
	}
	if c.Command != nil { // probe mode
		os.Stdout.Write(res.Stdout)
		if res.Exit != 0 {
			return fmt.Errorf("review: probe exited %d", res.Exit)
		}
		return nil
	}
	if !res.VerdictOK {
		return fmt.Errorf("review: no verdict: %w", res.VerdictE)
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(*out, res.Verdict, 0o644); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "review: verdict written")
	return nil
}
