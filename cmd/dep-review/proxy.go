package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sadbox/dep-review/internal/proxy"
)

// testUpstream registers the upstream override; only the sandboxtest
// build (testonly.go) has it, so the gate's binary can only ever talk to
// https://api.anthropic.com.
var testUpstream = func(*flag.FlagSet) *string { return nil }

// runProxy: dep-review proxy --model <m> --federation-rule-id <id> --organization-id <id> [...]
//
// Runs in its own container, outside the reviewer sandbox. Reads
// ACTIONS_ID_TOKEN_REQUEST_URL/TOKEN, mints the first token before it
// listens (so a broken federation setup fails fast), prints "proxy: ready"
// and serves until killed.
func runProxy(args []string) error {
	fs := flag.NewFlagSet("proxy", flag.ContinueOnError)
	listen := fs.String("listen", ":8080", "listen address")
	model := fs.String("model", "", "the only model requests may name")
	rule := fs.String("federation-rule-id", "", "workload identity federation rule (fdrl_...)")
	org := fs.String("organization-id", "", "Anthropic organization ID")
	ws := fs.String("workspace-id", "", "workspace (wrkspc_...), optional")
	svac := fs.String("service-account-id", "", "service account (svac_...), optional")
	maxReq := fs.Int64("max-requests", proxy.DefaultMaxRequests, "Messages requests allowed per run")
	override := testUpstream(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *model == "" || fs.NArg() > 0 {
		return errors.New("proxy: --model is required")
	}
	upstream, _ := url.Parse(proxy.DefaultUpstream)
	if override != nil && *override != "" {
		u, err := url.Parse(*override)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return errors.New("proxy: bad --test-upstream")
		}
		upstream = u
	}
	if upstream.Scheme != "https" && (override == nil || *override == "") {
		return errors.New("proxy: the upstream must be https")
	}
	logger := log.New(os.Stderr, "proxy: ", log.LstdFlags|log.LUTC)
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		Proxy:               nil,
		TLSHandshakeTimeout: 10 * time.Second,
		ForceAttemptHTTP2:   true,
	}}
	tokens, err := proxy.NewTokenSource(proxy.Federation{
		OIDCRequestURL:   os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL"),
		OIDCRequestToken: os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN"),
		RuleID:           *rule,
		OrganizationID:   *org,
		WorkspaceID:      *ws,
		ServiceAccountID: *svac,
	}, upstream, client, logger.Printf)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	startCtx, cancel := context.WithTimeout(ctx, time.Minute)
	_, err = tokens.Token(startCtx)
	cancel()
	if err != nil {
		return fmt.Errorf("proxy: first token: %w", err)
	}
	p, err := proxy.New(proxy.Config{Upstream: upstream, Model: *model, MaxRequests: *maxReq, Tokens: tokens, Logf: logger.Printf})
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: p, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute, ErrorLog: logger}
	go func() {
		<-ctx.Done()
		srv.Close()
	}()
	// The orchestrator waits for this exact line (internal/sandbox).
	fmt.Fprintln(os.Stderr, "proxy: ready")
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
