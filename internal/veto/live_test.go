package veto

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestLive sends one small, harmless chunk to the real API with an API
// key. It is the experiment for what the fake cannot show: that the API
// accepts this request as written (version header, adaptive thinking,
// effort, the answer schema) and answers in the shape interpret reads.
//
// It costs money and needs a credential, so it runs only when asked:
//
//	DEP_REVIEW_VETO_LIVE=1 ANTHROPIC_API_KEY=... go test ./internal/veto/ -run TestLive -v
//
// It was written without ever being run.
func TestLive(t *testing.T) {
	if os.Getenv("DEP_REVIEW_VETO_LIVE") != "1" {
		t.Skip("set DEP_REVIEW_VETO_LIVE=1 and " + APIKeyEnv + " to call the real API")
	}
	key, err := APIKeyFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(DefaultConfig(), key, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.Logf = t.Logf
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	p := prepared("diff --git a/pad.go b/pad.go\n--- a/pad.go\n+++ b/pad.go\n@@ -1,3 +1,3 @@\n package pad\n \n-const width = 8\n+const width = 10\n")
	counts, err := c.CountTokens(ctx, Request{Read: p})
	if err != nil {
		t.Fatalf("CountTokens: %v", err)
	}
	t.Logf("input tokens: %v", counts)

	v, err := c.Review(ctx, Request{Read: p})
	if err != nil {
		t.Fatalf("Review: %v", err)
	}
	t.Logf("verdict: %+v", v)
	if v.Answer != NoVeto {
		t.Errorf("a one-line constant change was answered %q (%s)", v.Answer, v.Category)
	}
}
