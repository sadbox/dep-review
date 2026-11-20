package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStepOutput(t *testing.T) {
	p := filepath.Join(t.TempDir(), "out")
	t.Setenv("GITHUB_OUTPUT", p)
	for _, kv := range [][2]string{{"kind", "dependabot-unverified"}, {"route", "review"}} {
		if err := stepOutput(kv[0], kv[1]); err != nil {
			t.Fatal(err)
		}
	}
	if b, err := os.ReadFile(p); err != nil || string(b) != "kind=dependabot-unverified\nroute=review\n" {
		t.Fatalf("%q %v", b, err)
	}
	for _, v := range []string{"review\nroute=auto", "", "a b", "Review"} {
		if err := stepOutput("route", v); err == nil {
			t.Errorf("value %q accepted", v)
		}
	}
}
