package main

import (
	"fmt"
	"os"
	"regexp"
)

// stepValueRe is what a single-line step output may hold: the gate's own
// enums (kind, route), never untrusted text. Multi-line values use
// reviewprep.WriteOutputs (random heredoc delimiters) instead.
var stepValueRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)

// stepOutput appends name=value to $GITHUB_OUTPUT, or prints it to stdout
// when that is unset (local runs).
func stepOutput(name, value string) error {
	if !stepValueRe.MatchString(name) || !stepValueRe.MatchString(value) {
		return fmt.Errorf("step output %q=%q is not a plain identifier", name, value)
	}
	path := os.Getenv("GITHUB_OUTPUT")
	if path == "" {
		fmt.Printf("%s=%s\n", name, value)
		return nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(f, "%s=%s\n", name, value); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
