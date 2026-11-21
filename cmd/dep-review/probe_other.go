//go:build sandboxtest && !linux

package main

import "errors"

// runProbe runs inside the (Linux) sandbox only; see probe_linux.go.
func runProbe([]string) error { return errors.New("probe: Linux only") }
