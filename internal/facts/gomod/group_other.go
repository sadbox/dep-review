//go:build !unix

package gomod

import "os/exec"

// setGroup does nothing where there are no process groups.
func setGroup(*exec.Cmd) {}

// killGroup kills cmd.
func killGroup(cmd *exec.Cmd) {
	if cmd.Process != nil {
		cmd.Process.Kill()
	}
}
