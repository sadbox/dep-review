package main

import "flag"

// requiredMark in a flag's usage marks it required. The subcommand still
// checks it itself; the mark is what TestGateInvocations checks gate.yml
// against.
const requiredMark = "(required)"

// flagSetHook, set only by tests, sees every subcommand's FlagSet.
var flagSetHook func(*flag.FlagSet)

// newFlagSet is flag.NewFlagSet for every subcommand.
func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	if flagSetHook != nil {
		flagSetHook(fs)
	}
	return fs
}
