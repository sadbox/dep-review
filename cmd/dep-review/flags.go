package main

import "flag"

// newFlagSet makes every subcommand's FlagSet. It is a variable so that a
// test can see the flags a subcommand defines and hold gate.yml to them.
var newFlagSet = func(name string) *flag.FlagSet {
	return flag.NewFlagSet(name, flag.ContinueOnError)
}
