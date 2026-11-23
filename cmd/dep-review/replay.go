package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/sadbox/dep-review/internal/config"
	"github.com/sadbox/dep-review/internal/replay"
)

// runReplay: dep-review replay --dir <dir> --now <time> [--policy <file>] [--name-created <time>]
//
// Decides every recorded pull request in --dir offline, with stand-ins
// for the facts that need the network (internal/replay says which), and
// prints one line for each and the totals for each ecosystem. It is for
// measuring a policy before shipping it: run it with the built-in policy
// and with the changed one, and compare. It reads no token and calls no
// API; for npm records it runs the local npm, which reads the locks
// offline.
func runReplay(args []string) error {
	fl := newFlagSet("replay")
	dir := fl.String("dir", "", "directory of recorded pull requests, one JSON file each, in the form internal/replay documents (required)")
	nowFlag := fl.String("now", "", "the clock: the moment every pull request is decided at, as RFC 3339 (required)")
	policyPath := fl.String("policy", "", "a complete policy file in the form of internal/config/policy/defaults.json, to decide with in place of the built-in one")
	nameCreatedFlag := fl.String("name-created", "", "stand-in for when every new, unlisted name was created, as RFC 3339; left out, that time is unknown and such an update goes to a person")
	if err := fl.Parse(args); err != nil {
		return err
	}
	if *dir == "" || *nowFlag == "" || fl.NArg() > 0 {
		return errors.New("replay: --dir and --now are required")
	}
	opt := replay.Options{}
	var err error
	if opt.Now, err = time.Parse(time.RFC3339, *nowFlag); err != nil {
		return fmt.Errorf("replay: --now: %w", err)
	}
	if *nameCreatedFlag != "" {
		if opt.NameCreated, err = time.Parse(time.RFC3339, *nameCreatedFlag); err != nil {
			return fmt.Errorf("replay: --name-created: %w", err)
		}
	}
	// No repository file is applied on top: the file given here is the
	// whole policy, so that a run can also measure a narrower list or a
	// shorter age than the built-in one.
	var cfg config.Config
	if *policyPath == "" {
		cfg, err = config.Load(nil)
	} else {
		var b []byte
		if b, err = os.ReadFile(*policyPath); err == nil {
			cfg, err = config.Complete(b)
		}
	}
	if err != nil {
		return fmt.Errorf("replay: %w", err)
	}
	opt.Policy = cfg.Policy()

	results, err := replay.Run(context.Background(), *dir, opt)
	if err != nil {
		return err
	}
	return replay.Print(os.Stdout, results)
}
