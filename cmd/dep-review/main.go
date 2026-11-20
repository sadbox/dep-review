// Command dep-review is the gate's deterministic half: classify, fetch,
// review-prep, publish and sweep. See README.md.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: dep-review classify|fetch|review-prep|publish|sweep [flags]")
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "classify":
		err = runClassify(args)
	case "fetch":
		err = runFetch(args)
	case "review-prep":
		err = runReviewPrep(args)
	case "publish":
		err = runPublish(args)
	case "sweep":
		err = runSweep(args)
	default:
		err = fmt.Errorf("unknown command %q", cmd)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "dep-review:", err)
		os.Exit(1)
	}
}
