package main

import "errors"

// Stubs, replaced by the real implementations (one file per command).
var errTODO = errors.New("not implemented")

func runClassify(args []string) error   { return errTODO }
func runFetch(args []string) error      { return errTODO }
func runReviewPrep(args []string) error { return errTODO }
func runPublish(args []string) error    { return errTODO }
func runSweep(args []string) error      { return errTODO }
