package main

import (
	"github.com/sadbox/dep-review/internal/eco/actions"
	"github.com/sadbox/dep-review/internal/eco/docker"
	"github.com/sadbox/dep-review/internal/eco/gomod"
	"github.com/sadbox/dep-review/internal/eco/npm"
	"github.com/sadbox/dep-review/internal/eco/submodule"
	"github.com/sadbox/dep-review/internal/eco/uv"
	"github.com/sadbox/dep-review/internal/fetch"
	"github.com/sadbox/dep-review/internal/model"
)

// ecosystems is the fetcher for each Dependabot ecosystem, one line each.
// An ecosystem missing here gets fetch.Run's "ecosystem.unknown" finding,
// which forces a human decision.
var ecosystems = fetch.Registry{
	model.GoModules:     gomod.Fetcher{},
	model.NPM:           npm.Fetcher{},
	model.UV:            uv.Fetcher{},
	model.GitHubActions: actions.New(actions.Config{}),
	model.Docker:        docker.New(),
	model.GitSubmodule:  submodule.New(),
}
