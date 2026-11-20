// Package submodule is the git submodules ecosystem fetcher. Submodule
// bumps pull in arbitrary code with no release or lockfile metadata to
// check, so every one goes to a human; the fetcher only reports which
// gitlinks moved.
package submodule

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/sadbox/dep-review/internal/fetch"
	"github.com/sadbox/dep-review/internal/model"
)

// Code is the finding every submodule PR carries.
const Code = "submodule.human-review"

type fetcher struct{ git string }

// New returns the submodules fetcher.
func New() fetch.Ecosystem { return fetcher{git: "git"} }

var shaRx = regexp.MustCompile(`^[0-9a-f]{40}$`)

func (f fetcher) Fetch(ctx context.Context, env fetch.Env) (fetch.Result, error) {
	res := fetch.Result{Findings: []model.Finding{{
		Code:   Code,
		Route:  model.RouteHuman,
		Detail: "git submodule updates are reviewed by a human",
	}}}
	if !shaRx.MatchString(env.Class.BaseSHA) || !shaRx.MatchString(env.Class.HeadSHA) {
		return res, nil
	}
	cmd := exec.CommandContext(ctx, f.git, "-C", env.RepoDir, "-c", "core.hooksPath=/dev/null",
		"diff", "--raw", "--no-abbrev", "--no-renames", "-z", env.Class.BaseSHA, env.Class.HeadSHA, "--")
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	if err := cmd.Run(); err != nil {
		return res, fmt.Errorf("submodule: git diff: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	res.Updates = gitlinkUpdates(out.Bytes())
	return res, nil
}

// gitlinkUpdates parses `git diff --raw -z` and returns one update per
// modified gitlink (mode 160000 on both sides).
func gitlinkUpdates(raw []byte) []model.Update {
	var us []model.Update
	f := bytes.Split(raw, []byte{0})
	for i := 0; i+1 < len(f); i += 2 {
		meta := strings.Fields(strings.TrimPrefix(string(f[i]), ":"))
		if len(meta) < 5 || meta[0] != "160000" || meta[1] != "160000" {
			continue
		}
		us = append(us, model.Update{
			Ecosystem: model.GitSubmodule,
			Directory: "/",
			Name:      string(f[i+1]),
			From:      meta[2],
			To:        meta[3],
			FromRef:   meta[2],
			ToRef:     meta[3],
			Type:      model.Digest,
			Direct:    true,
		})
	}
	return us
}
