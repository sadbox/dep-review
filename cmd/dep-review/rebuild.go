package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/sadbox/dep-review/internal/model"
	"github.com/sadbox/dep-review/internal/rebuild"
)

// rebuildTimeout leaves the job (60 minutes) time to upload the results.
const rebuildTimeout = 50 * time.Minute

// rebuildOut is rebuild.json.
type rebuildOut struct {
	Results []model.RebuildResult `json:"results"`
}

// runRebuild: dep-review rebuild --evidence <dir> --out <dir> --images 20=<ref>,22=<ref>,24=<ref> [--runtime runsc]
//
// Rebuilds every plan in evidence.json (package rebuild) and writes
// <out>/rebuild.json. A plan that cannot be rebuilt is a result, not an
// error; an error means no results (publish then shows none).
func runRebuild(args []string) error {
	fl := newFlagSet("rebuild")
	evDir := fl.String("evidence", "", "the verified evidence directory (required)")
	outDir := fl.String("out", "", "directory to write rebuild.json to (required)")
	images := fl.String("images", "", "Node major=image, comma-separated (required)")
	runtime := fl.String("runtime", "runsc", "the OCI runtime the builds run under; anything but runsc is for local use")
	cloneBase := fl.String("clone-base", "https://github.com/", "prefixed to owner/repo to fetch a commit (CI points it at a local fixture)")
	if err := fl.Parse(args); err != nil {
		return err
	}
	if *evDir == "" || *outDir == "" || *images == "" || fl.NArg() > 0 {
		return errors.New("usage: dep-review rebuild --evidence <dir> --out <dir> --images 24=<ref>,...")
	}
	imgs := map[int]string{}
	for _, kv := range strings.Split(*images, ",") {
		k, v, ok := strings.Cut(kv, "=")
		n, err := strconv.Atoi(k)
		if !ok || err != nil || v == "" {
			return fmt.Errorf("--images: %q", kv)
		}
		imgs[n] = v
	}
	b, err := os.ReadFile(filepath.Join(*evDir, "evidence.json"))
	if err != nil {
		return err
	}
	var ev model.Evidence
	if err := json.Unmarshal(b, &ev); err != nil {
		return fmt.Errorf("evidence.json: %w", err)
	}
	work, err := os.MkdirTemp(os.Getenv("RUNNER_TEMP"), "dep-review-rebuild-")
	if err != nil {
		return err
	}
	defer removeScratch(work)
	ctx, cancel := context.WithTimeout(context.Background(), rebuildTimeout)
	defer cancel()
	res := rebuild.Run(ctx, rebuild.Config{
		Runtime:   *runtime,
		CloneBase: *cloneBase,
		Images:    imgs,
		Work:      work,
		Logf: func(format string, args ...any) {
			fmt.Fprintln(os.Stderr, logLine("dep-review rebuild: "+fmt.Sprintf(format, args...)))
		},
	}, ev.Rebuilds)
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return err
	}
	out, err := json.MarshalIndent(rebuildOut{Results: res}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(*outDir, "rebuild.json"), append(out, '\n'), 0o644)
}
