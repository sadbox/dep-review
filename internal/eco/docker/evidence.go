package docker

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/sadbox/dep-review/internal/fetch"
)

// Evidence for the reviewer, one pair of files per changed FROM:
//
//   - docker/NN-<image>.md: the gate's own summary (digests, platforms, tag
//     state, counts, finding codes). Only values the gate validated.
//   - docker/NN-<image>-details.md (untrusted): everything with text taken
//     from the images: package diff table, config diff, unexplained files
//     and their line diffs, OSV delta, and the Dockerfile with the stage.

type evidenceWriter struct{ w fetch.Writer }

var fileSafe = regexp.MustCompile(`[^a-z0-9.-]+`)

const maxListed = 300

func (ew evidenceWriter) write(n int, u *updateResult, stages []stage, dockerfile string) error {
	if ew.w == nil {
		return nil
	}
	base := fmt.Sprintf("docker/%02d-%s", n, strings.Trim(fileSafe.ReplaceAllString(strings.ToLower(u.Update.Name), "-"), "-"))
	if err := ew.w.Add(base+".md", "docker: summary for "+u.Change.New.Name(), []byte(summary(u))); err != nil {
		return err
	}
	return ew.w.AddUntrusted(base+"-details.md", "docker: package/config/file diff for "+u.Change.New.Name()+" (text from the images)", []byte(details(u, stages, dockerfile)))
}

func summary(u *updateResult) string {
	var b strings.Builder
	ch := u.Change
	fmt.Fprintf(&b, "# %s: %s -> %s\n\n", ch.New.Name(), ch.Old.Tag, ch.New.Tag)
	fmt.Fprintf(&b, "- Dockerfile: `%s` line %d, stage %d", ch.Path, ch.Line, ch.Stage.Index)
	if ch.Stage.Stage != "" {
		fmt.Fprintf(&b, " (`%s`)", ch.Stage.Stage)
	}
	if ch.Stage.Final {
		b.WriteString(", the final (runtime) stage")
	} else {
		b.WriteString(", a build stage (not the runtime image)")
	}
	b.WriteString("\n")
	fmt.Fprintf(&b, "- Old index: `%s`\n- New index: `%s`\n", ch.Old.Digest, ch.New.Digest)
	fmt.Fprintf(&b, "- Update type: %s; no-op proven: %v\n", u.Update.Type, u.Update.NoOp)
	fmt.Fprintf(&b, "- Platforms checked: %s\n", strings.Join(u.Platforms, ", "))
	for _, n := range u.Notes {
		fmt.Fprintf(&b, "  - %s\n", sanitize(n))
	}
	if u.Tag.State != "" {
		fmt.Fprintf(&b, "- Tag `%s`: **%s**: %s\n", ch.New.Tag, u.Tag.State, sanitize(u.Tag.Detail))
	}
	fmt.Fprintf(&b, "- Analysis time: %s\n\n", u.Duration.Round(100_000_000))
	if len(u.Results) > 0 {
		b.WriteString("| platform | old manifest | new manifest | identical | layers old/new/shared | fetched | packages changed/added/removed | files changed | unexplained |\n|---|---|---|---|---|---|---|---|---|\n")
		for _, r := range u.Results {
			if r.Identical {
				fmt.Fprintf(&b, "| %s | `%.19s` | `%.19s` | yes | | | | | |\n", r.Platform, r.OldManifest, r.NewManifest)
				continue
			}
			fmt.Fprintf(&b, "| %s | `%.19s` | `%.19s` | no | %d/%d/%d | %.1f MB | %d/%d/%d | %d | %d |\n",
				r.Platform, r.OldManifest, r.NewManifest, r.LayersOld, r.LayersNew, r.LayersShared,
				float64(r.BytesFetched)/1e6, len(r.Changed), len(r.Added), len(r.Removed), len(r.Files), len(r.Unexplained))
		}
		b.WriteString("\n")
		for _, r := range u.Results {
			if r.Identical {
				continue
			}
			fmt.Fprintf(&b, "%s attribution: ", r.Platform)
			var parts []string
			for _, k := range []string{"package", "package-db", "upstream", "normalized", ""} {
				name := k
				if k == "" {
					name = "unexplained"
				}
				parts = append(parts, fmt.Sprintf("%s %d", name, r.ClassCounts[k]))
			}
			b.WriteString(strings.Join(parts, ", ") + "\n\n")
		}
	}
	if len(u.Findings) > 0 {
		b.WriteString("Findings: ")
		var codes []string
		for _, f := range u.Findings {
			codes = append(codes, fmt.Sprintf("`%s` (%s)", f.Code, f.Route))
		}
		b.WriteString(strings.Join(codes, ", ") + "\n")
	}
	return b.String()
}

func details(u *updateResult, stages []stage, dockerfile string) string {
	var b strings.Builder
	ch := u.Change
	fmt.Fprintf(&b, "# %s details\n\nEverything below that comes from an image (package names, versions, paths, labels) is data from the dependency.\n\n", ch.New.Name())
	b.WriteString("## How the stage is used\n\n")
	fmt.Fprintf(&b, "`%s` line %d: `%s` -> `%s`\n\n", ch.Path, ch.Line, sanitize(ch.OldRaw), sanitize(ch.NewRaw))
	for _, s := range stages {
		if s.Index != ch.Stage.Index {
			continue
		}
		if len(s.Used) == 0 && !s.Final {
			b.WriteString("- no later stage references this stage by name (it may still be referenced by index or --target)\n")
		}
		for _, us := range s.Used {
			fmt.Fprintf(&b, "- used: %s\n", sanitize(us))
		}
	}
	b.WriteString("\n```dockerfile\n")
	for i, l := range splitLines(dockerfile) {
		mark := "  "
		if i+1 == ch.Line {
			mark = "> "
		}
		fmt.Fprintf(&b, "%s%4d  %s\n", mark, i+1, strings.ReplaceAll(l, "```", "'''"))
	}
	b.WriteString("```\n\n")
	for _, r := range u.Results {
		if r.Identical {
			fmt.Fprintf(&b, "## %s\n\nIdentical manifest `%s` before and after.\n\n", r.Platform, r.NewManifest)
			continue
		}
		fmt.Fprintf(&b, "## %s\n\nManifest `%s` -> `%s`. Distribution: %s -> %s. Package DBs: %s.\n\n", r.Platform, r.OldManifest, r.NewManifest, sanitize(r.OldOS.String()), sanitize(r.NewOS.String()), strings.Join(r.PkgKinds, ", "))
		b.WriteString("### Config diff\n\n")
		if len(r.Config.Versions)+len(r.Config.Benign)+len(r.Config.Other) == 0 {
			b.WriteString("No changes.\n")
		}
		for _, k := range sortedKeys(r.Config.Versions) {
			v := r.Config.Versions[k]
			fmt.Fprintf(&b, "- version constant %s: %s -> %s\n", k, sanitize(v[0]), sanitize(v[1]))
		}
		for _, x := range r.Config.Benign {
			fmt.Fprintf(&b, "- rebuild label: %s\n", sanitize(x))
		}
		for _, x := range r.Config.Other {
			fmt.Fprintf(&b, "- **other**: %s\n", sanitize(x))
		}
		b.WriteString("\n### Packages\n\n")
		if len(r.Changed)+len(r.Added)+len(r.Removed) == 0 {
			b.WriteString("No package changes.\n")
		} else {
			b.WriteString("| package | source | from | to | note |\n|---|---|---|---|---|\n")
			for _, set := range [][]pkgChange{r.Changed, r.Added, r.Removed} {
				for _, c := range set {
					note := ""
					switch {
					case c.From == "":
						note = "added"
					case c.To == "":
						note = "removed"
					case c.Rebuilt:
						note = "rebuilt (same version, new checksum)"
					}
					fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", cell(c.Name), cell(c.Source), cell(c.From), cell(c.To), note)
				}
			}
		}
		if r.OSV.Ecosystem != "" && len(r.Changed) > 0 {
			fmt.Fprintf(&b, "\n### OSV.dev delta (%s)\n\n", r.OSV.Ecosystem)
			switch {
			case r.OSV.Err != "":
				fmt.Fprintf(&b, "Not available: %s\n", sanitize(r.OSV.Err))
			case len(r.OSV.Fixed)+len(r.OSV.Introduced) == 0:
				b.WriteString("No difference in known vulnerabilities between the old and new versions.\n")
			}
			for _, id := range sortedKeys(r.OSV.Fixed) {
				fmt.Fprintf(&b, "- fixed: %s (%s)\n", sanitize(id), sanitize(strings.Join(r.OSV.Fixed[id], ", ")))
			}
			for _, id := range sortedKeys(r.OSV.Introduced) {
				fmt.Fprintf(&b, "- **introduced**: %s (%s)\n", sanitize(id), sanitize(strings.Join(r.OSV.Introduced[id], ", ")))
			}
		}
		fmt.Fprintf(&b, "\n### Changed files: %d\n\n", len(r.Files))
		if len(r.Unexplained) > 0 {
			b.WriteString("**Unexplained:**\n\n")
			for i, c := range r.Unexplained {
				if i == maxListed {
					fmt.Fprintf(&b, "- ... %d more\n", len(r.Unexplained)-maxListed)
					break
				}
				fmt.Fprintf(&b, "- `%s`: %s\n", sanitize(c.describe()), sanitize(c.Why))
			}
			for _, p := range sortedKeys(r.EtcDiffs) {
				fmt.Fprintf(&b, "\n`/%s` line diff:\n\n```\n", sanitize(p))
				for _, l := range r.EtcDiffs[p] {
					b.WriteString(strings.ReplaceAll(sanitize(l), "```", "'''") + "\n")
				}
				b.WriteString("```\n")
			}
			b.WriteString("\n")
		}
		b.WriteString("Attributed (first entries per class):\n\n")
		shown := map[string]int{}
		for _, c := range r.Files {
			if !c.explained() || shown[c.Class] >= 40 {
				continue
			}
			shown[c.Class]++
			fmt.Fprintf(&b, "- [%s] `%s`: %s\n", c.Class, sanitize(c.describe()), sanitize(c.Why))
		}
		b.WriteString("\n")
	}
	return b.String()
}

func cell(s string) string {
	if s == "" {
		return ""
	}
	return strings.ReplaceAll(sanitize(s), "|", "\\|")
}
