package docker

import (
	"path"
	"regexp"
	"slices"
	"strings"
)

// Which platforms a repository builds a Dockerfile for, read from its
// workflow files. This is a deliberately small line/indent scanner, not a
// YAML parser: it understands docker/build-push-action's `context:`,
// `file:` and `platforms:`, `docker [buildx] build` commands with
// `--platform`/`-f`, `${{ matrix.X }}` expansion from the same job, and
// `runs-on:` for the build platform. Anything it cannot resolve falls back
// to the default (linux/amd64 + linux/arm64), which only ever widens the
// set of platforms checked.

var defaultPlatforms = []string{"linux/amd64", "linux/arm64"}

type platformInfo struct {
	Targets   []string // platforms images are built for
	Build     []string // runner platforms ($BUILDPLATFORM)
	Sources   []string // "workflow:job" that build this Dockerfile
	Notes     []string // why a default was used
	Defaulted bool
}

// stagePlatforms is the set of platforms one stage's base image is pulled
// for: $BUILDPLATFORM stages run on the runner, a literal --platform is
// itself, everything else follows the targets.
func (pi platformInfo) stagePlatforms(flag string) []string {
	switch {
	case flag == "":
		return pi.Targets
	case strings.Contains(flag, "BUILDPLATFORM"):
		return pi.Build
	case strings.Contains(flag, "$"):
		return pi.Targets
	}
	var out []string
	for p := range strings.SplitSeq(flag, ",") {
		out = append(out, normPlatform(p))
	}
	return out
}

type job struct {
	file, name string
	lines      []string
}

var (
	jobKeyRe   = regexp.MustCompile(`^(\s+)([A-Za-z0-9_-]+):\s*(#.*)?$`)
	matrixRef  = regexp.MustCompile(`\$\{\{\s*matrix\.([A-Za-z0-9_-]+)\s*\}\}`)
	anyExpr    = regexp.MustCompile(`\$\{\{.*?\}\}`)
	platformRe = regexp.MustCompile(`--platform[= ]\s*("[^"]*"|'[^']*'|\S+)`)
	fileFlagRe = regexp.MustCompile(`(?:^|\s)(?:-f|--file)[= ]\s*("[^"]*"|'[^']*'|\S+)`)
	buildCmdRe = regexp.MustCompile(`\bdocker\s+(?:buildx\s+)?build\b|\bbuildah\s+bud\b|\bpodman\s+build\b`)
)

func splitJobs(file, content string) []job {
	lines := splitLines(content)
	start := -1
	for i, l := range lines {
		if strings.HasPrefix(l, "jobs:") {
			start = i + 1
			break
		}
	}
	if start < 0 {
		return nil
	}
	var jobs []job
	indent := ""
	for i := start; i < len(lines); i++ {
		l := lines[i]
		if l != "" && l[0] != ' ' && l[0] != '#' {
			break // next top-level key
		}
		m := jobKeyRe.FindStringSubmatch(l)
		if m != nil && (indent == "" || m[1] == indent) {
			indent = m[1]
			jobs = append(jobs, job{file: file, name: m[2]})
			continue
		}
		if len(jobs) > 0 {
			jobs[len(jobs)-1].lines = append(jobs[len(jobs)-1].lines, l)
		}
	}
	return jobs
}

func cleanValue(v string) string {
	if i := strings.Index(v, " #"); i >= 0 {
		v = v[:i]
	}
	v = strings.TrimSpace(v)
	return strings.Trim(v, `"'`)
}

// keyValues returns every value of key in the job (scalars, [a, b] lists
// and block lists).
func (j job) keyValues(key string) []string {
	re := regexp.MustCompile(`^(\s*)(?:-\s+)?` + regexp.QuoteMeta(key) + `:\s*(.*)$`)
	var out []string
	for i := 0; i < len(j.lines); i++ {
		m := re.FindStringSubmatch(j.lines[i])
		if m == nil {
			continue
		}
		v := cleanValue(m[2])
		switch {
		case strings.HasPrefix(v, "["):
			for x := range strings.SplitSeq(strings.Trim(v, "[]"), ",") {
				if x = cleanValue(x); x != "" {
					out = append(out, x)
				}
			}
		case v == "" || v == "|" || v == ">":
			for k := i + 1; k < len(j.lines); k++ {
				t := strings.TrimSpace(j.lines[k])
				if !strings.HasPrefix(t, "- ") {
					break
				}
				out = append(out, cleanValue(t[2:]))
			}
		default:
			out = append(out, v)
		}
	}
	return out
}

// expand resolves ${{ matrix.X }} in v against the job's matrix. ok is
// false if an expression remains.
func (j job) expand(v string) ([]string, bool) {
	m := matrixRef.FindStringSubmatch(v)
	if m == nil {
		return []string{v}, !anyExpr.MatchString(v)
	}
	vals := j.keyValues(m[1])
	if len(vals) == 0 {
		return nil, false
	}
	var out []string
	ok := true
	for _, x := range vals {
		e, eok := j.expand(strings.Replace(v, m[0], x, 1))
		ok = ok && eok
		out = append(out, e...)
	}
	return out, ok
}

func normCtx(c string) string {
	c = strings.TrimSpace(c)
	c = strings.TrimPrefix(c, "${{ github.workspace }}")
	c = path.Clean("./" + strings.TrimPrefix(c, "/"))
	return c
}

// builds reports whether job j builds the Dockerfile at dfPath and returns
// the raw platform values it sets ("" entries mean "native").
func (j job) builds(dfPath string) (bool, []string) {
	dfDir := path.Dir(dfPath)
	usesBPA := false
	for _, l := range j.lines {
		if strings.Contains(l, "docker/build-push-action") {
			usesBPA = true
		}
	}
	matched := false
	var plats []string
	if usesBPA {
		ctxs, files := j.keyValues("context"), j.keyValues("file")
		switch {
		case len(files) > 0:
			for _, f := range files {
				if normCtx(f) == path.Clean(dfPath) {
					matched = true
				}
			}
		case len(ctxs) > 0:
			for _, c := range ctxs {
				if normCtx(c) == dfDir && strings.EqualFold(path.Base(dfPath), "Dockerfile") {
					matched = true
				}
			}
		default:
			// Git context: the repository root's Dockerfile.
			matched = dfPath == "Dockerfile"
		}
		if matched {
			plats = append(plats, j.keyValues("platforms")...)
		}
	}
	for _, l := range j.lines {
		if !buildCmdRe.MatchString(l) {
			continue
		}
		hit := false
		if m := fileFlagRe.FindStringSubmatch(l); m != nil {
			hit = normCtx(strings.Trim(m[1], `"'`)) == path.Clean(dfPath)
		} else {
			f := strings.Fields(l)
			c := cleanValue(f[len(f)-1])
			hit = normCtx(c) == dfDir && strings.EqualFold(path.Base(dfPath), "Dockerfile")
		}
		if !hit {
			continue
		}
		matched = true
		if m := platformRe.FindStringSubmatch(l); m != nil {
			plats = append(plats, strings.Trim(m[1], `"'`))
		} else {
			plats = append(plats, "")
		}
	}
	return matched, plats
}

func runnerPlatform(r string) (string, bool) {
	r = strings.ToLower(r)
	switch {
	case strings.Contains(r, "self-hosted") || strings.Contains(r, "$"):
		return "", false
	case strings.Contains(r, "arm"):
		return "linux/arm64", true
	case strings.HasPrefix(r, "ubuntu-"):
		return "linux/amd64", true
	}
	return "", false
}

// detectPlatforms scans workflow files (path -> content) for jobs that
// build dfPath.
func detectPlatforms(workflows map[string]string, dfPath string) platformInfo {
	var pi platformInfo
	targets, build := map[string]bool{}, map[string]bool{}
	unresolved := false
	names := make([]string, 0, len(workflows))
	for n := range workflows {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		for _, j := range splitJobs(n, workflows[n]) {
			ok, raw := j.builds(dfPath)
			if !ok {
				continue
			}
			pi.Sources = append(pi.Sources, path.Base(n)+":"+j.name)
			var runners []string
			for _, r := range j.keyValues("runs-on") {
				vals, rok := j.expand(r)
				if !rok {
					unresolved = true
					pi.Notes = append(pi.Notes, "unresolved runs-on in "+path.Base(n)+":"+j.name)
				}
				for _, v := range vals {
					p, pok := runnerPlatform(v)
					if !pok {
						unresolved = true
						pi.Notes = append(pi.Notes, "unknown runner "+v)
						continue
					}
					runners = append(runners, p)
					build[p] = true
				}
			}
			if len(raw) == 0 {
				raw = []string{""}
			}
			for _, r := range raw {
				if r == "" {
					// Native build: the runner's platform.
					for _, p := range runners {
						targets[p] = true
					}
					if len(runners) == 0 {
						unresolved = true
					}
					continue
				}
				vals, rok := j.expand(r)
				if !rok {
					unresolved = true
					pi.Notes = append(pi.Notes, "unresolved platforms "+r+" in "+path.Base(n)+":"+j.name)
				}
				for _, v := range vals {
					for p := range strings.SplitSeq(v, ",") {
						if p = strings.TrimSpace(p); p != "" && !strings.Contains(p, "$") {
							targets[normPlatform(p)] = true
						}
					}
				}
			}
		}
	}
	if len(pi.Sources) == 0 {
		pi.Notes = append(pi.Notes, "no workflow job builds "+dfPath)
	}
	if len(pi.Sources) == 0 || unresolved || len(targets) == 0 {
		pi.Defaulted = true
		for _, p := range defaultPlatforms {
			targets[p] = true
			build[p] = true
		}
	}
	if len(build) == 0 {
		for p := range targets {
			build[p] = true
		}
	}
	pi.Targets = sortedKeys(targets)
	pi.Build = sortedKeys(build)
	return pi
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
