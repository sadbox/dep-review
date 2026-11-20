package docker

import (
	"fmt"
	"path"
	"strings"
)

// fromLine is one parsed FROM instruction.
type fromLine struct {
	Line     int    // 1-based
	Platform string // value of --platform=, "" if none
	Image    string // as written
	Stage    string // AS name, "" if none
	Raw      string
}

// parseFrom parses a FROM line; ok is false if line is not a FROM.
func parseFrom(line string) (f fromLine, ok bool, err error) {
	fields := strings.Fields(line)
	if len(fields) == 0 || !strings.EqualFold(fields[0], "FROM") {
		return f, false, nil
	}
	f.Raw = strings.TrimSpace(line)
	rest := fields[1:]
	for len(rest) > 0 && strings.HasPrefix(rest[0], "--") {
		k, v, _ := strings.Cut(rest[0], "=")
		if k != "--platform" {
			return f, true, fmt.Errorf("unsupported FROM flag %q", k)
		}
		f.Platform = v
		rest = rest[1:]
	}
	switch {
	case len(rest) == 1:
	case len(rest) == 3 && strings.EqualFold(rest[1], "AS"):
		f.Stage = strings.ToLower(rest[2])
	default:
		return f, true, fmt.Errorf("cannot parse FROM line %q", f.Raw)
	}
	f.Image = rest[0]
	return f, true, nil
}

// stage describes one FROM of a Dockerfile.
type stage struct {
	fromLine
	Index int
	Final bool // the last stage: what `docker build` produces without --target
	// Used lists how later stages consume this one (COPY --from, FROM <stage>).
	Used []string
}

// parseStages lists the stages of a Dockerfile.
func parseStages(content string) ([]stage, error) {
	var out []stage
	lines := splitLines(content)
	for i, l := range lines {
		f, ok, err := parseFrom(l)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		if !ok {
			continue
		}
		f.Line = i + 1
		out = append(out, stage{fromLine: f, Index: len(out)})
	}
	if len(out) > 0 {
		out[len(out)-1].Final = true
	}
	// Who uses which stage: COPY --from=<name|index> and FROM <name>.
	cur := -1
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if f, ok, _ := parseFrom(t); ok {
			cur++
			for j := range out[:cur] {
				if out[j].Stage != "" && strings.EqualFold(f.Image, out[j].Stage) {
					out[j].Used = append(out[j].Used, fmt.Sprintf("line %d: base of stage %d", i+1, cur))
				}
			}
			continue
		}
		for _, fld := range strings.Fields(t) {
			v, ok := strings.CutPrefix(fld, "--from=")
			if !ok {
				continue
			}
			for j := range out {
				if j != cur && (strings.EqualFold(v, out[j].Stage) || v == fmt.Sprint(j)) {
					out[j].Used = append(out[j].Used, fmt.Sprintf("line %d: %s", i+1, t))
				}
			}
		}
	}
	return out, nil
}

func splitLines(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.Split(s, "\n")
}

// isDockerfile reports whether a changed path is one Dependabot's docker
// ecosystem edits.
func isDockerfile(p string) bool {
	b := strings.ToLower(path.Base(p))
	return b == "dockerfile" || b == "containerfile" ||
		strings.HasPrefix(b, "dockerfile.") || strings.HasSuffix(b, ".dockerfile") ||
		strings.HasPrefix(b, "containerfile.") || strings.HasSuffix(b, ".containerfile")
}

// fromChange is one FROM line whose image reference changed.
type fromChange struct {
	Path     string // Dockerfile path
	Line     int
	Old, New imageRef
	OldRaw   string
	NewRaw   string
	Stage    stage // in the new Dockerfile
}

// changeError is a Dockerfile change the gate refuses to interpret.
type changeError struct {
	Code   string
	Detail string
}

func (e *changeError) Error() string { return e.Detail }

// diffDockerfile compares a Dockerfile at base and head. The only change
// allowed is the image reference of FROM lines (same flags, same stage
// name, same image name); anything else is a changeError.
func diffDockerfile(p, oldContent, newContent string) ([]fromChange, []stage, error) {
	ol, nl := splitLines(oldContent), splitLines(newContent)
	if len(ol) != len(nl) {
		return nil, nil, &changeError{codeDockerfileOther, fmt.Sprintf("%s: line count changed (%d -> %d); only FROM references may change", p, len(ol), len(nl))}
	}
	stages, err := parseStages(newContent)
	if err != nil {
		return nil, nil, &changeError{codeFromUnparseable, fmt.Sprintf("%s: %v", p, err)}
	}
	byLine := map[int]stage{}
	for _, s := range stages {
		byLine[s.Line] = s
	}
	var out []fromChange
	for i := range ol {
		if ol[i] == nl[i] {
			continue
		}
		of, ook, oerr := parseFrom(ol[i])
		nf, nok, nerr := parseFrom(nl[i])
		if !ook || !nok {
			return nil, nil, &changeError{codeDockerfileOther, fmt.Sprintf("%s:%d: a non-FROM line changed", p, i+1)}
		}
		if oerr != nil || nerr != nil {
			return nil, nil, &changeError{codeFromUnparseable, fmt.Sprintf("%s:%d: %v", p, i+1, firstErr(oerr, nerr))}
		}
		if of.Platform != nf.Platform || of.Stage != nf.Stage {
			return nil, nil, &changeError{codeDockerfileOther, fmt.Sprintf("%s:%d: FROM flags or stage name changed", p, i+1)}
		}
		oref, err1 := parseRef(of.Image)
		nref, err2 := parseRef(nf.Image)
		if err := firstErr(err1, err2); err != nil {
			return nil, nil, &changeError{codeFromUnparseable, fmt.Sprintf("%s:%d: %v", p, i+1, err)}
		}
		if oref.Digest == "" || nref.Digest == "" {
			return nil, nil, &changeError{codeFromUnpinned, fmt.Sprintf("%s:%d: FROM %s is not pinned by digest", p, i+1, nf.Image)}
		}
		if oref.Registry != nref.Registry || oref.Repo != nref.Repo {
			return nil, nil, &changeError{codeDockerfileOther, fmt.Sprintf("%s:%d: image changed from %s to %s", p, i+1, oref.Name(), nref.Name())}
		}
		if oref == nref {
			return nil, nil, &changeError{codeDockerfileOther, fmt.Sprintf("%s:%d: whitespace-only FROM change", p, i+1)}
		}
		out = append(out, fromChange{Path: p, Line: i + 1, Old: oref, New: nref, OldRaw: of.Raw, NewRaw: nf.Raw, Stage: byLine[i+1]})
	}
	return out, stages, nil
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}
