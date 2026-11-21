package gomod

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// ModFile is the part of a go.mod the gate needs. It is a small parser of
// its own (standard library only), not golang.org/x/mod.
type ModFile struct {
	Module    string
	Go        string
	Toolchain string
	Require   map[string]Require // by module path
	// Other directives that change what gets built or run, normalized one
	// per line ("replace a => b v1", "exclude m v1", "godebug k=v", "tool p",
	// "ignore d"); compared as sets between base and head.
	Directives []string

	seen map[string]bool // "verb key" of require/replace/exclude lines, for ErrDuplicate
}

// ErrDuplicate is returned for a go.mod that names the same module twice
// where one reading must win: two require lines for one path (the gate's
// map would keep the last), two replace lines with the same left-hand side
// ("path" or "path version"), or one exclude line repeated. Excluding or
// replacing several versions of one path is ordinary and allowed.
var ErrDuplicate = errors.New("duplicate module in go.mod")

type Require struct {
	Version  string
	Indirect bool
}

// ParseModFile parses go.mod text.
func ParseModFile(data []byte) (*ModFile, error) {
	mf := &ModFile{Require: map[string]Require{}, seen: map[string]bool{}}
	block := ""
	for i, raw := range strings.Split(string(data), "\n") {
		line, comment := splitComment(raw)
		fields, err := tokenize(line)
		if err != nil {
			return nil, fmt.Errorf("go.mod:%d: %w", i+1, err)
		}
		if len(fields) == 0 {
			continue
		}
		if block != "" {
			if fields[0] == ")" {
				block = ""
				continue
			}
			if err := mf.directive(block, fields, comment); err != nil {
				return nil, fmt.Errorf("go.mod:%d: %w", i+1, err)
			}
			continue
		}
		if len(fields) == 2 && fields[1] == "(" {
			block = fields[0]
			continue
		}
		if err := mf.directive(fields[0], fields[1:], comment); err != nil {
			return nil, fmt.Errorf("go.mod:%d: %w", i+1, err)
		}
	}
	if block != "" {
		return nil, fmt.Errorf("go.mod: unterminated %s block", block)
	}
	if mf.Module == "" {
		return nil, fmt.Errorf("go.mod: no module directive")
	}
	slices.Sort(mf.Directives)
	return mf, nil
}

func (mf *ModFile) directive(verb string, args []string, comment string) error {
	switch verb {
	case "module":
		if len(args) != 1 {
			return fmt.Errorf("module: want 1 argument")
		}
		mf.Module = args[0]
	case "go":
		if len(args) != 1 {
			return fmt.Errorf("go: want 1 argument")
		}
		mf.Go = args[0]
	case "toolchain":
		if len(args) != 1 {
			return fmt.Errorf("toolchain: want 1 argument")
		}
		mf.Toolchain = args[0]
	case "require":
		if len(args) != 2 {
			return fmt.Errorf("require: want path and version, got %q", args)
		}
		if err := mf.once("require", args[0]); err != nil {
			return err
		}
		indirect := slices.Contains(strings.Fields(strings.ReplaceAll(comment, ";", " ")), "indirect")
		mf.Require[args[0]] = Require{Version: args[1], Indirect: indirect}
	case "retract":
		// Retractions only matter to the module's own consumers.
	case "replace", "exclude", "godebug", "tool", "ignore":
		switch verb {
		case "replace":
			lhs, _, _ := strings.Cut(strings.Join(args, " "), " =>")
			if err := mf.once(verb, strings.TrimSpace(lhs)); err != nil {
				return err
			}
		case "exclude":
			if err := mf.once(verb, strings.Join(args, " ")); err != nil {
				return err
			}
		}
		mf.Directives = append(mf.Directives, verb+" "+strings.Join(args, " "))
	default:
		mf.Directives = append(mf.Directives, "unknown-directive "+verb+" "+strings.Join(args, " "))
	}
	return nil
}

// splitComment separates "// ..." from the line, outside quoted strings.
func splitComment(line string) (string, string) {
	inQuote, inBack := false, false
	for i := 0; i < len(line); i++ {
		switch c := line[i]; {
		case inQuote:
			if c == '\\' {
				i++
			} else if c == '"' {
				inQuote = false
			}
		case inBack:
			if c == '`' {
				inBack = false
			}
		case c == '"':
			inQuote = true
		case c == '`':
			inBack = true
		case c == '/' && i+1 < len(line) && line[i+1] == '/':
			return line[:i], strings.TrimSpace(line[i+2:])
		}
	}
	return line, ""
}

// tokenize splits a go.mod line into fields, unquoting "..." and `...`, and
// keeping "(", ")" and "=>" as their own fields.
func tokenize(line string) ([]string, error) {
	var out []string
	for i := 0; i < len(line); {
		c := line[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r':
			i++
		case c == '(' || c == ')':
			out = append(out, string(c))
			i++
		case c == '"' || c == '`':
			j := i + 1
			for j < len(line) && line[j] != c {
				if c == '"' && line[j] == '\\' {
					j++
				}
				j++
			}
			if j >= len(line) {
				return nil, fmt.Errorf("unterminated string")
			}
			s, err := strconv.Unquote(line[i : j+1])
			if err != nil {
				return nil, err
			}
			out = append(out, s)
			i = j + 1
		default:
			j := i
			for j < len(line) && !strings.ContainsRune(" \t\r()\"`", rune(line[j])) {
				j++
			}
			out = append(out, line[i:j])
			i = j
		}
	}
	return out, nil
}

// SumFile is a parsed go.sum: hashes by "module version" (the module zip)
// and "module version/go.mod".
type SumFile map[string]string

func ParseSumFile(data []byte) (SumFile, error) {
	s := SumFile{}
	for i, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if len(f) != 3 || !strings.HasPrefix(f[2], "h1:") {
			return nil, fmt.Errorf("go.sum:%d: malformed line", i+1)
		}
		key := f[0] + " " + f[1]
		if old, ok := s[key]; ok && old != f[2] {
			return nil, fmt.Errorf("go.sum:%d: two hashes for %s", i+1, key)
		}
		s[key] = f[2]
	}
	return s, nil
}

// ZipVersions returns, per module path, the versions whose module zip (not
// just go.mod) is hashed.
func (s SumFile) ZipVersions() map[string][]string {
	out := map[string][]string{}
	for k := range s {
		mod, ver, _ := strings.Cut(k, " ")
		if strings.HasSuffix(ver, "/go.mod") {
			continue
		}
		out[mod] = append(out[mod], ver)
	}
	for _, v := range out {
		slices.Sort(v)
	}
	return out
}

func (mf *ModFile) once(verb, key string) error {
	if mf.seen[verb+" "+key] {
		return fmt.Errorf("%w: %s %s appears twice", ErrDuplicate, verb, key)
	}
	mf.seen[verb+" "+key] = true
	return nil
}
