// Package evidence writes the evidence directory the reviewer reads:
//
//	evidence.json   model.Evidence (the gate's own analysis)
//	gate/...        files the gate wrote itself (summaries)
//	untrusted/...   text taken from dependencies and upstreams (diffs, changelogs)
//
// It implements fetch.Writer. Every file is normalized to valid UTF-8 text;
// binary content is never written and is recorded as a finding instead.
// Names are sanitized into the directory (no "..", no absolute paths) and
// all writes go through an os.Root, so nothing can land outside it and no
// symlink is ever created or followed. Per-file and total size caps keep the
// evidence within a model's context; any cut is recorded as truncation,
// which forces model.RouteHuman through policy.Combine.
package evidence

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/sadbox/dep-review/internal/model"
)

const (
	// DefaultFileCap is the largest single evidence file, in bytes.
	DefaultFileCap = 400 << 10
	// DefaultTotalCap bounds all evidence files together: roughly what a
	// model can read in one review without losing the start.
	DefaultTotalCap = 4 << 20

	GateDir      = "gate"
	UntrustedDir = "untrusted"
	EvidenceJSON = "evidence.json"
)

// Dir is an evidence directory. It is safe for concurrent use.
type Dir struct {
	root     *os.Root
	fileCap  int
	totalCap int

	mu        sync.Mutex
	total     int
	files     []model.EvidenceFile
	names     map[string]bool
	findings  []model.Finding
	truncated bool
	omitted   []string
}

// Option adjusts a Dir's caps (tests use small ones).
type Option func(*Dir)

func WithCaps(fileCap, totalCap int) Option {
	return func(d *Dir) { d.fileCap, d.totalCap = fileCap, totalCap }
}

// Create makes dir (which must not exist, or be empty) and opens it.
func Create(dir string, opts ...Option) (*Dir, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	if len(ents) > 0 {
		return nil, fmt.Errorf("evidence directory %s is not empty", dir)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	d := &Dir{root: root, fileCap: DefaultFileCap, totalCap: DefaultTotalCap, names: map[string]bool{}}
	for _, o := range opts {
		o(d)
	}
	return d, nil
}

// Close releases the directory handle.
func (d *Dir) Close() error { return d.root.Close() }

// Add writes a gate-authored file under gate/.
func (d *Dir) Add(name, description string, content []byte) error {
	return d.add(GateDir, name, description, content, false)
}

// AddUntrusted writes third-party text under untrusted/.
func (d *Dir) AddUntrusted(name, description string, content []byte) error {
	return d.add(UntrustedDir, name, description, content, true)
}

func (d *Dir) add(top, name, description string, content []byte, untrusted bool) error {
	rel := top + "/" + SanitizeName(name)

	text, ok := Normalize(content)
	d.mu.Lock()
	defer d.mu.Unlock()
	if !ok {
		d.findings = append(d.findings, model.Finding{
			Code:   "evidence.binary",
			Route:  model.RouteHuman,
			Detail: fmt.Sprintf("%s is binary (%d bytes) and was not written; nobody can review it as text", rel, len(content)),
		})
		return nil
	}
	if untrusted && hasBidi(content) {
		d.findings = append(d.findings, model.Finding{
			Code:   "evidence.bidi-control",
			Route:  model.RouteHuman,
			Detail: fmt.Sprintf("%s contains Unicode bidirectional control characters (shown as <U+XXXX>); text may not read the way it compiles", rel),
		})
	}
	rel = d.unique(rel)

	desc := description
	room := min(d.fileCap, d.totalCap-d.total)
	if room <= 0 {
		d.truncated = true
		d.omitted = append(d.omitted, rel)
		return nil
	}
	if len(text) > room {
		const format = "\n[dep-review: truncated here; %d of %d bytes shown]\n"
		// The marker with len(text) twice is at least as long as the real one.
		keep := max(room-len(fmt.Sprintf(format, len(text), len(text))), 0)
		cut := utf8Prefix(text, keep)
		marker := fmt.Sprintf(format, len(cut), len(text))
		text = append(cut, marker...)
		if len(text) > room { // pathological tiny caps
			text = text[:room]
		}
		d.truncated = true
		desc += " (TRUNCATED)"
	}
	if err := d.write(rel, text); err != nil {
		return err
	}
	d.total += len(text)
	d.names[rel] = true
	d.files = append(d.files, model.EvidenceFile{Path: rel, Description: desc, Untrusted: untrusted, Bytes: int64(len(text))})
	return nil
}

func (d *Dir) write(rel string, data []byte) error {
	if dir := path.Dir(rel); dir != "." {
		if err := d.root.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	// O_EXCL: never reuse or follow anything already at the path.
	f, err := d.root.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// unique returns rel, or rel with a numeric suffix if it was already used
// (two names can sanitize to the same path). Caller holds d.mu.
func (d *Dir) unique(rel string) string {
	if !d.names[rel] {
		return rel
	}
	ext := path.Ext(rel)
	base := strings.TrimSuffix(rel, ext)
	for i := 2; ; i++ {
		c := fmt.Sprintf("%s-%d%s", base, i, ext)
		if !d.names[c] {
			return c
		}
	}
}

// Files lists the files written, in order.
func (d *Dir) Files() []model.EvidenceFile {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]model.EvidenceFile(nil), d.files...)
}

// Truncated reports whether any cap cut evidence short.
func (d *Dir) Truncated() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.truncated
}

// Findings are the writer's own observations (binary content, bidi
// controls, omitted files).
func (d *Dir) Findings() []model.Finding {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := append([]model.Finding(nil), d.findings...)
	if len(d.omitted) > 0 {
		out = append(out, model.Finding{
			Code:   "evidence.omitted",
			Route:  model.RouteHuman,
			Detail: fmt.Sprintf("total evidence cap (%d bytes) reached; not written: %s", d.totalCap, strings.Join(d.omitted, ", ")),
		})
	}
	return out
}

// WriteEvidence writes evidence.json at the root. It is not counted toward
// the caps: it is the gate's own structured output.
func (d *Dir) WriteEvidence(ev model.Evidence) error {
	b, err := json.MarshalIndent(ev, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if _, err := d.root.Lstat(EvidenceJSON); err == nil {
		return fmt.Errorf("%s already written", EvidenceJSON)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return d.write(EvidenceJSON, b)
}

// SanitizeName maps an arbitrary name (often containing a package name such
// as "@scope/pkg" or a module path) to a safe relative slash path: every
// element is limited to [A-Za-z0-9._@+=-], "." and ".." elements are
// replaced, empty elements dropped, and leading dots neutralized so no
// hidden files appear. The result is never empty or absolute.
func SanitizeName(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	var parts []string
	for _, p := range strings.Split(name, "/") {
		if p == "" {
			continue
		}
		var b strings.Builder
		for _, r := range p {
			switch {
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
				r == '.', r == '_', r == '-', r == '@', r == '+', r == '=':
				b.WriteRune(r)
			default:
				b.WriteByte('_')
			}
		}
		s := b.String()
		if strings.HasPrefix(s, ".") {
			s = "_" + s[1:]
		}
		if len(s) > 120 {
			s = s[:120]
		}
		parts = append(parts, s)
	}
	if len(parts) == 0 {
		return "_"
	}
	return strings.Join(parts, "/")
}

// Normalize turns content into valid UTF-8 text for the reviewer. It
// reports false for binary content (NUL bytes, or mostly invalid UTF-8 or
// control characters), which must not be written at all. Invalid sequences
// become U+FFFD, control characters other than tab/newline/CR become
// visible <0xNN>, and bidi controls become <U+XXXX>.
func Normalize(b []byte) ([]byte, bool) {
	if IsBinary(b) {
		return nil, false
	}
	var out bytes.Buffer
	out.Grow(len(b))
	for len(b) > 0 {
		r, n := utf8.DecodeRune(b)
		switch {
		case r == utf8.RuneError && n <= 1:
			out.WriteRune(utf8.RuneError)
		case r == '\t' || r == '\n' || r == '\r':
			out.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&out, "<0x%02X>", r)
		case isBidi(r):
			fmt.Fprintf(&out, "<U+%04X>", r)
		default:
			out.Write(b[:n])
		}
		b = b[n:]
	}
	return out.Bytes(), true
}

// IsBinary is the gate's test for "not text": any NUL byte, or more than 10%
// of the content invalid UTF-8 or C0 control characters.
func IsBinary(b []byte) bool {
	if bytes.IndexByte(b, 0) >= 0 {
		return true
	}
	bad, n := 0, 0
	for len(b) > 0 {
		r, sz := utf8.DecodeRune(b)
		if (r == utf8.RuneError && sz <= 1) || (r < 0x20 && r != '\t' && r != '\n' && r != '\r' && r != '\f' && r != 0x1b) {
			bad++
		}
		n++
		b = b[sz:]
	}
	return n > 0 && bad*10 > n
}

func isBidi(r rune) bool {
	return (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) || r == 0x200E || r == 0x200F || r == 0x061C
}

func hasBidi(b []byte) bool {
	for len(b) > 0 {
		r, n := utf8.DecodeRune(b)
		if isBidi(r) {
			return true
		}
		b = b[n:]
	}
	return false
}

// utf8Prefix returns the longest prefix of b no longer than n bytes that
// does not split a UTF-8 sequence.
func utf8Prefix(b []byte, n int) []byte {
	if n >= len(b) {
		return b
	}
	for n > 0 && !utf8.RuneStart(b[n]) {
		n--
	}
	return b[:n]
}
