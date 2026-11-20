package actions

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
)

// sourceMap is a version-3 source map (index maps with "sections" are not
// supported).
type sourceMap struct {
	Version        int       `json:"version"`
	SourceRoot     string    `json:"sourceRoot"`
	Sources        []string  `json:"sources"`
	SourcesContent []*string `json:"sourcesContent"`
	Mappings       string    `json:"mappings"`
	Sections       []any     `json:"sections"`
}

func parseSourceMap(data []byte) (*sourceMap, error) {
	var m sourceMap
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	if m.Version != 3 || len(m.Sections) > 0 {
		return nil, fmt.Errorf("unsupported source map (version %d, %d sections)", m.Version, len(m.Sections))
	}
	return &m, nil
}

// mappedSource is what a bundle's source map attributes to one source.
type mappedSource struct {
	path    string // as listed in "sources"
	content *string
	gen     strings.Builder
	genLen  int
	srcHash [32]byte
	genNorm [32]byte
}

// mappedBundle is a bundle split by its source map.
type mappedBundle struct {
	total    int
	sources  map[string]*mappedSource // by source path
	order    []string
	unmapped []string // generated chunks mapped to no source
}

const b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

var b64val = func() [256]int8 {
	var t [256]int8
	for i := range t {
		t[i] = -1
	}
	for i := 0; i < len(b64); i++ {
		t[b64[i]] = int8(i)
	}
	return t
}()

// decodeVLQ decodes one segment's fields.
func decodeVLQ(seg string) ([]int, error) {
	var vals []int
	shift, value := 0, 0
	for i := 0; i < len(seg); i++ {
		d := b64val[seg[i]]
		if d < 0 {
			return nil, fmt.Errorf("bad base64 %q", seg[i])
		}
		value |= int(d&31) << shift
		if d&32 != 0 {
			shift += 5
			if shift > 30 {
				return nil, fmt.Errorf("VLQ overflow")
			}
			continue
		}
		if value&1 != 0 {
			vals = append(vals, -(value >> 1))
		} else {
			vals = append(vals, value>>1)
		}
		shift, value = 0, 0
	}
	if shift != 0 {
		return nil, fmt.Errorf("truncated VLQ")
	}
	return vals, nil
}

// utf16ToByte maps UTF-16 column positions of a line to byte offsets.
// Source map columns count UTF-16 code units.
func utf16ToByte(line string) func(col int) int {
	ascii := true
	for i := 0; i < len(line); i++ {
		if line[i] >= 0x80 {
			ascii = false
			break
		}
	}
	if ascii {
		return func(col int) int {
			if col > len(line) {
				return len(line)
			}
			return col
		}
	}
	var offs []int // offs[u16col] = byte offset
	for i, r := range line {
		offs = append(offs, i)
		if r >= 0x10000 { // a surrogate pair is two UTF-16 units
			offs = append(offs, i)
		}
	}
	offs = append(offs, len(line))
	return func(col int) int {
		if col >= len(offs) {
			return len(line)
		}
		if col < 0 {
			return 0
		}
		return offs[col]
	}
}

func splitByMap(js string, m *sourceMap) (*mappedBundle, error) {
	mb := &mappedBundle{total: len(js), sources: map[string]*mappedSource{}}
	idx := make([]*mappedSource, len(m.Sources))
	for i, p := range m.Sources {
		ms := mb.sources[p]
		if ms == nil {
			ms = &mappedSource{path: p}
			mb.sources[p] = ms
			mb.order = append(mb.order, p)
		}
		if i < len(m.SourcesContent) && m.SourcesContent[i] != nil {
			ms.content = m.SourcesContent[i]
		}
		idx[i] = ms
	}
	lines := strings.Split(js, "\n")
	mapLines := strings.Split(m.Mappings, ";")
	src := 0
	for ln, text := range lines {
		var segs []string
		if ln < len(mapLines) && mapLines[ln] != "" {
			segs = strings.Split(mapLines[ln], ",")
		}
		toByte := utf16ToByte(text)
		col := 0
		type piece struct {
			start int
			src   int // -1 for unmapped
		}
		var ps []piece
		for _, s := range segs {
			v, err := decodeVLQ(s)
			if err != nil {
				return nil, fmt.Errorf("mappings line %d: %v", ln+1, err)
			}
			if len(v) == 0 {
				continue
			}
			col += v[0]
			if len(v) >= 4 {
				src += v[1]
				if src < 0 || src >= len(idx) {
					return nil, fmt.Errorf("mappings line %d: source index %d out of range", ln+1, src)
				}
				ps = append(ps, piece{toByte(col), src})
			} else {
				ps = append(ps, piece{toByte(col), -1})
			}
		}
		pos := 0
		for k, p := range ps {
			if p.start > pos {
				mb.unmapped = append(mb.unmapped, text[pos:p.start])
			}
			if p.start < pos {
				p.start = pos // overlapping/unsorted segments: never double count
			}
			end := len(text)
			if k+1 < len(ps) && ps[k+1].start > p.start {
				end = ps[k+1].start
			}
			if end < p.start {
				end = p.start
			}
			chunk := text[p.start:end]
			if p.src < 0 {
				mb.unmapped = append(mb.unmapped, chunk)
			} else {
				idx[p.src].gen.WriteString(chunk)
			}
			pos = end
		}
		if pos < len(text) && len(ps) == 0 {
			mb.unmapped = append(mb.unmapped, text[pos:])
		}
	}
	for _, ms := range mb.sources {
		g := ms.gen.String()
		ms.genLen = len(g)
		ms.genNorm = sha256.Sum256([]byte(normalizeMinified(g)))
		if ms.content != nil {
			ms.srcHash = sha256.Sum256([]byte(*ms.content))
		}
	}
	return mb, nil
}

var jsShortKeywords = map[string]bool{
	"var": true, "let": true, "new": true, "for": true, "if": true, "in": true, "do": true,
	"try": true, "void": true, "this": true, "null": true, "true": true, "else": true,
	"case": true, "with": true, "enum": true,
}

func isIdentStart(c byte) bool {
	return c == '_' || c == '$' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIdentPart(c byte) bool { return isIdentStart(c) || (c >= '0' && c <= '9') }

// normalizeMinified replaces short identifiers (what a minifier renames)
// with a placeholder, so a module whose only change is renamed locals
// compares equal. Property accesses (x.ab) keep their names; spreads
// (...ab) do not.
func normalizeMinified(s string) string {
	var sb strings.Builder
	sb.Grow(len(s))
	i := 0
	for i < len(s) {
		c := s[i]
		if !isIdentStart(c) || (i > 0 && isIdentPart(s[i-1])) {
			sb.WriteByte(c)
			i++
			continue
		}
		j := i + 1
		for j < len(s) && isIdentPart(s[j]) {
			j++
		}
		id := s[i:j]
		prop := i > 0 && s[i-1] == '.' && !(i >= 3 && s[i-3:i] == "...")
		if len(id) <= 4 && !prop && !jsShortKeywords[id] {
			sb.WriteByte(0)
		} else {
			sb.WriteString(id)
		}
		i = j
	}
	return sb.String()
}
