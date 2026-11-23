package actions

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/sadbox/dep-review/internal/gh"
	"github.com/sadbox/dep-review/internal/model"
)

func applyOps(a, b []string, ops []lineOp) (oldOut, newOut []string) {
	for _, op := range ops {
		switch op.kind {
		case opEqual:
			if a[op.a] != b[op.b] {
				panic("equal op on different lines")
			}
			oldOut = append(oldOut, a[op.a])
			newOut = append(newOut, b[op.b])
		case opDelete:
			oldOut = append(oldOut, a[op.a])
		case opInsert:
			newOut = append(newOut, b[op.b])
		}
	}
	return
}

func TestDiffLinesReconstructs(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	words := []string{"a", "b", "c", "d", "e", "}", "{", ""}
	gen := func(n int) []string {
		var l []string
		for range n {
			l = append(l, words[r.Intn(len(words))])
		}
		return l
	}
	for i := range 300 {
		a, b := gen(r.Intn(40)), gen(r.Intn(40))
		if i%3 == 0 {
			b = append(append([]string{}, a[:len(a)/2]...), b...)
		}
		ops := diffLines(a, b)
		oa, ob := applyOps(a, b, ops)
		if strings.Join(oa, "\n") != strings.Join(a, "\n") || strings.Join(ob, "\n") != strings.Join(b, "\n") {
			t.Fatalf("case %d: edit script does not reproduce inputs", i)
		}
	}
}

func TestUnifiedDiff(t *testing.T) {
	got := unifiedDiff("a/x", "b/x", "1\n2\n3\n4\n5\n6\n7\n8\n9\n", "1\n2\n3\n4\nfive\n6\n7\n8\n9\nten\n", 1)
	want := "--- a/x\n+++ b/x\n@@ -4,3 +4,3 @@\n 4\n-5\n+five\n 6\n@@ -9,1 +9,2 @@\n 9\n+ten\n"
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
	if unifiedDiff("a", "b", "same\n", "same\n", 3) != "" {
		t.Fatal("equal inputs must give an empty diff")
	}
	if n := insertedBytes("a\nb\n", "a\nxyz\nb\n"); n != 4 {
		t.Fatalf("insertedBytes = %d", n)
	}
}

func TestVersionComments(t *testing.T) {
	v := semver{4, 6, 0}
	tests := []struct {
		comment string
		ok      bool
		match   bool
	}{
		{"v4", true, true},
		{"v4.6", true, true},
		{"v4.6.0", true, true},
		{"v4.5.1", true, false},
		{"v5", true, false},
		{"v04", false, false},
		{"latest", false, false},
		{"", false, false},
	}
	for _, tt := range tests {
		parts, ok := versionComment(tt.comment)
		if ok != tt.ok || (ok && commentMatches(parts, v) != tt.match) {
			t.Errorf("comment %q: ok=%v match=%v", tt.comment, ok, ok && commentMatches(parts, v))
		}
	}
	types := []struct {
		from, to string
		want     model.UpdateType
	}{
		{"v7.0.0", "v7.1.0", model.Minor},
		{"v7.0.1", "v7.0.2", model.Patch},
		{"v4.8.0", "v5.0.0", model.Major},
	}
	for _, tt := range types {
		a, _ := parseTag(tt.from)
		b, _ := parseTag(tt.to)
		if got := updateType(a, b); got != tt.want {
			t.Errorf("%s->%s = %s", tt.from, tt.to, got)
		}
	}
	for _, bad := range []string{"v1.2", "1.2.3", "v1.2.3-rc.1", "v01.2.3"} {
		if _, ok := parseTag(bad); ok {
			t.Errorf("parseTag(%q) accepted", bad)
		}
	}
}

func TestParseActionMetaRecorded(t *testing.T) {
	tests := []struct {
		file                   string
		using, main, post, pIf string
		inputs, outputs        int
	}{
		{"setup-go-v7.0.0.action.yml", "node24", "dist/setup/index.js", "dist/cache-save/index.js", "success()", 8, 2},
		{"setup-go-v7.1.0.action.yml", "node24", "dist/setup/index.js", "dist/cache-save/index.js", "success()", 8, 11},
		{"login-action-v4.7.0.action.yml", "node24", "dist/index.cjs", "dist/index.cjs", "", -1, -1},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			m, err := parseActionMeta(readFixture(t, "upstream/"+tt.file))
			if err != nil {
				t.Fatal(err)
			}
			if m.using != tt.using || m.main != tt.main || m.post != tt.post || m.postIf != tt.pIf {
				t.Fatalf("got using=%q main=%q post=%q post-if=%q", m.using, m.main, m.post, m.postIf)
			}
			if tt.inputs >= 0 && (len(m.inputs.keys) != tt.inputs || len(m.outputs.keys) != tt.outputs) {
				t.Fatalf("inputs=%d outputs=%d", len(m.inputs.keys), len(m.outputs.keys))
			}
		})
	}
	// setup-go 7.0.0 -> 7.1.0 only adds outputs: no routing findings.
	o, _ := parseActionMeta(readFixture(t, "upstream/setup-go-v7.0.0.action.yml"))
	n, _ := parseActionMeta(readFixture(t, "upstream/setup-go-v7.1.0.action.yml"))
	fs, text := compareActionMeta("", o, n)
	if len(fs) != 0 {
		t.Fatalf("unexpected findings %+v", fs)
	}
	if !strings.Contains(text, "+ output GOROOT") {
		t.Fatalf("structured diff misses the new output:\n%s", text)
	}
}

func TestCompareActionMeta(t *testing.T) {
	const base = "name: x\nruns:\n  using: node20\n  main: dist/index.js\n"
	const composite = "name: x\nruns:\n  using: composite\n  steps:\n    - uses: a/b@1111111111111111111111111111111111111111\n    - run: echo\n      shell: bash\n"
	tests := []struct {
		name, old, new string
		want           []string
	}{
		{"same", base, base, nil},
		{"using", base, strings.Replace(base, "node20", "node24", 1), []string{"actions.runs-using-changed"}},
		{"new post", base, base + "  post: dist/post.js\n", []string{"actions.entrypoint-added"}},
		{"new pre", base, base + "  pre: dist/index.js\n", []string{"actions.entrypoint-added"}},
		{"main moved", base, strings.Replace(base, "index.js", "main.js", 1), []string{"actions.entrypoint-changed"}},
		{"nested uses", composite, strings.Replace(composite, "1111", "2222", 1), []string{"actions.nested-uses-changed"}},
		{"docker step", composite, strings.Replace(composite, "    - run: echo", "    - uses: docker://alpine:3\n    - run: echo", 1), []string{"actions.docker-image-changed"}},
		{"docker action", "runs:\n  using: docker\n  image: Dockerfile\n", "runs:\n  using: docker\n  image: docker://x@sha256:00\n", []string{"actions.docker-action", "actions.docker-image-changed"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o, err := parseActionMeta(tt.old)
			if err != nil {
				t.Fatal(err)
			}
			n, err := parseActionMeta(tt.new)
			if err != nil {
				t.Fatal(err)
			}
			fs, _ := compareActionMeta("", o, n)
			var got []string
			for _, f := range fs {
				if f.route != model.RouteHuman {
					t.Errorf("%s routes %s", f.code, f.route)
				}
				got = append(got, f.code)
			}
			if strings.Join(got, ",") != strings.Join(tt.want, ",") {
				t.Fatalf("findings %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseYAML(t *testing.T) {
	good := `# c
name: 'It''s'
description: >-
  folded
  text
inputs:
  a:
    description: "q \"x\" \u00e9"
    default: 1 # comment
  b: {required: true}
list:
- one
- two: 2
  three: 3
-
  - nested
runs:
  using: node24
  steps:
    - run: |
        echo # not a comment
        done
      shell: bash
`
	v, err := parseYAML(good)
	if err != nil {
		t.Fatal(err)
	}
	m := v.(*yMap)
	if m.str("name") != "It's" || m.str("description") != "folded text" {
		t.Fatalf("scalars: %q %q", m.str("name"), m.str("description"))
	}
	in := m.sub("inputs")
	if in.sub("a").str("description") != `q "x" é` || in.sub("a").str("default") != "1" || in.get("b") != yFlow("{required: true}") {
		t.Fatalf("inputs: %+v", in.m)
	}
	l := m.get("list").([]any)
	if len(l) != 3 || l[0] != "one" || l[1].(*yMap).str("three") != "3" || l[2].([]any)[0] != "nested" {
		t.Fatalf("list: %#v", l)
	}
	step := m.sub("runs").get("steps").([]any)[0].(*yMap)
	if step.str("run") != "echo # not a comment\ndone\n" || step.str("shell") != "bash" {
		t.Fatalf("block scalar: %q", step.str("run"))
	}
	for name, bad := range map[string]string{
		"anchor":    "a: &x 1\nb: *x\n",
		"duplicate": "a: 1\na: 2\n",
		"tab":       "a:\n\tb: 1\n",
		"indent":    "a: 1\n   b: 2\n",
		"merge":     "a:\n  <<: {}\n",
	} {
		if _, err := parseYAML(bad); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestLockfiles(t *testing.T) {
	o, err := parseLockfile("package-lock.json", []byte(readFixture(t, "upstream/setup-go-old.package-lock.json")))
	if err != nil {
		t.Fatal(err)
	}
	n, err := parseLockfile("package-lock.json", []byte(readFixture(t, "upstream/setup-go-new.package-lock.json")))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]pkgChange{}
	for _, c := range lockChanges(o.names, n.names) {
		got[c.name] = c
	}
	if c := got["@azure/storage-blob"]; !c.downgrade || fmt.Sprint(c.old, c.new) != "[12.32.0] [12.31.0]" {
		t.Errorf("storage-blob: %+v", c)
	}
	if c := got["@actions/cache"]; c.downgrade || c.added {
		t.Errorf("@actions/cache: %+v", c)
	}
	if c := got["minimatch"]; c.downgrade || len(c.old) != 2 || len(c.new) != 1 {
		t.Errorf("minimatch: %+v", c)
	}
	cp := changedPaths(o.paths, n.paths)
	if !cp["node_modules/@actions/cache/node_modules/minimatch"] || cp["node_modules/minimatch"] {
		t.Errorf("changed paths: %v", cp)
	}

	others := []struct {
		name, text string
		want       map[string]string
	}{
		{"yarn.lock", "__metadata:\n  version: 8\n\n\"@actions/core@npm:^1.0.0\":\n  version: 1.11.1\n  resolution: \"@actions/core@npm:1.11.1\"\n\nsemver@npm:^7:\n  resolution: \"semver@npm:7.7.3\"\n",
			map[string]string{"@actions/core": "1.11.1", "semver": "7.7.3"}},
		{"yarn.lock", "# yarn lockfile v1\n\n\"@babel/core@^7.0.0\", \"@babel/core@^7.1.0\":\n  version \"7.24.0\"\n  resolved \"x\"\n\nms@2.1.2:\n  version \"2.1.2\"\n",
			map[string]string{"@babel/core": "7.24.0", "ms": "2.1.2"}},
		{"pnpm-lock.yaml", "lockfileVersion: '9.0'\n\npackages:\n\n  '@actions/core@1.11.1':\n    resolution: {integrity: x}\n\n  ms@2.1.3:\n    resolution: {integrity: y}\n\nsnapshots:\n\n  ms@9.9.9:\n    x: y\n",
			map[string]string{"@actions/core": "1.11.1", "ms": "2.1.3"}},
	}
	for _, tt := range others {
		d, err := parseLockfile(tt.name, []byte(tt.text))
		if err != nil {
			t.Fatal(err)
		}
		for k, v := range tt.want {
			if vs := d.names.versions(k); len(vs) != 1 || vs[0] != v {
				t.Errorf("%s: %s = %v, want %s", tt.name, k, vs, v)
			}
		}
		if len(d.names) != len(tt.want) {
			t.Errorf("%s: parsed %v", tt.name, d.names)
		}
	}
}

// The upload-artifact v7.0.1 -> v7.0.2 bundle (ncc), cut down to four
// modules: a numbered package.json module whose version string moved, two
// changed @actions modules, one unchanged module.
func TestAnalyzeModulesRecorded(t *testing.T) {
	old := readFixture(t, "upstream/upload-artifact-excerpt.old.js")
	new := readFixture(t, "upstream/upload-artifact-excerpt.new.js")
	newLock := lockSet{}
	newLock.add("@actions/artifact", "6.3.1")
	newLock.add("@actions/github", "9.1.1")
	tests := []struct {
		name       string
		attr       attribution
		residual   bool
		residualOf []string
	}{
		{"locks explain everything", attribution{lockChanged: map[string]bool{"@actions/artifact": true, "@actions/github": true}, lockNew: newLock}, false, nil},
		{"no lock change", attribution{lockChanged: map[string]bool{}}, true, []string{"webpack#2822", "./node_modules/@actions/artifact/lib/internal/shared/errors.js", "./node_modules/@actions/github/lib/utils.js"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := analyzeBundle(bundleInput{path: "dist/upload/index.js", old: []byte(old), new: []byte(new)}, tt.attr)
			if r.mode != "modules" {
				t.Fatalf("mode %s", r.mode)
			}
			if (r.residual > 0) != tt.residual {
				t.Fatalf("residual %d: %+v", r.residual, r.residuals)
			}
			var names []string
			for _, it := range r.residuals {
				names = append(names, it.name)
			}
			if strings.Join(names, ",") != strings.Join(tt.residualOf, ",") {
				t.Fatalf("residuals %v, want %v", names, tt.residualOf)
			}
			if r.unchanged == 0 {
				t.Fatal("the unchanged @actions/core module was not recognized")
			}
		})
	}
}

// vlq encodes source-map segment fields.
func vlq(vals ...int) string {
	var sb strings.Builder
	for _, v := range vals {
		u := v << 1
		if v < 0 {
			u = (-v << 1) | 1
		}
		for {
			d := u & 31
			u >>= 5
			if u > 0 {
				d |= 32
			}
			sb.WriteByte(b64[d])
			if u == 0 {
				break
			}
		}
	}
	return sb.String()
}

type chunk struct {
	src  int // -1: unmapped
	text string
}

// minified builds a one-line bundle and its source map from chunks.
func minified(sources []string, contents []*string, chunks []chunk) (string, string) {
	var js strings.Builder
	var segs []string
	col, src := 0, 0
	for _, c := range chunks {
		start := js.Len()
		if c.src < 0 {
			segs = append(segs, vlq(start-col))
		} else {
			segs = append(segs, vlq(start-col, c.src-src, 0, 0))
			src = c.src
		}
		col = start
		js.WriteString(c.text)
	}
	m, _ := json.Marshal(map[string]any{"version": 3, "sources": sources, "sourcesContent": contents, "mappings": strings.Join(segs, ",")})
	return js.String(), string(m)
}

func sp(s string) *string { return &s }

func TestAnalyzeSourceMap(t *testing.T) {
	sources := []string{"../src/main.ts", "../node_modules/left-pad/index.js", "../node_modules/other/index.js"}
	oldJS, oldMap := minified(sources,
		[]*string{sp("run(1)"), sp("pad v1"), sp("other")},
		[]chunk{{-1, "var a=1;"}, {0, "function q(){return 1}"}, {1, "function p(a){return a}"}, {2, "function o(){}"}})
	type tc struct {
		name     string
		contents []*string
		chunks   []chunk
		attr     attribution
		residual []string
		nulls    int
	}
	attr := attribution{lockChanged: map[string]bool{"left-pad": true}, firstParty: []string{"src/main.ts"}}
	tests := []tc{
		{"renamed locals only", []*string{sp("run(1)"), sp("pad v1"), sp("other")},
			[]chunk{{-1, "var b=1;"}, {0, "function r(){return 1}"}, {1, "function z(b){return b}"}, {2, "function x(){}"}},
			attribution{}, nil, 0},
		{"first-party and locked package changed", []*string{sp("run(2)"), sp("pad v2"), sp("other")},
			[]chunk{{-1, "var a=1;"}, {0, "function q(){return 2}"}, {1, "function p(a){return a+1}"}, {2, "function o(){}"}},
			attr, nil, 0},
		{"output changed, source same", []*string{sp("run(1)"), sp("pad v1"), sp("other")},
			[]chunk{{-1, "var a=1;"}, {0, "function q(){return 1}"}, {1, "function p(a){return a}"}, {2, "function o(){fetch('//evil')}"}},
			attr, []string{"../node_modules/other/index.js"}, 0},
		{"package without lock change", []*string{sp("run(1)"), sp("pad v1"), sp("other v2")},
			[]chunk{{-1, "var a=1;"}, {0, "function q(){return 1}"}, {1, "function p(a){return a}"}, {2, "function o(){return 2}"}},
			attr, []string{"../node_modules/other/index.js"}, 0},
		{"new unmapped code", []*string{sp("run(1)"), sp("pad v1"), sp("other")},
			[]chunk{{-1, "var a=1;"}, {0, "function q(){return 1}"}, {-1, "require('child_process').exec('x');"}, {1, "function p(a){return a}"}, {2, "function o(){}"}},
			attr, []string{"(unmapped)"}, 0},
		{"null sourcesContent", []*string{sp("run(1)"), nil, sp("other")},
			[]chunk{{-1, "var a=1;"}, {0, "function q(){return 1}"}, {1, "function p(a){return a+1}"}, {2, "function o(){}"}},
			attr, nil, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newJS, newMap := minified(sources, tt.contents, tt.chunks)
			r := analyzeBundle(bundleInput{path: "dist/index.cjs", old: []byte(oldJS), new: []byte(newJS), oldMap: []byte(oldMap), newMap: []byte(newMap)}, tt.attr)
			if r.mode != "sourcemap" {
				t.Fatalf("mode %s (%s)", r.mode, r.note)
			}
			var names []string
			for _, it := range r.residuals {
				names = append(names, it.name)
			}
			if strings.Join(names, ",") != strings.Join(tt.residual, ",") {
				t.Fatalf("residuals %v, want %v", r.residuals, tt.residual)
			}
			if len(r.nullContent) != tt.nulls {
				t.Fatalf("null content %v", r.nullContent)
			}
		})
	}
}

func TestDecodeVLQ(t *testing.T) {
	for _, vals := range [][]int{{0}, {1, -1, 15, -16}, {1 << 20, -(1 << 20)}} {
		got, err := decodeVLQ(vlq(vals...))
		if err != nil || fmt.Sprint(got) != fmt.Sprint(vals) {
			t.Errorf("round trip %v: %v %v", vals, got, err)
		}
	}
	if _, err := decodeVLQ("g"); err == nil {
		t.Error("truncated VLQ accepted")
	}
}

func TestPureRename(t *testing.T) {
	tests := []struct {
		name, a, b string
		want       bool
	}{
		{"declared locals", "var a = f(1), c = a;", "var x = f(1), z = x;", true},
		{"function and params", "function q(a, b) { return a + b }", "function w(x, y) { return x + y }", true},
		{"arrow params", "const g = (a) => a * 2; h(b => b)", "const k = (x) => x * 2; h(y => y)", true},
		{"bundler aliases", "var core = __webpack_require__(1); _core__WEBPACK_IMPORTED_MODULE_0__.x()", "var core = __nccwpck_require__(1); _core__WEBPACK_IMPORTED_MODULE_3__.x()", true},
		{"inconsistent", "var a = 1; a(a);", "var x = 1; x(z);", false},
		{"literal", "f(1)", "f(2)", false},
		{"hex literal", "f(0x1F)", "f(0x2F)", false},
		{"string", "f('a')", "f('b')", false},
		// Regressions: these were accepted as renames and hidden.
		{"free global swap", "fetch(u)", "eval(u)", false},
		{"free name swap", "var a = 1; log(a)", "var a = 1; exec(a)", false},
		{"bound local to global", "function f(atob) { return atob(x) }", "function f(y) { return eval(x) }", false},
		{"property rename", "var o = {}; o.read(1)", "var o = {}; o.exec(1)", false},
		{"object key rename", "var o = { safe: 1 }", "var o = { evil: 1 }", false},
		{"keyword swap", "var a = true", "var a = false", false},
		{"to a dangerous global name", "var a = 1; a()", "var require = 1; require()", false},
	}
	for _, tt := range tests {
		if got := pureRename(tt.a, tt.b); got != tt.want {
			t.Errorf("%s: pureRename = %v, want %v", tt.name, got, tt.want)
		}
	}
}

// minifiedPair builds old and new minified bundles with one source per
// chunk (same sourcesContent on both sides) and reports which chunks the
// source-map analysis counts as unchanged.
func minifiedPair(chunks [][2]string) []bool {
	var sources []string
	var contents []*string
	var oc, nc []chunk
	for i, c := range chunks {
		sources = append(sources, fmt.Sprintf("../node_modules/p%d/index.js", i))
		contents = append(contents, sp(fmt.Sprintf("source %d", i)))
		oc = append(oc, chunk{i, c[0] + ";"})
		nc = append(nc, chunk{i, c[1] + ";"})
	}
	oldJS, oldMap := minified(sources, contents, oc)
	newJS, newMap := minified(sources, contents, nc)
	r := analyzeBundle(bundleInput{path: "dist/index.cjs", old: []byte(oldJS), new: []byte(newJS), oldMap: []byte(oldMap), newMap: []byte(newMap)}, attribution{})
	out := make([]bool, len(chunks))
	for i := range out {
		out[i] = true
	}
	for _, it := range r.residuals {
		var i int
		if _, err := fmt.Sscanf(it.name, "../node_modules/p%d/index.js", &i); err == nil {
			out[i] = false
		}
	}
	return out
}

func TestMinifiedRenames(t *testing.T) {
	tests := []struct {
		name      string
		chunks    [][2]string
		unchanged []bool
	}{
		{"consistent bundle-wide renames",
			[][2]string{{"function ab(a){return a+1}", "function xy(b){return b+1}"}, {"ab(2);cd(3)", "xy(2);zw(3)"}, {"function cd(){}", "function zw(){}"}},
			[]bool{true, true, true}},
		// Regressions: the old short-identifier normalization accepted these.
		{"swap to a dangerous global", [][2]string{{"function q(a){return atob(a)}", "function q(a){return eval(a)}"}}, []bool{false}},
		{"swap to an unbound name", [][2]string{{"function q(a){return ab(a)}", "function q(a){return zz(a)}"}}, []bool{false}},
		{"selective swap between bundle symbols",
			[][2]string{{"function ab(){}function cd(){}", "function ab(){}function cd(){}"}, {"ab(1)", "cd(1)"}, {"ab(2)", "ab(2)"}},
			[]bool{true, false, true}}, // only the swapped call site is changed
		{"consistent swap of two bundle symbols at every use",
			[][2]string{{"function ab(){}function cd(){}", "function ab(){}function cd(){}"}, {"ab(1);cd(2)", "cd(1);ab(2)"}},
			[]bool{true, false}},
		{"selective swap, declaration in an unaligned chunk",
			[][2]string{{"ab(1)", "cd(1)"}, {"ab(2)", "ab(2)"}, {"ab(3)", "ab(3)"}, {"var ab,cd;", "var ab,cd;"}},
			[]bool{false, true, true, true}},
		{"per-scope local renames",
			[][2]string{{"function ab(t){return t}function cd(t,e){return e}", "function ab(e){return e}function cd(e,t){return t}"}, {"ab(1),cd(2)", "ab(1),cd(2)"}},
			[]bool{true, true}},
		{"private members and class fields", [][2]string{{"var ab=class{#x(){}w;y(){return this.#x()}}", "var ab=class{#q(){}w;y(){return this.#q()}}"}}, []bool{true}},
		{"public method rename", [][2]string{{"var ab,y;ab=class{y(){}}", "var ab,z;ab=class{z(){}}"}}, []bool{false}},
		{"property rename", [][2]string{{"var ab;ab.foo()", "var ab;ab.bar()"}}, []bool{false}},
		{"object key rename", [][2]string{{"var ab,cd;f({ab:1})", "var ab,cd;f({cd:1})"}}, []bool{false}},
		{"string change", [][2]string{{"var ab;ab('x')", "var ab;ab('y')"}}, []bool{false}},
	}
	for _, tt := range tests {
		got := minifiedPair(tt.chunks)
		if fmt.Sprint(got) != fmt.Sprint(tt.unchanged) {
			t.Errorf("%s: unchanged %v, want %v", tt.name, got, tt.unchanged)
		}
	}
}

func TestJSONModuleStrict(t *testing.T) {
	a := attribution{lockChanged: map[string]bool{"left-pad": true}, lockNew: lockSet{"left-pad": {"1.0.1": true}}}
	wrap := func(line string) string {
		return "/***/ ((module) => {\n\n" + line + "\n\n/***/ })\n"
	}
	tests := []struct {
		name, line string
		want       bool
	}{
		{"package.json", `module.exports = /*#__PURE__*/JSON.parse('{"name":"left-pad","version":"1.0.1","description":"it\'s"}');`, true},
		{"without pure", `module.exports = JSON.parse('{"name":"left-pad","version":"1.0.1"}');`, true},
		{"version not locked", `module.exports = JSON.parse('{"name":"left-pad","version":"9.9.9"}');`, false},
		{"other package", `module.exports = JSON.parse('{"name":"evil","version":"1.0.1"}');`, false},
		// Regressions: these matched the old prefix regex and "');" suffix.
		{"code after the literal", `module.exports = JSON.parse('{"name":"left-pad","version":"1.0.1"}' + require('child_process').execSync('id') + '');`, false},
		{"second statement", `module.exports = JSON.parse('{"name":"left-pad","version":"1.0.1"}'); require('x')('');`, false},
		{"trailing json", `module.exports = JSON.parse('{"name":"left-pad","version":"1.0.1"} {}');`, false},
		{"not an object", `module.exports = JSON.parse('["left-pad"]');`, false},
	}
	for _, tt := range tests {
		if got := a.jsonModulePackage(wrap(tt.line)); got != tt.want {
			t.Errorf("%s: %v, want %v", tt.name, got, tt.want)
		}
	}
	// A hostile numbered module is residual even though its package's
	// lock changed.
	old := "/***/ 1:\n" + wrap(`module.exports = JSON.parse('{"name":"left-pad","version":"1.0.0"}');`) + ";// CONCATENATED MODULE: ./src/a.ts\nx()\n;// CONCATENATED MODULE: ./src/b.ts\ny()\n"
	new := strings.Replace(old, `"version":"1.0.0"}');`, `"version":"1.0.1"}' + require('child_process').execSync('id') + '');`, 1)
	r := analyzeBundle(bundleInput{path: "dist/index.js", old: []byte(old), new: []byte(new)}, a)
	if r.residual == 0 || r.residuals[0].name != "webpack#1" {
		t.Fatalf("hostile JSON module not residual: %+v", r.residuals)
	}
}

func TestHostileRenameModule(t *testing.T) {
	old := ";// CONCATENATED MODULE: ./node_modules/other/index.js\nfunction other(u) {\n  return fetch(u);\n}\n;// CONCATENATED MODULE: ./src/main.ts\nother(1)\n"
	new := strings.Replace(old, "return fetch(u);", "return eval(u);", 1)
	r := analyzeBundle(bundleInput{path: "dist/index.js", old: []byte(old), new: []byte(new)}, attribution{})
	if r.residual == 0 {
		t.Fatalf("global swap counted as a rename: %+v", r)
	}
	if !strings.Contains(renderBundle(r), "+  return eval(u);") {
		t.Fatal("the swap is not in the reviewer's diff")
	}
}

func TestCompiledFrom(t *testing.T) {
	a := attribution{firstParty: []string{"src/main.ts", "docs/evil.md", "src/util/x.js", "scripts/evil.ts"}}
	tests := []struct {
		mod  string
		want bool
	}{
		{"./src/main.ts", true},
		{"./lib/main.js", true},
		{"./dist/main.cjs", true},
		{"./lib/util/x.mjs", true},
		// Regressions: the old stem match accepted these.
		{"./lib/evil.js", false},   // docs/evil.md is not source code
		{"./out/main.js", false},   // unknown output directory
		{"./lib/main.json", false}, // not a compiled extension
		{"./lib/x.js", false},      // src/util/x.js: directories must match
		{"./src/other/main.ts", false},
		{"./lib/evil.js", false}, // scripts/evil.ts is not under src/
	}
	for _, tt := range tests {
		if got := a.firstPartyChanged("dist", tt.mod); got != tt.want {
			t.Errorf("firstPartyChanged(%q) = %v, want %v", tt.mod, got, tt.want)
		}
	}
}

func TestActionMetaFailsClosed(t *testing.T) {
	bad := map[string]string{
		"flow steps":         "runs:\n  using: composite\n  steps: [{uses: evil/x@1111111111111111111111111111111111111111}]\n",
		"flow step item":     "runs:\n  using: composite\n  steps:\n    - {uses: evil/x@1111111111111111111111111111111111111111}\n",
		"flow in step value": "runs:\n  using: composite\n  steps:\n    - run: echo\n      with: {a: b}\n",
		"flow runs":          "runs: {using: node24, main: x.js}\n",
		"anchor":             "runs:\n  using: composite\n  steps: &s\n    - run: echo\n",
		"alias":              "x: &a\n  - uses: evil/x@1\nruns:\n  using: composite\n  steps: *a\n",
		"merge":              "runs:\n  <<: {using: node24}\n",
		"second document":    "runs:\n  using: node24\n  main: a.js\n---\nruns:\n  using: composite\n",
		"document end":       "runs:\n  using: node24\n  main: a.js\n...\nruns: x\n",
	}
	for name, y := range bad {
		if _, err := parseActionMeta(y); err == nil {
			t.Errorf("%s: parsed without error", name)
		}
	}
	if _, err := parseActionMeta("name: x\nbranding: {icon: a}\nruns:\n  using: node24\n  main: a.js\n"); err != nil {
		t.Errorf("flow outside runs rejected: %v", err)
	}
}

func TestBuildConfig(t *testing.T) {
	for p, want := range map[string]bool{
		"tsconfig.json": true, "tsconfig.build.json": true, "rollup.config.mjs": true,
		"esbuild.config.js": true, ".yarn/plugins/x.cjs": true, "patches/foo.patch": true,
		"src/main.ts": false, "README.md": false, "package.json": false,
	} {
		if isBuildConfig(p) != want {
			t.Errorf("isBuildConfig(%q) != %v", p, want)
		}
	}
	c, err := comparePackageJSON([]byte(`{"scripts":{"build":"ncc build"},"devDependencies":{"@vercel/ncc":"0.38"}}`),
		[]byte(`{"scripts":{"build":"ncc build && curl x"},"devDependencies":{"esbuild":"0.28","@vercel/ncc":"0.44"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(c.scripts, c.bundlersChanged, c.bundlerVersions) != "[build] [esbuild] [@vercel/ncc]" {
		t.Fatalf("%+v", c)
	}
}

func TestMapReference(t *testing.T) {
	if _, ref := mapReference("dist/index.js", []byte("x\n//# sourceMappingURL=index.js.map\n")); ref != "dist/index.js.map" {
		t.Errorf("ref %q", ref)
	}
	if _, ref := mapReference("dist/index.js", []byte("x\n//# sourceMappingURL=../../etc/passwd\n")); ref != "" {
		t.Errorf("escaping ref accepted: %q", ref)
	}
	inline, _ := mapReference("dist/index.js", []byte("x\n//# sourceMappingURL=data:application/json;base64,e30=\n"))
	if string(inline) != "{}" {
		t.Errorf("inline %q", inline)
	}
}

// A 404 means "absent"; any other API error (including one whose path
// happens to contain "404") must fail the fetch, not read as absent.
func TestNotFoundOnlyFor404(t *testing.T) {
	const p = "repos/a/b/releases/tags/v1.0.0"
	for status, wantErr := range map[int]bool{404: false, 403: true, 502: true} {
		u := &upstream{gh: &fakeGH{resp: map[string]any{p: &gh.Error{Method: "GET", Path: "repos/a/b/compare/a404b...c", StatusCode: status}}}, owner: "a", repo: "b"}
		rel, err := u.releaseFor(context.Background(), "v1.0.0")
		if (err != nil) != wantErr || rel != nil {
			t.Errorf("status %d: release %v, err %v; want err=%v", status, rel, err, wantErr)
		}
	}
}

// Regression: with the old normalization (identifiers of up to four
// characters replaced), atob -> eval in a same-source chunk compared equal.
func TestSourceMapGlobalSwap(t *testing.T) {
	sources := []string{"../node_modules/other/index.js"}
	contents := []*string{sp("module.exports = (x) => atob(x)")}
	oldJS, oldMap := minified(sources, contents, []chunk{{0, "var o=function(x){return atob(x)};"}})
	newJS, newMap := minified(sources, contents, []chunk{{0, "var o=function(x){return eval(x)};"}})
	r := analyzeBundle(bundleInput{path: "dist/index.cjs", old: []byte(oldJS), new: []byte(newJS), oldMap: []byte(oldMap), newMap: []byte(newMap)}, attribution{})
	if r.mode != "sourcemap" || len(r.residuals) != 1 || r.residuals[0].reason != resGenSrcSame {
		t.Fatalf("mode %s residuals %+v", r.mode, r.residuals)
	}
}

func TestPlainPath(t *testing.T) {
	for p, want := range map[string]bool{"src/main.ts": true, "a.b/c..d": true, "src/./evil.js": false, "a/../b": false, "a//b": false, "/a": false, "a/": false, ".": false} {
		if plainPath(p) != want {
			t.Errorf("plainPath(%q) = %v", p, !want)
		}
	}
}
