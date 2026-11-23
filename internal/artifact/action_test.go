package artifact

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/sadbox/dep-review/internal/allow"
)

// actionPair is an update of the action someorg/scan-action from v2.3.0
// to v2.3.1, used from dirs, with the given files at each commit.
func actionPair(t *testing.T, oldFiles, newFiles map[string]string, dirs ...string) (Pair, fakeFetcher) {
	t.Helper()
	oldCommit, newCommit := strings.Repeat("a", 40), strings.Repeat("b", 40)
	p := Pair{Ecosystem: allow.GitHubActions, Name: "someorg/scan-action", From: "v2.3.0", To: "v2.3.1", Dirs: dirs,
		Old: Ref{Kind: ActionTarball, Name: "someorg/scan-action", Version: "v2.3.0", Hash: oldCommit},
		New: Ref{Kind: ActionTarball, Name: "someorg/scan-action", Version: "v2.3.1", Hash: newCommit}}
	return p, fakeFetcher{p.Old: actionTarball(t, oldCommit, oldFiles), p.New: actionTarball(t, newCommit, newFiles)}
}

const (
	nodeAction      = "name: scan\ndescription: scan\nruns:\n  using: 'node24'\n  main: 'dist/index.js'\n"
	compositeAction = "name: scan\nruns:\n  using: \"composite\"\n  steps:\n    - run: echo hi\n      shell: bash\n"
	imageAction     = "name: scan\ndescription: scan\nruns:\n  using: 'docker'\n  image: 'docker://ghcr.io/someorg/scan-action:%s'\n"
	dockerfile      = "name: scan\nruns:\n  using: docker\n  image: Dockerfile\n  args:\n    - scan\n"
)

// A container action runs an image: by reference, or built from a
// Dockerfile whose base image and downloads are an image's too. Nothing
// of an image is read, so the read of such an action is not a read of
// what runs, and the gate refuses it (spec section 11, amendment 55).
func TestContainerActionIsNotRead(t *testing.T) {
	code := map[string]string{"dist/index.js": "run()\n"}
	with := func(extra map[string]string) map[string]string {
		out := map[string]string{}
		for k, v := range code {
			out[k] = v
		}
		for k, v := range extra {
			out[k] = v
		}
		return out
	}
	tests := []struct {
		name     string
		old, new map[string]string
		dirs     []string
		refused  string // part of the error; "" for a read
	}{
		{"a node action", with(map[string]string{"action.yml": nodeAction}), with(map[string]string{"action.yml": nodeAction, "dist/index.js": "run(2)\n"}), []string{"."}, ""},
		{"a composite action in action.yaml", with(map[string]string{"action.yaml": compositeAction}), with(map[string]string{"action.yaml": compositeAction, "x.sh": "echo\n"}), []string{"."}, ""},
		{"a bare value, and a comment after it", nil, with(map[string]string{"action.yml": "runs:\n  using: node20 # LTS\n  main: dist/index.js\n"}), []string{"."}, ""},
		{"line ends of another system", nil, with(map[string]string{"action.yml": strings.ReplaceAll(nodeAction, "\n", "\r\n")}), []string{"."}, ""},

		// The verifier's case: the release moves only the image's tag.
		{"an image by reference", with(map[string]string{"action.yml": fmt.Sprintf(imageAction, "2.3.0")}), with(map[string]string{"action.yml": fmt.Sprintf(imageAction, "2.3.1")}), []string{"."}, "docker://"},
		{"an image by a reference of another form", nil, with(map[string]string{"action.yml": "runs:\n  using: docker\n  image: ghcr.io/someorg/scan-action:2.3.1\n"}), []string{"."}, "that is not `using: nodeNN`"},
		{"an image built from a Dockerfile", with(map[string]string{"action.yml": dockerfile, "Dockerfile": "FROM alpine:3.20\n"}), with(map[string]string{"action.yml": dockerfile, "Dockerfile": "FROM alpine:3.21\n"}), []string{"."}, "that is not `using: nodeNN`"},
		{"a node action that became a container action", with(map[string]string{"action.yml": nodeAction}), with(map[string]string{"action.yml": dockerfile, "Dockerfile": "FROM alpine\n"}), []string{"."}, "that is not `using: nodeNN`"},
		{"a composite action with an image for a step", nil, with(map[string]string{"action.yml": compositeAction + "    - uses: docker://alpine:3.21\n"}), []string{"."}, "docker://"},
		{"a node action whose text names an image", nil, with(map[string]string{"action.yml": nodeAction + "# see docker://ghcr.io/x/y\n"}), []string{"."}, "docker://"},

		// What is not the one shape the gate knows is not guessed at.
		{"no metadata file where the workflow uses the action", nil, with(map[string]string{"Dockerfile": "FROM alpine\n"}), []string{"."}, "no action.yml"},
		{"a flow mapping", nil, with(map[string]string{"action.yml": "name: x\nruns: {using: docker, image: Dockerfile}\n"}), []string{"."}, "is not `runs:` alone"},
		{"no line that says what runs", nil, with(map[string]string{"action.yml": "name: x\ndescription: y\n"}), []string{"."}, "has 0 top-level `runs` keys"},
		{"two lines that both say node", nil, with(map[string]string{"action.yml": nodeAction + "  using: node20\n"}), []string{"."}, "has 2 `using` keys"},
		{"a quoted key", nil, with(map[string]string{"action.yml": "name: x\nruns:\n  \"using\": docker\n  image: Dockerfile\n"}), []string{"."}, "is in the `runs` block"},
		{"two lines that say what runs", nil, with(map[string]string{"action.yml": nodeAction + "  using: docker\n"}), []string{"."}, "that is not `using: nodeNN`"},
		{"an unknown runner", nil, with(map[string]string{"action.yml": "runs:\n  using: wasm\n"}), []string{"."}, "that is not `using: nodeNN`"},
		{"a value that only starts like node", nil, with(map[string]string{"action.yml": "runs:\n  using: node20docker\n"}), []string{"."}, "that is not `using: nodeNN`"},
		{"metadata that is not text", nil, with(map[string]string{"action.yml": "runs:\n  using: node24\n\x00"}), []string{"."}, "not text"},
		{"both metadata files, one of them a container's", nil, with(map[string]string{"action.yml": nodeAction, "action.yaml": dockerfile}), []string{"."}, "that is not `using: nodeNN`"},

		// Which directory the workflows use decides. A container action
		// elsewhere in the repository (one its own tests use) is not what
		// runs.
		{"a container action in a directory nobody uses", with(map[string]string{"action.yml": nodeAction}),
			with(map[string]string{"action.yml": nodeAction, "dist/index.js": "run(2)\n", ".github/actions/pull/action.yml": dockerfile, ".github/actions/pull/Dockerfile": "FROM alpine\n"}), []string{"."}, ""},
		{"used from a directory", nil, with(map[string]string{"action.yml": dockerfile, "upload/action.yml": nodeAction}), []string{"upload"}, ""},
		{"used from the root and from a directory, and the directory's is a container", nil,
			with(map[string]string{"action.yml": nodeAction, "scan/action.yml": dockerfile}), []string{".", "scan"}, "that is not `using: nodeNN`"},
		{"used from a directory without metadata", nil, with(map[string]string{"action.yml": nodeAction, "scan/Dockerfile": "FROM alpine\n"}), []string{"scan"}, "no action.yml"},
		// actions.lock does not say from where an action that another
		// action uses is used: every action of the repository counts.
		{"directory not known, one action", nil, with(map[string]string{"action.yml": nodeAction}), nil, ""},
		{"directory not known, and a container action somewhere", nil,
			with(map[string]string{"action.yml": nodeAction, ".github/actions/pull/action.yml": dockerfile}), nil, "that is not `using: nodeNN`"},
		{"directory not known, and no action anywhere", nil, code, nil, "no action.yml"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			old := tt.old
			if old == nil {
				old = with(map[string]string{"action.yml": nodeAction, "README.md": "old\n"})
			}
			p, f := actionPair(t, old, tt.new, tt.dirs...)
			got, err := newReader(t, f).Prepare(context.Background(), p, roomy)
			if tt.refused == "" {
				if err != nil || len(got.Chunks) == 0 {
					t.Fatalf("Prepare: %d chunks, %v; want a read", len(got.Chunks), err)
				}
				return
			}
			if !errors.Is(err, ErrActionKind) || !strings.Contains(err.Error(), tt.refused) {
				t.Fatalf("Prepare: state %q, %v; want ErrActionKind saying %q", got.State, err, tt.refused)
			}
		})
	}
}

// A metadata file counts only in the plain block form (spec section 11,
// amendment 68). YAML has other ways of saying `runs` and `using`, and a
// line reader that took a few of them could be shown one runtime while
// the runner reads another. Each case below is such a way, or a decoy
// that only a line reader would believe.
func TestMetadataForms(t *testing.T) {
	tests := []struct {
		name    string
		content string
		refused string // part of the problem; "" for a file that counts
	}{
		// What the publishers write.
		{"a node action", nodeAction, ""},
		{"a composite action with steps at the key's indent", "name: x\nruns:\n  using: composite\n  steps:\n  - run: echo hi\n    shell: bash\n  - uses: actions/checkout@v4\n", ""},
		{"a leading document marker", "---\nname: x\nruns:\n  using: node24\n  main: dist/index.js\n", ""},
		{"a leading document marker with blanks after it", "--- \t\nname: x\nruns:\n  using: node24\n", ""},
		{"comments and blank lines everywhere", "# top\n\nname: x # n\n  # stray\nruns: # what runs\n  # first\n\n  using: 'node20' # LTS\n    # deeper\n  main: dist/index.js\npost: x\n", ""},
		{"a block scalar elsewhere", "name: x\ndescription: |\n  using: docker\n  runs:\nruns:\n  using: node20\n  main: x\n", ""},
		{"line ends of another system", strings.ReplaceAll(nodeAction, "\n", "\r\n"), ""},
		{"keys of every plain shape", "name: x\nbranding_x-1:\n  icon: y\nruns:\n  using: node20\n  pre-if: always()\n", ""},

		// The line breaks YAML knows and a split on LF does not.
		{"a byte order mark", "\xef\xbb\xbf" + nodeAction, "byte order mark"},
		{"a bare CR before a using line", "runs:\n  using: node20\r  using: docker\n", "bare CR"},
		{"a CR CR LF", "runs:\n  using: node20\r\r\n", "bare CR"},
		{"U+2028 before a using line", "runs:\n  main: x\u2028  using: docker\n  using: node20\n", "U+2028"},
		{"U+2029", "runs:\n  using: node20\u2029\n", "U+2029"},
		{"U+0085", "runs:\n  using: node20\u0085\n", "U+0085"},
		{"a tab in the indentation", "runs:\n\tusing: docker\n  using: node20\n", "line 2 has a tab"},
		{"a tab before a comment", "runs:\n  using: node20\n\t# x\n", "line 3 has a tab"},
		{"a tab on a blank line", "runs:\n  using: node20\n \t\n", "line 3 has a tab"},

		// The top level.
		{"a decoy in a block scalar, beside runs in flow style", "name: x\ndescription: |\n  runs:\n  using: node20\nruns: {using: docker, image: Dockerfile}\n", "line 5 is not `runs:` alone"},
		{"a whole-file flow mapping", "{name: x,\nruns: {using: docker, image: Dockerfile}}\n", "line 1 starts in column 0"},
		{"a quoted key", "name: x\nruns:\n  using: node20\n\"runs\":\n  using: docker\n", "line 4 starts in column 0"},
		{"a single-quoted key", "'runs':\n  using: docker\n", "line 1 starts in column 0"},
		{"an explicit key", "name: x\nruns:\n  using: node20\n? runs\n: using: docker\n", "line 4 starts in column 0"},
		{"a merge key at the top", "name: x\nruns:\n  using: node20\n<<: {runs: {using: docker}}\n", "line 4 starts in column 0"},
		{"an anchor for the runs block", "runs: &r\n  using: node20\n", "line 1 is not `runs:` alone"},
		{"an alias for the runs block", "x: &r\n  using: docker\nruns: *r\n", "line 3 is not `runs:` alone"},
		{"a tag", "!!map\nruns:\n  using: node20\n", "line 1 starts in column 0"},
		{"a directive", "%YAML 1.2\n---\nruns:\n  using: node20\n", "line 1 starts in column 0"},
		{"a second document", "runs:\n  using: node20\n---\nruns:\n  using: docker\n", "line 3 is a document marker"},
		{"an end of document", "runs:\n  using: node20\n...\n", "line 3 is a document marker"},
		{"a document marker with content", "--- !!map\nruns:\n  using: node20\n", "line 1 is a document marker"},
		{"a document marker after a key", "name: x\n---\n", "line 2 is a document marker"},
		{"two runs keys", "runs:\n  using: node20\nruns:\n  using: docker\n", "has 2 top-level `runs` keys"},
		{"a runs key in capitals", "name: x\nRuns:\n  using: docker\nruns:\n  using: node20\n", "has 2 top-level `runs` keys"},
		{"only a runs key in capitals", "Runs:\n  using: node20\n", "line 1 is not `runs:` alone"},
		{"no runs key", "name: x\ndescription: y\n", "has 0 top-level `runs` keys"},
		{"an indented first line", "  name: x\nruns:\n  using: node20\n", "line 1 is indented"},
		// After the one `---` the root mapping must still start in column
		// 0. Without that rule a mapping indented under `---` would hold a
		// multi-line quoted scalar whose column-0 lines are a decoy.
		{"an indented root mapping under the document marker", "---\n  description: \"a\nruns:\n  using: node20\n  b: c\"\n  runs:\n    using: docker\n", "line 2 is indented"},

		// The runs block.
		{"a runs block in flow style", "runs:\n  {using: docker, image: Dockerfile}\n", "line 2 is in the `runs` block"},
		{"a quoted using key", "name: x\nruns:\n  main: x\n  \"using\": docker\n  using: node20\n", "line 4 is in the `runs` block"},
		{"an explicit using key", "runs:\n  ? using\n  : docker\n  using: node20\n", "line 2 is in the `runs` block"},
		{"a merge key in the runs block", "base: &b\n  using: docker\nruns:\n  <<: *b\n  main: x\n", "line 4 is in the `runs` block"},
		{"a line less indented than the block's first", "runs:\n    using: node20\n  using: docker\n", "line 3 is indented less"},
		{"two using lines", "runs:\n  using: node20\n  using: node24\n", "has 2 `using` keys"},
		{"a using key in capitals", "runs:\n  USING: docker\n  using: node20\n", "that is not `using: nodeNN`"},
		{"a using key only deeper", "runs:\n  main: x\n  steps:\n    using: node20\n", "has 0 `using` keys"},
		{"a runs block with nothing in it", "runs:\nname: x\n", "has 0 `using` keys"},
		{"a using value of another runtime", "runs:\n  using: docker\n  image: Dockerfile\n", "that is not `using: nodeNN`"},
		{"an alias for the using value", "x: &u node20\nruns:\n  using: *u\n", "that is not `using: nodeNN`"},
		{"an image by reference", fmt.Sprintf(imageAction, "1"), "docker://"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := metadataProblem([]byte(tt.content))
			if tt.refused == "" {
				if got != "" {
					t.Fatalf("metadataProblem = %q, want none", got)
				}
				return
			}
			if !strings.Contains(got, tt.refused) {
				t.Fatalf("metadataProblem = %q, want one saying %q", got, tt.refused)
			}
		})
	}
}

// Where the directory is not known, only directories with a metadata
// file are held to the rule. A directory with a Dockerfile and nothing
// else is not looked for: the runner builds it only for an action that
// names that directory, and is an accepted limit (spec section 11,
// amendments 55 and 68).
func TestDockerfileOnlyDirectoryIsNotSought(t *testing.T) {
	files := map[string]string{"action.yml": nodeAction, "dist/index.js": "run(2)\n", "scan/Dockerfile": "FROM alpine\n"}
	p, f := actionPair(t, map[string]string{"action.yml": nodeAction, "dist/index.js": "run()\n"}, files)
	got, err := newReader(t, f).Prepare(context.Background(), p, roomy)
	if err != nil || len(got.Chunks) == 0 {
		t.Fatalf("Prepare: %d chunks, %v; want a read", len(got.Chunks), err)
	}
}

// The directories are the gatherer's, from workflow lines: a path in the
// repository, and only for an action. They are not part of the read's
// key, which is about what is read.
func TestActionDirs(t *testing.T) {
	files := map[string]string{"action.yml": nodeAction, "sub/action.yml": nodeAction, "dist/index.js": "run()\n"}
	changed := map[string]string{"action.yml": nodeAction, "sub/action.yml": nodeAction, "dist/index.js": "run(2)\n"}
	for _, bad := range []string{"", "/sub", "sub/", "../x", "sub/../..", "a b"} {
		p, f := actionPair(t, files, changed, bad)
		if _, err := newReader(t, f).Prepare(context.Background(), p, roomy); !errors.Is(err, ErrBadRef) {
			t.Errorf("directory %q: %v, want ErrBadRef", bad, err)
		}
	}
	p, f := npmPair(t, map[string]string{"index.js": "a\n"}, map[string]string{"index.js": "b\n"})
	p.Dirs = []string{"."}
	if _, err := newReader(t, f).Prepare(context.Background(), p, roomy); !errors.Is(err, ErrBadRef) {
		t.Errorf("an npm package with directories: %v, want ErrBadRef", err)
	}

	root, f1 := actionPair(t, files, changed, ".")
	both, f2 := actionPair(t, files, changed, ".", "sub")
	a, err := newReader(t, f1).Prepare(context.Background(), root, roomy)
	if err != nil {
		t.Fatal(err)
	}
	b, err := newReader(t, f2).Prepare(context.Background(), both, roomy)
	if err != nil {
		t.Fatal(err)
	}
	if a.Key != b.Key {
		t.Errorf("the key depends on the directories: %s and %s", a.Key, b.Key)
	}
}
