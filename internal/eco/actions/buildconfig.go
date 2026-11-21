package actions

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/sadbox/dep-review/internal/strictjson"
)

// buildConfigRx matches files that configure how dist/ is produced:
// compiler and bundler configs, package-manager configs and plugins, and
// patch directories that rewrite dependencies before bundling.
var buildConfigRx = regexp.MustCompile(`(^|/)(` +
	`tsconfig[^/]*\.json|jsconfig[^/]*\.json|` +
	`(rollup|esbuild|webpack|vite|tsup|tsdown|rspack|rolldown|babel|swc|ncc|build)\.config\.[cm]?[jt]s|` +
	`(build|esbuild|bundle)\.[cm]?[jt]s|` +
	`\.babelrc(\.json)?|\.swcrc|\.parcelrc|\.ncc[^/]*|` +
	`\.npmrc|\.yarnrc(\.yml)?|\.pnpmfile\.cjs|pnpm-workspace\.yaml` +
	`)$|(^|/)\.yarn/(releases|plugins|patches)/|(^|/)patches/`)

func isBuildConfig(p string) bool { return buildConfigRx.MatchString(p) }

// bundlerPackages are the build tools whose presence or version shapes the
// bundle bytes.
var bundlerPackages = []string{
	"@vercel/ncc", "esbuild", "rollup", "webpack", "tsup", "tsdown", "parcel",
	"rolldown", "vite", "@rspack/core", "typescript", "@swc/core", "@babel/core",
}

type packageJSON struct {
	Scripts         map[string]string `json:"scripts"`
	PackageManager  string            `json:"packageManager"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
	Engines         map[string]string `json:"engines"`
}

// packageJSONChange compares two package.json files. scripts is set when
// the scripts map differs; bundlersChanged lists bundler packages added or
// removed; bundlerVersions lists bundler version-range changes.
type packageJSONChange struct {
	scripts         []string
	bundlersChanged []string
	bundlerVersions []string
	packageManager  string
	engines         string
}

// comparePackageJSON decodes with strictjson: encoding/json would bind
// "Scripts" to the scripts field and let the last of "scripts"/"Scripts"
// win, hiding a build-script change from the gate that npm (exact-case)
// would run. A strictjson.ErrRejected error means the file is ambiguous.
func comparePackageJSON(oldData, newData []byte) (*packageJSONChange, error) {
	var o, n packageJSON
	if len(oldData) > 0 {
		if err := strictjson.Unmarshal(oldData, &o); err != nil {
			return nil, fmt.Errorf("old package.json: %w", err)
		}
	}
	if err := strictjson.Unmarshal(newData, &n); err != nil {
		return nil, fmt.Errorf("new package.json: %w", err)
	}
	c := &packageJSONChange{}
	for _, k := range unionKeys(o.Scripts, n.Scripts) {
		if o.Scripts[k] != n.Scripts[k] {
			c.scripts = append(c.scripts, k)
		}
	}
	dep := func(p packageJSON, name string) (string, bool) {
		if v, ok := p.DevDependencies[name]; ok {
			return v, true
		}
		v, ok := p.Dependencies[name]
		return v, ok
	}
	for _, b := range bundlerPackages {
		ov, oh := dep(o, b)
		nv, nh := dep(n, b)
		switch {
		case oh != nh:
			c.bundlersChanged = append(c.bundlersChanged, b)
		case ov != nv:
			c.bundlerVersions = append(c.bundlerVersions, b)
		}
	}
	if o.PackageManager != n.PackageManager {
		c.packageManager = fmt.Sprintf("%q -> %q", o.PackageManager, n.PackageManager)
	}
	for _, k := range unionKeys(o.Engines, n.Engines) {
		if o.Engines[k] != n.Engines[k] {
			c.engines += fmt.Sprintf("%s: %q -> %q; ", k, o.Engines[k], n.Engines[k])
		}
	}
	return c, nil
}

func unionKeys(a, b map[string]string) []string {
	m := map[string]bool{}
	for k := range a {
		m[k] = true
	}
	for k := range b {
		m[k] = true
	}
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func isBundlerPackage(name string) bool {
	for _, b := range bundlerPackages {
		if b == name || strings.HasPrefix(name, "@esbuild/") || strings.HasPrefix(name, "@rollup/rollup-") {
			return true
		}
	}
	return false
}
