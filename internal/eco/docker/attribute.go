package docker

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// fileChange is one path that differs between the old and new rootfs.
type fileChange struct {
	Path     string
	Kind     byte // 'A' added, 'D' removed, 'M' modified
	Old, New *entry
	// Attribution: Class is "package", "package-db", "upstream",
	// "normalized" or "" (unexplained); Why says which and how.
	Class string
	Why   string
}

func (c fileChange) explained() bool { return c.Class != "" }

func effType(e *entry) byte {
	if e.Type == 'h' && e.SHA256 != "" {
		return 'f'
	}
	return e.Type
}

func sameEntry(a, b *entry) bool {
	if a == b {
		return true
	}
	if effType(a) != effType(b) || a.Mode != b.Mode || a.UID != b.UID || a.GID != b.GID || a.Xattr != b.Xattr {
		return false
	}
	switch effType(a) {
	case 'f':
		return a.Size == b.Size && a.SHA256 == b.SHA256
	case 'l':
		return a.Link == b.Link
	case 'h':
		return a.Link == b.Link
	case 'c', 'b':
		return a.Dev == b.Dev
	}
	return true
}

func diffRootfs(a, b *rootfs) []fileChange {
	var out []fileChange
	for _, p := range sortedKeys(b.Files) {
		ne := b.Files[p]
		oe, ok := a.Files[p]
		switch {
		case !ok:
			out = append(out, fileChange{Path: p, Kind: 'A', New: ne})
		case !sameEntry(oe, ne):
			out = append(out, fileChange{Path: p, Kind: 'M', Old: oe, New: ne})
		}
	}
	for _, p := range sortedKeys(a.Files) {
		if _, ok := b.Files[p]; !ok {
			out = append(out, fileChange{Path: p, Kind: 'D', Old: a.Files[p]})
		}
	}
	slices.SortFunc(out, func(x, y fileChange) int { return strings.Compare(x.Path, y.Path) })
	return out
}

func (c fileChange) describe() string {
	switch c.Kind {
	case 'A':
		return fmt.Sprintf("+ /%s (%s)", c.Path, entryDesc(c.New))
	case 'D':
		return fmt.Sprintf("- /%s (%s)", c.Path, entryDesc(c.Old))
	}
	return fmt.Sprintf("~ /%s (%s -> %s)", c.Path, entryDesc(c.Old), entryDesc(c.New))
}

func entryDesc(e *entry) string {
	s := fmt.Sprintf("%s %04o %d:%d", e.typeName(), e.Mode, e.UID, e.GID)
	switch effType(e) {
	case 'f':
		s += fmt.Sprintf(" %dB sha256:%.12s", e.Size, e.SHA256)
	case 'l', 'h':
		s += " -> " + e.Link
	case 'c', 'b':
		s += fmt.Sprintf(" %d,%d", e.Dev[0], e.Dev[1])
	}
	return s
}

// payloadRule ties files of a Docker Official Image that come from an
// upstream release artifact (not a distro package) to the *_VERSION
// constant the image's Dockerfile downloads it by. A rule applies only
// when that constant changed.
//
// TODO(v2): verify the payload instead of trusting the path: Go = go.dev
// tarball whose sha256 is in docker-library/golang's Dockerfile at the
// image's org.opencontainers.image.revision; Node = nodejs.org tarball
// checked against the signed SHASUMS256.txt; Caddy = the GitHub release
// asset and its checksums file.
type payloadRule struct {
	Env      string
	Prefixes []string // a trailing "-" matches a name prefix ("opt/yarn-")
	Upstream string
}

var payloadRules = map[string][]payloadRule{
	"golang": {{Env: "GOLANG_VERSION", Prefixes: []string{"usr/local/go"}, Upstream: "go.dev/dl toolchain tarball"}},
	"node": {
		{Env: "NODE_VERSION", Upstream: "nodejs.org release", Prefixes: []string{
			"usr/local/bin/node", "usr/local/bin/npm", "usr/local/bin/npx", "usr/local/bin/corepack",
			"usr/local/include/node", "usr/local/lib/node_modules", "usr/local/share/doc/node",
			"usr/local/share/man/man1/node.1", "usr/local/share/systemtap/tapset/node.stp",
			"usr/local/CHANGELOG.md", "usr/local/LICENSE", "usr/local/README.md",
		}},
		{Env: "YARN_VERSION", Upstream: "yarnpkg release", Prefixes: []string{"opt/yarn-", "usr/local/bin/yarn", "usr/local/bin/yarnpkg"}},
	},
	"caddy": {{Env: "CADDY_VERSION", Prefixes: []string{"usr/bin/caddy"}, Upstream: "caddyserver/caddy GitHub release"}},
}

func hasPathPrefix(p, pre string) bool {
	if strings.HasSuffix(pre, "-") {
		return strings.HasPrefix(p, pre)
	}
	return p == pre || strings.HasPrefix(p, pre+"/")
}

var (
	pkgLogRe = regexp.MustCompile(`^var/log/(?:apk\.log|dpkg\.log|alternatives\.log|bootstrap\.log|apt/(?:history|term)\.log|apt/eipp\.log\.xz)$`)
	// Package-manager state that changes whenever any package does.
	pkgStateRe = regexp.MustCompile(`^(?:` +
		`var/lib/dpkg/(?:status|status-old|available|available-old|diversions|diversions-old|statoverride|statoverride-old|lock|lock-frontend|triggers/[^/]+)|` +
		`(?:usr/)?lib/apk/db/[^/]+|` +
		`var/cache/debconf/[^/]+|var/lib/apt/extended_states|var/cache/apt/[^/]+|` +
		`etc/ld\.so\.cache|var/cache/ldconfig/aux-cache` +
		`)$`)
	dpkgInfoRe = regexp.MustCompile(`^var/lib/dpkg/(?:info/([^/:]+)(?::[^/.]+)?\.[a-z0-9_]+|status\.d/([^/]+?)(?:\.md5sums)?)$`)
)

type attrInput struct {
	Image          string // official image name ("golang"), or ""
	Old, New       *rootfs
	OldDB, NewDB   *pkgDB
	Changed        map[string]pkgChange // name -> change (bumped, rebuilt, added, removed)
	VersionChanges map[string][2]string // *_VERSION env constants that moved
}

// attribute explains each change, or leaves Class empty.
func attribute(in attrInput, changes []fileChange) {
	anyPkg := len(in.Changed) > 0
	caChanged := false
	for n := range in.Changed {
		if strings.HasPrefix(n, "ca-certificates") {
			caChanged = true
		}
	}
	for i := range changes {
		c := &changes[i]
		p := c.Path
		owners := append(slices.Clone(in.OldDB.Owners[p]), in.NewDB.Owners[p]...)
		var changedOwner string
		for _, o := range owners {
			if _, ok := in.Changed[o]; ok {
				changedOwner = o
				break
			}
		}
		if changedOwner != "" {
			ch := in.Changed[changedOwner]
			if c.Kind != 'D' && effType(c.New) == 'f' {
				if s, ok := in.NewDB.Sums[p]; ok {
					if s.Sum != "md5:"+c.New.MD5 && s.Sum != "sha1:"+c.New.SHA1 {
						c.Why = fmt.Sprintf("owned by %s but content does not match the package's recorded checksum", changedOwner)
						continue
					}
					c.Class, c.Why = "package", fmt.Sprintf("%s %s (checksum matches package DB)", changedOwner, ch.label())
					continue
				}
			}
			c.Class, c.Why = "package", fmt.Sprintf("%s %s", changedOwner, ch.label())
			continue
		}
		if why, ok := normalize(in, c, caChanged); ok {
			c.Class, c.Why = "normalized", why
			continue
		}
		if anyPkg && pkgStateRe.MatchString(p) {
			c.Class, c.Why = "package-db", "package manager state (packages changed)"
			continue
		}
		if m := dpkgInfoRe.FindStringSubmatch(p); m != nil {
			n := m[1] + m[2]
			if ch, ok := in.Changed[n]; ok {
				c.Class, c.Why = "package-db", fmt.Sprintf("dpkg metadata of %s %s", n, ch.label())
				continue
			}
		}
		if rule, ok := payloadFor(in, p); ok {
			v := in.VersionChanges[rule.Env]
			c.Class, c.Why = "upstream", fmt.Sprintf("%s %s -> %s (%s; not yet verified)", rule.Env, v[0], v[1], rule.Upstream)
			continue
		}
		switch {
		case c.Why != "":
		case len(owners) > 0:
			slices.Sort(owners)
			c.Why = "owned by unchanged package " + strings.Join(slices.Compact(owners), ", ")
		default:
			c.Why = "not owned by any package"
		}
	}
}

func payloadFor(in attrInput, p string) (payloadRule, bool) {
	for _, r := range payloadRules[in.Image] {
		if _, moved := in.VersionChanges[r.Env]; !moved {
			continue
		}
		for _, pre := range r.Prefixes {
			if hasPathPrefix(p, pre) {
				return r, true
			}
		}
	}
	return payloadRule{}, false
}

func (c pkgChange) label() string {
	switch {
	case c.From == "":
		return "added " + c.To
	case c.To == "":
		return "removed " + c.From
	case c.Rebuilt:
		return c.To + " (rebuilt)"
	}
	return c.From + " -> " + c.To
}

// normalize recognises build noise: files that differ on every rebuild of
// identical software. Each rule is narrow and content-checked where the
// content is available.
func normalize(in attrInput, c *fileChange, caChanged bool) (string, bool) {
	p := c.Path
	switch {
	case pkgLogRe.MatchString(p):
		return "package manager log", true
	case p == "var/cache/ldconfig/aux-cache" && c.Kind == 'M':
		return "ldconfig auxiliary cache (rebuilt by every ldconfig run)", true
	case (p == "etc/shadow" || p == "etc/shadow-") && c.Kind == 'M':
		if onlyFieldDiffers(in.Old.Captured[p], in.New.Captured[p], ':', 2) && sameMeta(c) {
			return "only the last-password-change field differs", true
		}
	case p == "etc/cloud/build.info" && c.Kind == 'M':
		if onlyKeysDiffer(in.Old.Captured[p], in.New.Captured[p], ":", "serial") && sameMeta(c) {
			return "image build serial", true
		}
	case p == ".rock/metadata.yaml" && c.Kind == 'M':
		if onlyKeysDiffer(in.Old.Captured[p], in.New.Captured[p], ":", "created", "created-at", "build-id", "digest", "version", "revision", "timestamp") && sameMeta(c) {
			return "rock build metadata", true
		}
	case apkIndexRe.MatchString(p) && c.Kind != 'D':
		key, err := verifyAPKIndex(in.New.Captured[p], unchangedKey(in.Old, in.New))
		if err == nil {
			return "apk index cache; signature verified with " + key + " (present unchanged in both images)", true
		}
		c.Why = "apk index cache whose signature did not verify: " + err.Error()
		return "", false
	case strings.HasPrefix(p, "etc/ssl/certs/") && caChanged:
		return "CA links regenerated by update-ca-certificates (ca-certificates changed)", true
	}
	return "", false
}

func sameMeta(c *fileChange) bool {
	return c.Old != nil && c.New != nil && c.Old.Type == c.New.Type && c.Old.Mode == c.New.Mode && c.Old.UID == c.New.UID && c.Old.GID == c.New.GID
}

// onlyFieldDiffers: same lines, same fields, except field idx of some lines.
func onlyFieldDiffers(a, b []byte, sep byte, idx int) bool {
	if a == nil || b == nil {
		return false
	}
	la, lb := splitLines(string(a)), splitLines(string(b))
	if len(la) != len(lb) {
		return false
	}
	for i := range la {
		if la[i] == lb[i] {
			continue
		}
		fa, fb := strings.Split(la[i], string(sep)), strings.Split(lb[i], string(sep))
		if len(fa) != len(fb) || len(fa) <= idx {
			return false
		}
		for k := range fa {
			if k != idx && fa[k] != fb[k] {
				return false
			}
		}
		if !isDigits(fa[idx]) || !isDigits(fb[idx]) {
			return false
		}
	}
	return true
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// onlyKeysDiffer: same lines except "key<sep> value" lines for the given
// keys (leading whitespace allowed).
func onlyKeysDiffer(a, b []byte, sep string, keys ...string) bool {
	if a == nil || b == nil {
		return false
	}
	la, lb := splitLines(string(a)), splitLines(string(b))
	if len(la) != len(lb) {
		return false
	}
	for i := range la {
		if la[i] == lb[i] {
			continue
		}
		ka, _, oka := strings.Cut(strings.TrimSpace(la[i]), sep)
		kb, _, okb := strings.Cut(strings.TrimSpace(lb[i]), sep)
		if !oka || !okb || ka != kb || !slices.Contains(keys, ka) {
			return false
		}
	}
	return true
}

// unifiedLines is a tiny line diff for evidence: lines only in a ("-") and
// only in b ("+"), in order. Good enough for small config files.
func unifiedLines(a, b []byte, max int) []string {
	la, lb := splitLines(string(a)), splitLines(string(b))
	inB := map[string]int{}
	for _, l := range lb {
		inB[l]++
	}
	inA := map[string]int{}
	for _, l := range la {
		inA[l]++
	}
	var out []string
	for _, l := range la {
		if inB[l] == 0 {
			out = append(out, "- "+l)
		} else {
			inB[l]--
		}
	}
	for _, l := range lb {
		if inA[l] == 0 {
			out = append(out, "+ "+l)
		} else {
			inA[l]--
		}
	}
	if len(out) > max {
		out = append(out[:max], fmt.Sprintf("... %d more lines", len(out)-max))
	}
	return out
}
