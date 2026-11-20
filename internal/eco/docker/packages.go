package docker

import (
	"encoding/base64"
	"encoding/hex"
	"path"
	"slices"
	"strings"
)

// Package databases inside an image: dpkg (var/lib/dpkg/status, or
// distroless's status.d/), and apk (lib/apk/db/installed). Only metadata is
// read; package bytes are not fetched in v1.

type pkg struct {
	Name     string
	Version  string
	Arch     string
	Source   string // source package (dpkg Source:, apk o:)
	Checksum string // apk C: (identifies the exact .apk build)
	Kind     string // "dpkg" or "apk"
}

type pkgDB struct {
	Kinds []string
	Pkgs  map[string]*pkg
	// Owners maps a canonical rootfs path to the packages that list it.
	Owners map[string][]string
	// Sums maps a canonical path to the checksum its package recorded:
	// "md5:<hex>" (dpkg md5sums, conffiles) or "sha1:<hex>" (apk Z:Q1).
	Sums map[string]sumRec
}

type sumRec struct {
	Pkg string
	Sum string
}

func (db *pkgDB) own(p, name string) {
	if !slices.Contains(db.Owners[p], name) {
		db.Owners[p] = append(db.Owners[p], name)
	}
}

// stanzas splits deb822-style text into key/value maps (continuation lines
// appended with "\n").
func stanzas(text string) []map[string]string {
	var out []map[string]string
	cur := map[string]string{}
	key := ""
	flush := func() {
		if len(cur) > 0 {
			out = append(out, cur)
		}
		cur, key = map[string]string{}, ""
	}
	for _, l := range splitLines(text) {
		switch {
		case strings.TrimSpace(l) == "":
			flush()
		case (l[0] == ' ' || l[0] == '\t') && key != "":
			cur[key] += "\n" + strings.TrimSpace(l)
		default:
			k, v, ok := strings.Cut(l, ":")
			if !ok {
				continue
			}
			key = k
			cur[k] = strings.TrimSpace(v)
		}
	}
	flush()
	return out
}

func parsePackages(fs *rootfs) *pkgDB {
	db := &pkgDB{Pkgs: map[string]*pkg{}, Owners: map[string][]string{}, Sums: map[string]sumRec{}}
	parseDpkg(fs, db)
	parseApk(fs, db)
	return db
}

func parseDpkg(fs *rootfs, db *pkgDB) {
	var texts []string
	if b, ok := fs.Captured["var/lib/dpkg/status"]; ok {
		texts = append(texts, string(b))
	}
	for _, p := range sortedKeys(fs.Captured) {
		if strings.HasPrefix(p, "var/lib/dpkg/status.d/") && !strings.HasSuffix(p, ".md5sums") {
			texts = append(texts, string(fs.Captured[p]))
		}
	}
	found := false
	for _, t := range texts {
		for _, s := range stanzas(t) {
			name := s["Package"]
			if name == "" {
				continue
			}
			if st, ok := s["Status"]; ok && !strings.HasSuffix(st, " installed") {
				continue
			}
			found = true
			src, _, _ := strings.Cut(s["Source"], " ")
			if src == "" {
				src = name
			}
			// The source version can differ from the binary's: "Source: x (1.2-3)".
			key := name
			if old, dup := db.Pkgs[key]; dup && old.Arch != s["Architecture"] {
				key = name + ":" + s["Architecture"]
			}
			db.Pkgs[key] = &pkg{Name: name, Version: s["Version"], Arch: s["Architecture"], Source: src, Kind: "dpkg"}
			for l := range strings.SplitSeq(s["Conffiles"], "\n") {
				f := strings.Fields(l)
				if len(f) >= 2 {
					c := fs.canon(f[0])
					db.own(c, name)
					db.Sums[c] = sumRec{name, "md5:" + f[1]}
				}
			}
		}
	}
	for p, b := range fs.Captured {
		var name, ext string
		switch {
		case strings.HasPrefix(p, "var/lib/dpkg/info/"):
			base := path.Base(p)
			i := strings.LastIndexByte(base, '.')
			name, ext = base[:i], base[i+1:]
		case strings.HasPrefix(p, "var/lib/dpkg/status.d/") && strings.HasSuffix(p, ".md5sums"):
			name, ext = strings.TrimSuffix(path.Base(p), ".md5sums"), "md5sums"
		default:
			continue
		}
		name, _, _ = strings.Cut(name, ":")
		switch ext {
		case "list":
			for l := range strings.SplitSeq(string(b), "\n") {
				if l = strings.TrimSpace(l); l != "" && l != "/." {
					db.own(fs.canon(l), name)
				}
			}
		case "md5sums":
			for l := range strings.SplitSeq(string(b), "\n") {
				sum, file, ok := strings.Cut(l, "  ")
				if !ok {
					continue
				}
				c := fs.canon(strings.TrimSpace(file))
				db.own(c, name)
				db.Sums[c] = sumRec{name, "md5:" + sum}
			}
		}
	}
	if found {
		db.Kinds = append(db.Kinds, "dpkg")
	}
}

func parseApk(fs *rootfs, db *pkgDB) {
	b, ok := fs.Captured["lib/apk/db/installed"]
	if !ok {
		b, ok = fs.Captured["usr/lib/apk/db/installed"]
	}
	if !ok {
		return
	}
	db.Kinds = append(db.Kinds, "apk")
	for block := range strings.SplitSeq(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n\n") {
		var p *pkg
		dir, last := "", ""
		for l := range strings.SplitSeq(block, "\n") {
			if len(l) < 2 || l[1] != ':' {
				continue
			}
			k, v := l[0], l[2:]
			if k == 'P' {
				p = &pkg{Name: v, Kind: "apk"}
				db.Pkgs[v] = p
				continue
			}
			if p == nil {
				continue
			}
			switch k {
			case 'V':
				p.Version = v
			case 'A':
				p.Arch = v
			case 'o':
				p.Source = v
			case 'C':
				p.Checksum = v
			case 'F':
				dir = v
				db.own(fs.canon(dir), p.Name)
			case 'R':
				last = fs.canon(path.Join(dir, v))
				db.own(last, p.Name)
			case 'Z':
				if last != "" && strings.HasPrefix(v, "Q1") {
					if raw, err := base64.StdEncoding.DecodeString(v[2:]); err == nil {
						db.Sums[last] = sumRec{p.Name, "sha1:" + hex.EncodeToString(raw)}
					}
				}
			}
		}
		if p != nil && p.Source == "" {
			p.Source = p.Name
		}
	}
}

// osRelease is the distribution identity of an image.
type osRelease struct {
	ID, VersionID, Codename, Pretty string
}

func parseOSRelease(fs *rootfs) osRelease {
	b, ok := fs.Captured["etc/os-release"]
	if !ok {
		b = fs.Captured["usr/lib/os-release"]
	}
	kv := map[string]string{}
	for l := range strings.SplitSeq(string(b), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(l), "=")
		if ok {
			kv[k] = strings.Trim(v, `"'`)
		}
	}
	return osRelease{ID: kv["ID"], VersionID: kv["VERSION_ID"], Codename: kv["VERSION_CODENAME"], Pretty: kv["PRETTY_NAME"]}
}

// release is the part of the version that names a distribution release:
// Alpine 3.24.4 -> 3.24; Debian "13" and Ubuntu "26.04" as they are.
func (o osRelease) release() string {
	if o.ID == "alpine" {
		parts := strings.SplitN(o.VersionID, ".", 3)
		if len(parts) >= 2 {
			return parts[0] + "." + parts[1]
		}
	}
	return o.VersionID
}

func (o osRelease) String() string {
	s := o.ID + " " + o.VersionID
	if o.Codename != "" {
		s += " (" + o.Codename + ")"
	}
	return strings.TrimSpace(s)
}

// osvEcosystem is OSV.dev's ecosystem name for the distribution, or "".
func (o osRelease) osvEcosystem() string {
	switch o.ID {
	case "debian":
		return "Debian:" + o.VersionID
	case "ubuntu":
		if strings.Contains(o.Pretty, "LTS") {
			return "Ubuntu:" + o.VersionID + ":LTS"
		}
		return "Ubuntu:" + o.VersionID
	case "alpine":
		return "Alpine:v" + o.release()
	}
	return ""
}

// pkgChange is one package's difference between old and new.
type pkgChange struct {
	Name     string
	Kind     string
	Source   string
	From, To string // "" when added/removed
	Rebuilt  bool   // same version, different apk checksum
}

func diffPackages(a, b *pkgDB) (changed []pkgChange, added, removed []pkgChange) {
	for _, k := range sortedKeys(b.Pkgs) {
		np := b.Pkgs[k]
		op, ok := a.Pkgs[k]
		switch {
		case !ok:
			added = append(added, pkgChange{Name: np.Name, Kind: np.Kind, Source: np.Source, To: np.Version})
		case op.Version != np.Version:
			changed = append(changed, pkgChange{Name: np.Name, Kind: np.Kind, Source: np.Source, From: op.Version, To: np.Version})
		case op.Checksum != np.Checksum:
			changed = append(changed, pkgChange{Name: np.Name, Kind: np.Kind, Source: np.Source, From: op.Version, To: np.Version, Rebuilt: true})
		}
	}
	for _, k := range sortedKeys(a.Pkgs) {
		if _, ok := b.Pkgs[k]; !ok {
			op := a.Pkgs[k]
			removed = append(removed, pkgChange{Name: op.Name, Kind: op.Kind, Source: op.Source, From: op.Version})
		}
	}
	return
}
