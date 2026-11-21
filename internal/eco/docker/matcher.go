package docker

import (
	"strings"
)

// Platform matching the way the tools that pull the image do it. BuildKit
// and containerd pick an index entry with github.com/containerd/platforms;
// the gate must see the same entry, so normalizeOS and normalizeArch are
// copied from containerd/platforms v1.0.0-rc.5, database.go (normalizeOS,
// normalizeArch), and matcher.match follows platforms.go (matcher.Match)
// with compare.go's OnlyStrict: the entry's platform, normalized, equals
// the wanted platform, normalized. Differences, all toward "ambiguous":
//
//   - an empty OS normalizes to "linux" (upstream: runtime.GOOS; the gate
//     and the builds it guards run on Linux runners);
//   - an entry with os.features counts as a match (upstream matches it only
//     when the wanted platform lists those features);
//   - an entry without a platform counts as a match for every platform
//     (upstream accepts it too, ranked last).
//
// OnlyStrict, not Only: Only also accepts lower-ranked platforms (386 for
// amd64, arm/v7 for arm64), but it always prefers an exact match. So when
// exactly one entry matches exactly, that is the entry any of them pulls;
// with none or several, the gate cannot know and a person decides.

// normalizeOS is containerd/platforms normalizeOS, except "" -> "linux".
func normalizeOS(os string) string {
	if os == "" {
		return "linux"
	}
	os = strings.ToLower(os)
	switch os {
	case "macos":
		os = "darwin"
	}
	return os
}

// normalizeArch is containerd/platforms normalizeArch (v1.0.0-rc.5).
func normalizeArch(arch, variant string) (string, string) {
	arch, variant = strings.ToLower(arch), strings.ToLower(variant)
	switch arch {
	case "i386":
		arch = "386"
		variant = ""
	case "x86_64", "x86-64", "amd64":
		arch = "amd64"
		if variant == "v1" {
			variant = ""
		}
	case "aarch64", "arm64":
		arch = "arm64"
		switch variant {
		case "8", "v8", "v8.0":
			variant = ""
		case "9", "9.0", "v9.0":
			variant = "v9"
		}
	case "armhf":
		arch = "arm"
		variant = "v7"
	case "armel":
		arch = "arm"
		variant = "v6"
	case "arm":
		switch variant {
		case "", "7":
			variant = "v7"
		case "5", "6", "8":
			variant = "v" + variant
		}
	}
	return arch, variant
}

// platformMatcher matches index entries against one wanted platform.
type platformMatcher struct{ os, arch, variant string }

// newMatcher parses "os/arch[/variant]" (a bare "arch" means linux).
func newMatcher(p string) platformMatcher {
	parts := strings.SplitN(strings.TrimSpace(p), "/", 3)
	var os, arch, variant string
	switch len(parts) {
	case 1:
		arch = parts[0]
	case 2:
		os, arch = parts[0], parts[1]
	default:
		os, arch, variant = parts[0], parts[1], parts[2]
	}
	arch, variant = normalizeArch(arch, variant)
	return platformMatcher{normalizeOS(os), arch, variant}
}

func (m platformMatcher) String() string {
	if m.variant != "" {
		return m.os + "/" + m.arch + "/" + m.variant
	}
	return m.os + "/" + m.arch
}

// match reports whether a pull for m could select an entry with platform
// p (see the package comment above for the conservative differences).
func (m platformMatcher) match(p *ociPlatform) bool {
	if p == nil || len(p.OSFeatures) > 0 {
		return true
	}
	arch, variant := normalizeArch(p.Architecture, p.Variant)
	return normalizeOS(p.OS) == m.os && arch == m.arch && variant == m.variant
}

// normPlatform is the canonical spelling of a platform string.
func normPlatform(p string) string { return newMatcher(strings.ToLower(p)).String() }

// candidates lists, in index order, every entry a pull for plat could
// select. Annotations are ignored, as the pulling tools ignore them.
func candidates(idx *manifestDoc, plat string) []descriptor {
	m := newMatcher(plat)
	var out []descriptor
	for _, d := range idx.Manifests {
		if m.match(d.Platform) {
			out = append(out, d)
		}
	}
	return out
}

// selectPlatform returns the one entry an index offers for plat, and how
// many it offers: only exactly one is an answer.
func selectPlatform(idx *manifestDoc, plat string) (descriptor, int) {
	c := candidates(idx, plat)
	if len(c) != 1 {
		return descriptor{}, len(c)
	}
	return c[0], 1
}
