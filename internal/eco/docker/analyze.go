package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sadbox/dep-review/internal/gh"
	"github.com/sadbox/dep-review/internal/model"
)

type analyzer struct {
	// platforms, when set, are the platforms the repository owner declares
	// it builds (gate input docker_platforms). The no-op proof and tag
	// equivalence then compare those platforms (plus any a stage names)
	// instead of every manifest in the index.
	platforms []string

	reg  *registry
	hist tagHistory
	osv  *osvClient
	// maxParallel bounds platforms analysed at once (each streams layers).
	maxParallel int
}

type platformResult struct {
	Platform                 string
	OldManifest, NewManifest string
	Identical                bool

	Config                             configDiff
	OldOS, NewOS                       osRelease
	PkgKinds                           []string
	Changed                            []pkgChange
	Added, Removed                     []pkgChange
	Files                              []fileChange
	Unexplained                        []fileChange
	ClassCounts                        map[string]int
	EtcDiffs                           map[string][]string // unexplained small text files: line diff
	OSV                                osvDelta
	Anomalies                          []string
	LayersOld, LayersNew, LayersShared int
	BytesFetched                       int64
	Duration                           time.Duration
}

type updateResult struct {
	Change    fromChange
	Update    model.Update
	Platforms []string
	Tag       tagResult
	Results   []*platformResult
	Findings  []model.Finding
	Notes     []string
	Duration  time.Duration
}

func (u *updateResult) find(route model.Route, code, format string, args ...any) {
	u.Findings = append(u.Findings, model.Finding{
		Code:   code,
		Route:  route,
		Detail: sanitize(fmt.Sprintf(format, args...)),
		Update: u.Update.Name,
	})
}

// classify turns an error into a finding when it says something about the
// image (tampering, size, format) rather than about the network. It
// returns false for errors that should fail the job (retry later).
func (u *updateResult) classify(err error, what string) bool {
	switch {
	case errors.Is(err, errDigestMismatch):
		u.find(model.RouteHuman, codeDigestMismatch, "%s: %v", what, err)
	case errors.Is(err, errTooLarge):
		u.find(model.RouteHuman, codeDownloadLimit, "%s: %v", what, err)
	case errors.Is(err, errUnsupportedLayer):
		u.find(model.RouteHuman, codeLayerUnsupported, "%s: %v", what, err)
	case errors.Is(err, errZstd):
		u.find(model.RouteHuman, codeZstdLayer, "%s: zstd layers cannot be read with the standard library", what)
	case errors.Is(err, gh.ErrNotFound):
		u.find(model.RouteHuman, codeNotFound, "%s: %v", what, err)
	default:
		return false
	}
	return true
}

func makeUpdate(ch fromChange) model.Update {
	dir := path.Dir(ch.Path)
	if dir == "." {
		dir = "/"
	} else {
		dir = "/" + dir
	}
	// From/To are the tags (Dependabot's dependency-version); a tagless pin
	// uses its digest so it never reads as a new dependency.
	from, to := ch.Old.Tag, ch.New.Tag
	if from == "" {
		from = ch.Old.Digest
	}
	if to == "" {
		to = ch.New.Digest
	}
	return model.Update{
		Ecosystem: model.Docker,
		Directory: dir,
		Name:      ch.New.Name(),
		From:      from,
		To:        to,
		FromRef:   ch.Old.Digest,
		ToRef:     ch.New.Digest,
		Type:      tagUpdateType(ch.Old.Tag, ch.New.Tag),
		Direct:    true,
	}
}

var tagVersionRe = regexp.MustCompile(`^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(.*)$`)

// tagUpdateType compares tags: same tag = digest; numeric prefix with the
// same suffix and precision = major/minor/patch; anything else unknown.
func tagUpdateType(a, b string) model.UpdateType {
	if a == b {
		return model.Digest
	}
	ma, mb := tagVersionRe.FindStringSubmatch(a), tagVersionRe.FindStringSubmatch(b)
	if ma == nil || mb == nil || ma[4] != mb[4] {
		return model.Unknown
	}
	for i := 1; i <= 3; i++ {
		if (ma[i] == "") != (mb[i] == "") {
			return model.Unknown
		}
	}
	for i, t := range []model.UpdateType{model.Major, model.Minor, model.Patch} {
		x, _ := strconv.Atoi(ma[i+1])
		y, _ := strconv.Atoi(mb[i+1])
		if x != y {
			if y < x {
				return model.Unknown // downgrade
			}
			return t
		}
	}
	return model.Unknown
}

// platformDesc finds the manifest one platform uses, and how many entries
// a pull for it could select (only 1 is an answer). A pin to a single
// manifest (not an index) is used for every platform.
func platformDesc(doc *manifestDoc, dg, plat string) (descriptor, int) {
	if !doc.isIndex() {
		return descriptor{MediaType: doc.MediaType, Digest: dg}, 1
	}
	return selectPlatform(doc, plat)
}

func (a *analyzer) analyze(ctx context.Context, ch fromChange, platforms []string, owner string) (*updateResult, error) {
	start := time.Now()
	u := &updateResult{Change: ch, Update: makeUpdate(ch), Platforms: platforms}
	defer func() { u.Duration = time.Since(start) }()
	if !ch.New.allowed(owner) {
		u.find(model.RouteHuman, codeNotAllowlisted, "%s is not an allowlisted registry/repository (Docker Official Images, gcr.io/distroless, ghcr.io/%s)", ch.New.Name(), owner)
		return u, nil
	}
	_, oldIdx, _, err := a.reg.manifest(ctx, ch.Old, ch.Old.Digest)
	if err != nil {
		if u.classify(err, "old index") {
			return u, nil
		}
		return nil, err
	}
	_, newIdx, _, err := a.reg.manifest(ctx, ch.New, ch.New.Digest)
	if err != nil {
		if u.classify(err, "new index") {
			return u, nil
		}
		return nil, err
	}
	type pair struct {
		plat     string
		old, new descriptor
	}
	// The detected platforms decide only what is analysed and shown as
	// evidence. Platform detection cannot see every way a repository
	// builds an image, so the no-op proof never relies on it: every image
	// manifest in the two indexes must be identical.
	var pairs []pair
	missing := false
	for _, p := range platforms {
		od, n1 := platformDesc(oldIdx, ch.Old.Digest, p)
		nd, n2 := platformDesc(newIdx, ch.New.Digest, p)
		switch {
		case n1 == 0 || n2 == 0:
			which := "old"
			if n1 > 0 {
				which = "new"
			}
			u.find(model.RouteHuman, codePlatformMissing, "%s: no %s manifest in the %s index", ch.New.Name(), p, which)
			missing = true
			continue
		case n1 > 1 || n2 > 1:
			// Which one a build pulls then depends on the tool and on
			// index order; the gate cannot prove what is used.
			u.find(model.RouteHuman, codePlatformAmbiguous, "%s: %d entries in the old index and %d in the new one could be pulled for %s", ch.New.Name(), n1, n2, p)
			missing = true
			continue
		}
		pairs = append(pairs, pair{p, od, nd})
	}
	noop, unbuilt := a.sameImage(oldIdx, ch.Old.Digest, newIdx, ch.New.Digest, platforms)
	switch {
	case len(unbuilt) > 0 && len(a.platforms) > 0:
		u.Notes = append(u.Notes, "manifests changed only for platforms outside the declared docker_platforms (not analysed): "+strings.Join(unbuilt, ", "))
	case len(unbuilt) > 0:
		u.find(model.RouteReview, codeOtherPlatforms, "%s: manifests changed for platforms the gate did not detect a build for, so this is not a proven no-op and they were not analysed: %s", ch.New.Name(), strings.Join(unbuilt, ", "))
	}
	if len(pairs) == 0 || missing {
		noop = false
	}

	u.Tag, err = a.tagCheck(ctx, ch.New, newIdx, platforms)
	if err != nil {
		return nil, err
	}
	switch u.Tag.State {
	case tagNever:
		u.find(model.RouteRefuse, codeTagUnattributable, "%s: %s", ch.New, u.Tag.Detail)
	case tagUnavailable:
		// Not proven either way, which is not proof: a person checks.
		u.find(model.RouteHuman, codeTagHistoryUnavailable, "%s: %s", ch.New, u.Tag.Detail)
	}

	if noop {
		u.Update.NoOp = true
		for _, p := range pairs {
			u.Results = append(u.Results, &platformResult{Platform: p.plat, OldManifest: p.old.Digest, NewManifest: p.new.Digest, Identical: true})
		}
		return u, nil
	}

	results := make([]*platformResult, len(pairs))
	errs := make([]error, len(pairs))
	sem := make(chan struct{}, max(1, a.maxParallel))
	var wg sync.WaitGroup
	for i, p := range pairs {
		if p.old.Digest == p.new.Digest {
			results[i] = &platformResult{Platform: p.plat, OldManifest: p.old.Digest, NewManifest: p.new.Digest, Identical: true}
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i], errs[i] = a.analyzePlatform(ctx, ch.New, p.plat, p.old, p.new)
		}()
	}
	wg.Wait()
	analysed := false
	for i, r := range results {
		if errs[i] != nil {
			if u.classify(errs[i], pairs[i].plat) {
				continue
			}
			return nil, errs[i]
		}
		u.Results = append(u.Results, r)
		if !r.Identical {
			analysed = true
			u.platformFindings(r)
		}
	}
	if analysed {
		u.find(model.RouteReview, codeArchiveNotVerified,
			"changed files were attributed from package metadata inside the image only; package bytes were not checked against the signed distro archives and upstream payloads were not checked against their release artifacts (v2)")
	}
	return u, nil
}

func (u *updateResult) platformFindings(r *platformResult) {
	p := r.Platform
	if len(r.Config.Other) > 0 {
		u.find(model.RouteHuman, codeConfigChanged, "%s: image config changed beyond version constants: %s", p, strings.Join(r.Config.Other, "; "))
	}
	if len(r.Added) > 0 {
		u.find(model.RouteHuman, codePackageAdded, "%s: packages added: %s", p, pkgList(r.Added))
	}
	if len(r.Removed) > 0 {
		u.find(model.RouteHuman, codePackageRemoved, "%s: packages removed: %s", p, pkgList(r.Removed))
	}
	if r.OldOS.ID != r.NewOS.ID || r.OldOS.release() != r.NewOS.release() || r.OldOS.Codename != r.NewOS.Codename {
		u.find(model.RouteHuman, codeReleaseChanged, "%s: distribution release changed: %s -> %s", p, r.OldOS, r.NewOS)
	}
	if len(r.Anomalies) > 0 {
		u.find(model.RouteHuman, codeLayerAnomaly, "%s: %s", p, strings.Join(r.Anomalies, "; "))
	}
	if n := len(r.Unexplained); n > 0 {
		var l []string
		for _, c := range r.Unexplained[:min(n, 15)] {
			l = append(l, c.describe()+": "+c.Why)
		}
		more := ""
		if n > 15 {
			more = fmt.Sprintf(" (+%d more in the evidence)", n-15)
		}
		u.find(model.RouteHuman, codeUnexplainedFiles, "%s: %d changed path(s) not attributable to a changed package, an upstream payload or known build noise: %s%s", p, n, strings.Join(l, "; "), more)
	}
	if len(r.OSV.Introduced) > 0 {
		u.find(model.RouteHuman, codeOSVIntroduced, "%s: OSV lists vulnerabilities for the new versions but not the old: %s", p, strings.Join(sortedKeys(r.OSV.Introduced), ", "))
	}
	if r.OSV.Err != "" {
		u.find(model.RouteHuman, codeOSVUnavailable, "%s: the changed packages could not be checked against OSV.dev: %s", p, r.OSV.Err)
	}
}

// sameImage is the identity both the no-op proof and tag equivalence use:
// sameManifests (every manifest) by default, samePlatforms (exactly the
// given platforms, each present once in both) when the owner declared
// docker_platforms. platforms is then the declared set plus whatever a
// stage names itself (see platformsFor).
func (a *analyzer) sameImage(oldDoc *manifestDoc, oldDigest string, newDoc *manifestDoc, newDigest string, platforms []string) (bool, []string) {
	if len(a.platforms) == 0 {
		return sameManifests(oldDoc, oldDigest, newDoc, newDigest, platforms)
	}
	_, unbuilt := sameManifests(oldDoc, oldDigest, newDoc, newDigest, platforms)
	return samePlatforms(oldDoc, oldDigest, newDoc, newDigest, platforms), unbuilt
}

// samePlatforms: two single manifests when their digests are equal; two
// indexes when every platform in plats has exactly one image manifest in
// each and the two are the same digest.
func samePlatforms(oldDoc *manifestDoc, oldDigest string, newDoc *manifestDoc, newDigest string, plats []string) bool {
	switch {
	case !oldDoc.isIndex() && !newDoc.isIndex():
		return oldDigest == newDigest
	case oldDoc.isIndex() != newDoc.isIndex() || len(plats) == 0:
		return false
	}
	for _, p := range plats {
		o, n1 := selectPlatform(oldDoc, p)
		n, n2 := selectPlatform(newDoc, p)
		if n1 != 1 || n2 != 1 || o.Digest != n.Digest {
			return false
		}
	}
	return true
}

// platformsFor is the platform set one stage is compared on: detection's
// (the default), or with docker_platforms the declared set plus anything
// detection found for the stage. Detection can only add platforms.
func (a *analyzer) platformsFor(detected []string) []string {
	if len(a.platforms) == 0 {
		return detected
	}
	seen := map[string]bool{}
	var out []string
	for _, p := range append(slicesConcat(a.platforms, nil), detected...) {
		if n := normPlatform(p); !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// ParsePlatforms validates a docker_platforms value
// ("linux/amd64,linux/arm64"): at most 16 os/arch[/variant] entries.
func ParsePlatforms(s string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if !declaredPlatformRe.MatchString(f) {
			return nil, fmt.Errorf("docker platform %.40q is not os/arch[/variant]", f)
		}
		if n := normPlatform(f); !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	if len(out) > 16 {
		return nil, fmt.Errorf("%d docker platforms; at most 16", len(out))
	}
	sort.Strings(out)
	return out, nil
}

var declaredPlatformRe = regexp.MustCompile(`^[a-z0-9]{1,16}/[a-z0-9_]{1,16}(?:/[a-z0-9]{1,8})?$`)

// isAttestation reports whether an index entry is a BuildKit attestation
// manifest: both the attestation annotation and the unknown/unknown
// platform. Anything else counts as an image manifest.
func isAttestation(d descriptor) bool {
	return d.Annotations["vnd.docker.reference.type"] == "attestation-manifest" &&
		d.Platform != nil && d.Platform.OS == "unknown" && d.Platform.Architecture == "unknown"
}

// ignorable is an attestation no compared platform could pull.
func ignorable(d descriptor, plats []string) bool {
	if !isAttestation(d) {
		return false
	}
	for _, p := range plats {
		if newMatcher(p).match(d.Platform) {
			return false
		}
	}
	return true
}

// manifestKey identifies an index entry by its full platform (including
// os.version, which tells Windows builds apart) and its digest.
func manifestKey(d descriptor) (plat, key string) {
	plat = "(no platform)"
	if p := d.Platform; p != nil {
		plat = p.String()
		if p.OSVersion != "" {
			plat += " " + p.OSVersion
		}
	}
	return plat, plat + " " + d.MediaType + " " + d.Digest
}

// sameManifests is the default no-op proof: two indexes are the same
// image when their entries, in order, are identical (digest, media type,
// platform, annotations), apart from attestations no compared platform
// could pull; two single manifests when their digests are equal; an index
// and a single manifest never. Order matters because the tools that pull
// take the first matching entry. unbuilt lists the platforms of entries
// that differ and that no compared platform matches (evidence only).
func sameManifests(oldDoc *manifestDoc, oldDigest string, newDoc *manifestDoc, newDigest string, plats []string) (same bool, unbuilt []string) {
	switch {
	case !oldDoc.isIndex() && !newDoc.isIndex():
		return oldDigest == newDigest, nil
	case oldDoc.isIndex() != newDoc.isIndex():
		return false, nil
	}
	entries := func(doc *manifestDoc) []string {
		var out []string
		for _, d := range doc.Manifests {
			if ignorable(d, plats) {
				continue
			}
			b, err := json.Marshal(d) // map keys sorted: annotations compare exactly
			if err != nil {
				return nil
			}
			out = append(out, string(b))
		}
		return out
	}
	oe, ne := entries(oldDoc), entries(newDoc)
	same = len(oe) > 0 && slices.Equal(oe, ne)

	// Evidence: which entries differ, as a multiset.
	count := func(doc *manifestDoc) (map[string]int, map[string]descriptor) {
		keys, descs := map[string]int{}, map[string]descriptor{}
		for _, d := range doc.Manifests {
			if isAttestation(d) {
				continue
			}
			_, k := manifestKey(d)
			keys[k]++
			descs[k] = d
		}
		return keys, descs
	}
	ok, od := count(oldDoc)
	nk, nd := count(newDoc)
	var differ []descriptor
	for k, n := range ok {
		if nk[k] != n {
			differ = append(differ, od[k])
		}
	}
	for k, n := range nk {
		if ok[k] != n {
			differ = append(differ, nd[k])
		}
	}
	seen := map[string]bool{}
	for _, d := range differ {
		compared := false
		for _, p := range plats {
			compared = compared || newMatcher(p).match(d.Platform)
		}
		if plat, _ := manifestKey(d); !compared && !seen[plat] {
			seen[plat] = true
			unbuilt = append(unbuilt, plat)
		}
	}
	sort.Strings(unbuilt)
	return same, unbuilt
}

func pkgList(cs []pkgChange) string {
	var s []string
	for _, c := range cs {
		s = append(s, c.Name+" "+c.label())
	}
	if len(s) > 30 {
		s = append(s[:30], fmt.Sprintf("+%d more", len(s)-30))
	}
	return strings.Join(s, ", ")
}

func (a *analyzer) tagCheck(ctx context.Context, ref imageRef, pinned *manifestDoc, platforms []string) (tagResult, error) {
	if ref.Tag == "" {
		return tagResult{State: tagUnavailable, Detail: "pinned by digest without a tag; nothing to attribute it to"}, nil
	}
	cur, err := a.reg.tagDigest(ctx, ref, ref.Tag)
	switch {
	case err == nil && cur == ref.Digest:
		return tagResult{State: tagCurrent, Current: cur, Detail: "the tag resolves to the pinned digest"}, nil
	case err == nil:
		_, curIdx, _, err := a.reg.manifest(ctx, ref, cur)
		if err != nil {
			return tagResult{}, err
		}
		if same, _ := a.sameImage(curIdx, cur, pinned, ref.Digest, platforms); same {
			what := "every manifest"
			if len(a.platforms) > 0 {
				what = "the same manifests for " + strings.Join(platforms, ", ")
			}
			return tagResult{State: tagEquivalent, Current: cur, Detail: "the tag's current index (" + cur + ") has " + what + " of the pin"}, nil
		}
	case !errors.Is(err, gh.ErrNotFound):
		return tagResult{}, err
	}
	name, official := ref.officialImage()
	if !official || a.hist == nil {
		return tagResult{State: tagUnavailable, Current: cur, Detail: "the tag has moved on and no published tag history exists for this image"}, nil
	}
	digests, ok, herr := a.hist.indexDigests(ctx, name, ref.Tag)
	switch {
	case herr != nil:
		return tagResult{State: tagUnavailable, Current: cur, Detail: "the tag has moved on and docker-library/repo-info could not be read: " + herr.Error()}, nil
	case !ok:
		return tagResult{State: tagUnavailable, Current: cur, Detail: "the tag has moved on and docker-library/repo-info has no history for it"}, nil
	case digests[ref.Digest]:
		return tagResult{State: tagSuperseded, Current: cur, Detail: fmt.Sprintf("the pin is a former value of the tag (docker-library/repo-info, %d values in history); the tag now resolves to %s", len(digests), cur)}, nil
	}
	return tagResult{State: tagNever, Current: cur, Detail: fmt.Sprintf("the pinned digest is not the tag's current index, does not match it on the built platforms, and is not among the %d values in docker-library/repo-info's history", len(digests))}, nil
}

func (a *analyzer) image(ctx context.Context, ref imageRef, d descriptor) (*manifestDoc, *imageConfig, error) {
	_, m, _, err := a.reg.manifest(ctx, ref, d.Digest)
	if err != nil {
		return nil, nil, err
	}
	if m.isIndex() || m.Config == nil {
		return nil, nil, fmt.Errorf("%s is not an image manifest", d.Digest)
	}
	b, err := a.reg.readBlob(ctx, ref, *m.Config, maxConfigBytes)
	if err != nil {
		return nil, nil, err
	}
	var c imageConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, nil, fmt.Errorf("config %s: %w", m.Config.Digest, err)
	}
	if len(c.RootFS.DiffIDs) != len(m.Layers) {
		return nil, nil, fmt.Errorf("%s: %d layers but %d diff_ids", d.Digest, len(m.Layers), len(c.RootFS.DiffIDs))
	}
	return m, &c, nil
}

func (a *analyzer) analyzePlatform(ctx context.Context, ref imageRef, plat string, od, nd descriptor) (*platformResult, error) {
	start := time.Now()
	r := &platformResult{Platform: plat, OldManifest: od.Digest, NewManifest: nd.Digest, ClassCounts: map[string]int{}, EtcDiffs: map[string][]string{}}
	defer func() { r.Duration = time.Since(start) }()
	om, oc, err := a.image(ctx, ref, od)
	if err != nil {
		return nil, err
	}
	nm, nc, err := a.image(ctx, ref, nd)
	if err != nil {
		return nil, err
	}
	r.Config = diffConfig(oc, nc)
	r.LayersOld, r.LayersNew = len(om.Layers), len(nm.Layers)
	oldSet := map[string]bool{}
	for _, l := range om.Layers {
		oldSet[l.Digest] = true
	}
	for _, l := range nm.Layers {
		if oldSet[l.Digest] {
			r.LayersShared++
		}
	}
	for _, l := range slicesConcat(om.Layers, nm.Layers) {
		if strings.Contains(l.MediaType, "foreign") || strings.Contains(l.MediaType, "nondistributable") {
			return nil, fmt.Errorf("layer %s has media type %s: %w", l.Digest, l.MediaType, errUnsupportedLayer)
		}
		if strings.Contains(l.MediaType, "zstd") {
			return nil, errZstd
		}
	}
	cache := map[string]*layerResult{}
	counted := map[string]bool{}
	budget := int64(maxCaptureTotal)
	load := func(m *manifestDoc, c *imageConfig) ([]*layerResult, error) {
		var out []*layerResult
		for i, l := range m.Layers {
			lr, ok := cache[l.Digest]
			if !ok {
				rc, err := a.reg.blob(ctx, ref, l, maxLayerBytes)
				if err != nil {
					return nil, err
				}
				lr, err = readLayer(rc, l.MediaType, i, &budget)
				rc.Close()
				if err != nil {
					return nil, err
				}
				lr.Digest = l.Digest
				cache[l.Digest] = lr
				r.BytesFetched += l.Size
			}
			if lr.DiffID != c.RootFS.DiffIDs[i] {
				return nil, fmt.Errorf("layer %s uncompresses to %s, config says %s: %w", l.Digest, lr.DiffID, c.RootFS.DiffIDs[i], errDigestMismatch)
			}
			if !counted[l.Digest] {
				counted[l.Digest] = true
				r.Anomalies = append(r.Anomalies, lr.Anomalies...)
			}
			out = append(out, lr)
		}
		return out, nil
	}
	ol, err := load(om, oc)
	if err != nil {
		return nil, err
	}
	nl, err := load(nm, nc)
	if err != nil {
		return nil, err
	}
	ofs, nfs := compose(ol), compose(nl)
	cache = nil
	odb, ndb := parsePackages(ofs), parsePackages(nfs)
	r.OldOS, r.NewOS = parseOSRelease(ofs), parseOSRelease(nfs)
	r.PkgKinds = ndb.Kinds
	r.Changed, r.Added, r.Removed = diffPackages(odb, ndb)
	changed := map[string]pkgChange{}
	for _, c := range append(slicesConcat(r.Changed, r.Added), r.Removed...) {
		changed[c.Name] = c
	}
	image, _ := ref.officialImage()
	r.Files = diffRootfs(ofs, nfs)
	attribute(attrInput{Image: image, Old: ofs, New: nfs, OldDB: odb, NewDB: ndb, Changed: changed, VersionChanges: r.Config.Versions}, r.Files)
	for _, c := range r.Files {
		r.ClassCounts[c.Class]++
		if !c.explained() {
			r.Unexplained = append(r.Unexplained, c)
			if ob, nb := ofs.Captured[c.Path], nfs.Captured[c.Path]; (ob != nil || nb != nil) && len(r.EtcDiffs) < 20 {
				r.EtcDiffs[c.Path] = unifiedLines(ob, nb, 40)
			}
		}
	}
	r.OSV = a.osv.delta(ctx, r.NewOS.osvEcosystem(), r.Changed)
	return r, nil
}

func slicesConcat[T any](a, b []T) []T {
	out := make([]T, 0, len(a)+len(b))
	return append(append(out, a...), b...)
}

// sanitize makes text from images safe to show: no control characters,
// bounded length.
func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == '\n' || r == '\t' {
			b.WriteByte(' ')
			continue
		}
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == '‮' || r == '‭' {
			b.WriteString("?")
			continue
		}
		b.WriteRune(r)
		if b.Len() > 4000 {
			b.WriteString("...")
			break
		}
	}
	return b.String()
}
