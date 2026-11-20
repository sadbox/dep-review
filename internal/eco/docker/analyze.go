package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sadbox/dep-review/internal/gh"
	"github.com/sadbox/dep-review/internal/model"
)

type analyzer struct {
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

// platformDesc finds the manifest one platform uses. A pin to a single
// manifest (not an index) is used for every platform.
func platformDesc(doc *manifestDoc, dg, plat string) (descriptor, bool) {
	if !doc.isIndex() {
		return descriptor{MediaType: doc.MediaType, Digest: dg}, true
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
	var pairs []pair
	noop := true
	for _, p := range platforms {
		od, ok1 := platformDesc(oldIdx, ch.Old.Digest, p)
		nd, ok2 := platformDesc(newIdx, ch.New.Digest, p)
		if !ok1 || !ok2 {
			u.find(model.RouteHuman, codePlatformMissing, "%s: no %s manifest in the %s index", ch.New.Name(), p, map[bool]string{true: "new", false: "old"}[ok1])
			noop = false
			continue
		}
		pairs = append(pairs, pair{p, od, nd})
		if od.Digest != nd.Digest {
			noop = false
		}
	}
	if len(pairs) == 0 {
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
		u.find(model.RouteReview, codeTagHistoryUnavailable, "%s: %s", ch.New, u.Tag.Detail)
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
		same := true
		for _, p := range platforms {
			x, ok1 := platformDesc(curIdx, cur, p)
			y, ok2 := platformDesc(pinned, ref.Digest, p)
			if !ok1 || !ok2 || x.Digest != y.Digest {
				same = false
			}
		}
		if same {
			return tagResult{State: tagEquivalent, Current: cur, Detail: "the tag's current index (" + cur + ") has the same manifests for every built platform"}, nil
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
