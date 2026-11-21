package actions

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/sadbox/dep-review/internal/fetch"
	"github.com/sadbox/dep-review/internal/gh"
	"github.com/sadbox/dep-review/internal/model"
)

// upstream is the REST view of one action repository. All endpoints used
// are public and read-only. A missing object is errors.Is(err,
// gh.ErrNotFound).
type upstream struct {
	gh          fetch.GitHub
	owner, repo string
	tagDeref    map[string]string // annotated tag object SHA -> commit SHA
}

func (u *upstream) get(ctx context.Context, p string, v any) error {
	full := "repos/" + u.owner + "/" + u.repo
	if p != "" {
		full += "/" + p
	}
	return u.gh.Get(ctx, full, v)
}

type repoInfo struct {
	ID            int64  `json:"id"`
	FullName      string `json:"full_name"`
	DefaultBranch string `json:"default_branch"`
	Archived      bool   `json:"archived"`
	Owner         struct {
		ID int64 `json:"id"`
	} `json:"owner"`
}

type compareResult struct {
	Status       string `json:"status"`
	AheadBy      int    `json:"ahead_by"`
	BehindBy     int    `json:"behind_by"`
	TotalCommits int    `json:"total_commits"`
	Commits      []struct {
		SHA    string `json:"sha"`
		Commit struct {
			Message string `json:"message"`
			Author  struct {
				Name string `json:"name"`
			} `json:"author"`
		} `json:"commit"`
		Author *struct {
			Login string `json:"login"`
		} `json:"author"`
	} `json:"commits"`
}

func (u *upstream) compare(ctx context.Context, base, head string, perPage int) (*compareResult, error) {
	var c compareResult
	err := u.get(ctx, "compare/"+base+"..."+head+"?per_page="+itoa(perPage), &c)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

type gitObject struct {
	SHA  string `json:"sha"`
	Type string `json:"type"`
}

type gitRef struct {
	Ref    string    `json:"ref"`
	Object gitObject `json:"object"`
}

// tagRef is a vX.Y.Z tag ref.
type tagRef struct {
	name string
	v    semver
	obj  gitObject
}

// semverTags lists the repository's vX.Y.Z tags, newest version first.
func (u *upstream) semverTags(ctx context.Context) ([]tagRef, error) {
	var refs []gitRef
	if err := u.get(ctx, "git/matching-refs/tags/v", &refs); err != nil {
		return nil, err
	}
	var out []tagRef
	for _, r := range refs {
		name := strings.TrimPrefix(r.Ref, "refs/tags/")
		v, ok := parseTag(name)
		if !ok || !shaRx.MatchString(r.Object.SHA) {
			continue
		}
		out = append(out, tagRef{name, v, r.Object})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].v.cmp(out[j].v) > 0 })
	return out, nil
}

// derefTag follows an annotated tag object (and nested tags) to a commit.
func (u *upstream) derefTag(ctx context.Context, sha string) (string, error) {
	if c, ok := u.tagDeref[sha]; ok {
		return c, nil
	}
	cur := sha
	for range 4 {
		var t struct {
			Object gitObject `json:"object"`
		}
		if err := u.get(ctx, "git/tags/"+cur, &t); err != nil {
			return "", err
		}
		if t.Object.Type == "commit" {
			u.tagDeref[sha] = t.Object.SHA
			return t.Object.SHA, nil
		}
		if t.Object.Type != "tag" {
			break
		}
		cur = t.Object.SHA
	}
	u.tagDeref[sha] = ""
	return "", nil
}

// tagsAt returns the vX.Y.Z tags that dereference to commit sha.
// Lightweight tags are matched directly. Annotated tags each cost a REST
// call, so they are tried in order — hinted names first, then newest
// version first among those accept allows — up to maxDeref calls.
func (u *upstream) tagsAt(ctx context.Context, tags []tagRef, sha string, hints []string, accept func(semver) bool, maxDeref int) (hits []tagRef, derefs int, err error) {
	for _, t := range tags {
		if t.obj.Type == "commit" && t.obj.SHA == sha {
			hits = append(hits, t)
		}
	}
	if len(hits) > 0 {
		return hits, 0, nil
	}
	var cands []tagRef
	seen := map[string]bool{}
	for _, h := range hints {
		for _, t := range tags {
			if t.name == h && t.obj.Type == "tag" && !seen[t.name] {
				cands = append(cands, t)
				seen[t.name] = true
			}
		}
	}
	for _, t := range tags {
		if t.obj.Type == "tag" && !seen[t.name] && (accept == nil || accept(t.v)) {
			cands = append(cands, t)
			seen[t.name] = true
		}
	}
	for _, t := range cands {
		if derefs >= maxDeref {
			break
		}
		if _, cached := u.tagDeref[t.obj.SHA]; !cached {
			derefs++
		}
		c, err := u.derefTag(ctx, t.obj.SHA)
		if err != nil {
			return nil, derefs, err
		}
		if c == sha {
			hits = append(hits, t)
			return hits, derefs, nil
		}
	}
	return nil, derefs, nil
}

// tagIs reports whether the vX.Y.Z tag name (from tags) dereferences to
// commit sha.
func (u *upstream) tagIs(ctx context.Context, tags []tagRef, name, sha string) (bool, error) {
	for _, t := range tags {
		if t.name != name {
			continue
		}
		switch t.obj.Type {
		case "commit":
			return t.obj.SHA == sha, nil
		case "tag":
			c, err := u.derefTag(ctx, t.obj.SHA)
			return c == sha, err
		}
		return false, nil
	}
	return false, nil
}

type release struct {
	TagName     string `json:"tag_name"`
	Draft       bool   `json:"draft"`
	Prerelease  bool   `json:"prerelease"`
	Immutable   bool   `json:"immutable"`
	Body        string `json:"body"`
	PublishedAt string `json:"published_at"`
	Author      struct {
		Login string `json:"login"`
	} `json:"author"`
}

// releaseFor returns the release for a tag, or nil when there is none
// visible (drafts are not visible to a read-only client).
func (u *upstream) releaseFor(ctx context.Context, tag string) (*release, error) {
	var r release
	if err := u.get(ctx, "releases/tags/"+url.PathEscape(tag), &r); err != nil {
		if errors.Is(err, gh.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &r, nil
}

// releaseAttestations counts release attestations whose subject is commit
// sha. The Sigstore bundle signatures are NOT verified here; this is a
// presence check for the provenance comparison.
func (u *upstream) releaseAttestations(ctx context.Context, sha string) (int, error) {
	var resp struct {
		Attestations []struct {
			Bundle struct {
				DSSEEnvelope struct {
					Payload string `json:"payload"`
				} `json:"dsseEnvelope"`
			} `json:"bundle"`
		} `json:"attestations"`
	}
	if err := u.get(ctx, "attestations/sha1:"+sha+"?per_page=100", &resp); err != nil {
		if errors.Is(err, gh.ErrNotFound) {
			return 0, nil
		}
		return 0, err
	}
	n := 0
	for _, a := range resp.Attestations {
		raw, err := base64.StdEncoding.DecodeString(a.Bundle.DSSEEnvelope.Payload)
		if err != nil {
			continue
		}
		var st struct {
			PredicateType string `json:"predicateType"`
			Subject       []struct {
				Digest map[string]string `json:"digest"`
			} `json:"subject"`
		}
		if json.Unmarshal(raw, &st) != nil || !strings.HasPrefix(st.PredicateType, "https://in-toto.io/attestation/release/") {
			continue
		}
		for _, s := range st.Subject {
			if s.Digest["sha1"] == sha {
				n++
				break
			}
		}
	}
	return n, nil
}

type commitVerification struct {
	Verified bool   `json:"verified"`
	Reason   string `json:"reason"`
}

func (u *upstream) commitVerification(ctx context.Context, sha string) (commitVerification, error) {
	var c struct {
		Verification commitVerification `json:"verification"`
	}
	err := u.get(ctx, "git/commits/"+sha, &c)
	return c.Verification, err
}

type advisory struct {
	GHSAID          string  `json:"ghsa_id"`
	Severity        string  `json:"severity"`
	Summary         string  `json:"summary"`
	WithdrawnAt     *string `json:"withdrawn_at"`
	Vulnerabilities []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		VulnerableVersionRange string `json:"vulnerable_version_range"`
	} `json:"vulnerabilities"`
}

var ghsaRx = regexp.MustCompile(`^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$`)

// advisories returns the reviewed GitHub advisories affecting
// owner/repo@version in the actions ecosystem.
func advisories(ctx context.Context, c fetch.GitHub, name, version string) ([]advisory, error) {
	var all []advisory
	q := "advisories?ecosystem=actions&per_page=100&affects=" + url.QueryEscape(name+"@"+version)
	if err := c.Get(ctx, q, &all); err != nil {
		return nil, err
	}
	var out []advisory
	for _, a := range all {
		if a.WithdrawnAt != nil {
			continue
		}
		for _, v := range a.Vulnerabilities {
			if strings.EqualFold(v.Package.Ecosystem, "actions") && fetch.SameName(model.GitHubActions, v.Package.Name, name) {
				out = append(out, a)
				break
			}
		}
	}
	return out, nil
}

// releaseBranchRx matches branches maintainers cut releases from:
// releases/v1, release/1.x, v4.
var releaseBranchRx = regexp.MustCompile(`^(releases?/[A-Za-z0-9._-]+|v[0-9]+(\.[0-9x]+)*)$`)

// onReleaseBranch reports the first default or release branch that
// contains sha (compare status behind/identical).
func (u *upstream) onReleaseBranch(ctx context.Context, def, sha string) (string, error) {
	ok, err := u.contains(ctx, def, sha)
	if err != nil {
		return "", err
	}
	if ok {
		return def, nil
	}
	var branches []struct {
		Name string `json:"name"`
	}
	if err := u.get(ctx, "branches?per_page=100", &branches); err != nil {
		return "", err
	}
	checked := 0
	for _, b := range branches {
		if b.Name == def || !releaseBranchRx.MatchString(b.Name) {
			continue
		}
		if checked++; checked > 10 {
			break
		}
		ok, err := u.contains(ctx, b.Name, sha)
		if err != nil {
			return "", err
		}
		if ok {
			return b.Name, nil
		}
	}
	return "", nil
}

func (u *upstream) contains(ctx context.Context, branch, sha string) (bool, error) {
	c, err := u.compare(ctx, branch, sha, 1)
	if err != nil {
		if errors.Is(err, gh.ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	return c.Status == "behind" || c.Status == "identical", nil
}

func itoa(n int) string { return strconv.Itoa(n) }
