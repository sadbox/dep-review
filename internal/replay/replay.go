// Package replay decides recorded pull requests offline: the tool for
// measuring a change of policy, or of a gatherer's reading of files,
// before shipping it.
//
// A pull request is recorded as one JSON file (Record). For each one the
// replay runs the real first half of its ecosystem's gatherer, which
// reads the change set and the Shape fact from the files at the base and
// head commits, and then the real allow.Decide. Nothing is asked of any
// network, so every fact whose source is a registry or GitHub is a
// stand-in, and always the favourable one:
//
//   - Identity holds unless the record says others pushed to the branch,
//     and ChecksConfigured holds;
//   - Bound, Clean and NoRegress hold, and no update is a security fix,
//     wherever the gatherer did not settle the fact from the files;
//   - FirstSeen is the time the pull request was created, which is the
//     gate's own fallback clock (docs/v0.2-spec.md, section 11,
//     amendment 4);
//   - NameCreated, for a new name that is not listed, is Options.NameCreated,
//     or not established when that is the zero time;
//   - every update was read in full (for Docker there is nothing to
//     read), and nothing was vetoed.
//
// So the outcome is an upper bound on what the gate would merge: a pull
// request that goes to a person here goes to a person in the gate, and
// one that merges here merges only if the registries, the advisory
// database and the model agree. The replay never sees a hash that does
// not match, a retracted or young version, a new install script, a tag
// off its branch, an action pinned without an actions.lock entry, a read
// that was partial, or a veto.
package replay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/facts"
	"github.com/sadbox/dep-review/internal/facts/actions"
	"github.com/sadbox/dep-review/internal/facts/docker"
	"github.com/sadbox/dep-review/internal/facts/gomod"
	"github.com/sadbox/dep-review/internal/facts/npm"
)

// Record is one recorded pull request: the content of one JSON file. The
// file's name, without ".json", is the name the pull request is printed
// under. A key this type does not have is an error.
type Record struct {
	// Ecosystem is the gate's name for the pull request's ecosystem, which
	// is its key in the policy list: go_modules, npm, github_actions or
	// docker. Anything else is an ecosystem without a rule.
	Ecosystem string `json:"ecosystem"`
	// Created is when the pull request was created (RFC 3339).
	Created time.Time `json:"created"`
	// OthersPushed says someone other than Dependabot pushed to the
	// branch, so Identity does not hold. Left out, Identity holds.
	OthersPushed bool `json:"others_pushed"`
	// Files is every path that differs between the merge base and the
	// head commit, not only the manifests: Shape is about there being no
	// others.
	Files []File `json:"files"`
}

// File is one changed path of a Record, as it is at both commits.
type File struct {
	// Path is relative to the repository root, with "/" separators.
	Path string `json:"path"`
	// BaseMode and HeadMode are git's file modes ("100644" for an
	// ordinary file). Empty or left out means the path does not exist at
	// that commit.
	BaseMode string `json:"base_mode"`
	HeadMode string `json:"head_mode"`
	// Base and Head are the file's content at the two commits, as text.
	// They may be left out for a path that is no manifest or lock file:
	// every gatherer refuses such a path by its name.
	Base string `json:"base"`
	Head string `json:"head"`
}

// Options are what one run is measured with.
type Options struct {
	// Policy is the policy to decide with.
	Policy allow.Policy
	// Now is the clock: the moment every pull request is decided at. It
	// only moves a pull request between wait and merge.
	Now time.Time
	// NameCreated stands in for when every new, unlisted name was
	// created. The zero time leaves that unknown, which is person.
	NameCreated time.Time
}

// Result is the replay of one record.
type Result struct {
	// Name is the record's file name without ".json".
	Name string
	// Ecosystem and Created are the record's.
	Ecosystem string
	Created   time.Time
	// Shape is the gatherer's Shape fact; not gathered when the gate
	// would not have gathered it either.
	Shape allow.Fact
	// Decision is allow.Decide's answer.
	Decision allow.Decision
}

// The sources of the facts the replay supplies itself.
const (
	standIn      = "replay stand-in"
	recordSource = "the record"
	// openedSource is the gate's own name for its first-seen fallback.
	openedSource = "pull request opened"
)

// Run replays every *.json file in dir, in the order of their names.
//
// An error means there is no result: the directory or a record could not
// be read, or npm is needed and cannot be run. A pull request the gate
// would refuse is not an error; it is a Result that says person.
func Run(ctx context.Context, dir string, opt Options) ([]Result, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var results []Result
	for _, e := range entries {
		name, isRecord := strings.CutSuffix(e.Name(), ".json")
		if e.IsDir() || !isRecord {
			continue
		}
		rec, err := readRecord(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("replay: %s: %w", e.Name(), err)
		}
		res, err := Decide(ctx, rec, opt)
		if err != nil {
			return nil, fmt.Errorf("replay: %s: %w", e.Name(), err)
		}
		res.Name = name
		results = append(results, res)
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("replay: %s holds no record (*.json)", dir)
	}
	return results, nil
}

// readRecord decodes one record strictly: one JSON object, known keys
// only, with an ecosystem and a creation time.
func readRecord(path string) (Record, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Record{}, err
	}
	var rec Record
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rec); err != nil {
		return Record{}, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return Record{}, errors.New("more than one JSON value")
	}
	if rec.Ecosystem == "" || rec.Created.IsZero() {
		return Record{}, errors.New("the record needs an ecosystem and a created time")
	}
	return rec, nil
}

// Decide replays one record. Result.Name is left for the caller.
//
// It follows the fetch job: for a pull request that is not Dependabot's
// alone, and in an ecosystem without a rule, nothing is gathered at all.
func Decide(ctx context.Context, rec Record, opt Options) (Result, error) {
	pr := allow.PRFacts{
		Ecosystem:        rec.Ecosystem,
		Identity:         allow.Yes("taken to be Dependabot's alone", standIn),
		ChecksConfigured: allow.Yes("taken to be configured", standIn),
		Opened:           rec.Created,
	}
	if rec.OthersPushed {
		pr.Identity = allow.No("someone other than Dependabot pushed to the branch", recordSource)
	}
	if pr.Identity.Holds() && allow.HasRule(rec.Ecosystem) {
		res, err := changes(ctx, rec, opt.Policy)
		if err != nil {
			return Result{}, err
		}
		pr.Shape = res.Shape
		for _, u := range res.Updates {
			pr.Updates = append(pr.Updates, withStandIns(u, rec, opt))
		}
	}
	return Result{
		Ecosystem: rec.Ecosystem,
		Created:   rec.Created,
		Shape:     pr.Shape,
		Decision:  allow.Decide(pr, opt.Policy, opt.Now),
	}, nil
}

// changes runs the half of the ecosystem's gatherer that reads only the
// pull request's files.
func changes(ctx context.Context, rec Record, policy allow.Policy) (facts.Result, error) {
	files := make([]facts.File, len(rec.Files))
	for i, f := range rec.Files {
		files[i] = facts.File{Path: f.Path, BaseMode: f.BaseMode, HeadMode: f.HeadMode}
		// A path that does not exist at a commit has no content there,
		// whatever the record says.
		if f.BaseMode != "" {
			files[i].Base = []byte(f.Base)
		}
		if f.HeadMode != "" {
			files[i].Head = []byte(f.Head)
		}
	}
	switch rec.Ecosystem {
	case allow.GoModules:
		return gomod.Changes(files, policy), nil
	case allow.NPM:
		// npm itself reads the two locks, offline.
		return npm.Gatherer{}.Changes(ctx, files, policy)
	case allow.GitHubActions:
		return actions.Changes(files, policy), nil
	case allow.Docker:
		return docker.Changes(files, policy), nil
	}
	return facts.Result{}, fmt.Errorf("no gatherer for %q", rec.Ecosystem)
}

// withStandIns completes an update the gatherer read from the files with
// the favourable answer for every fact it left unset.
func withStandIns(u allow.UpdateFacts, rec Record, opt Options) allow.UpdateFacts {
	for _, f := range []*allow.Fact{&u.Bound, &u.Clean, &u.NoRegress} {
		if *f == (allow.Fact{}) {
			*f = allow.Yes("taken to hold", standIn)
		}
	}
	if u.SecurityFix == (allow.Fact{}) {
		u.SecurityFix = allow.No("taken not to be a security fix", standIn)
	}
	u.FirstSeen = allow.At(rec.Created, openedSource)
	if !opt.NameCreated.IsZero() && u.NewName.Holds() && !u.Listed.Holds() {
		u.NameCreated = allow.At(opt.NameCreated, standIn)
	}
	u.Read = allow.ReadFull
	if rec.Ecosystem == allow.Docker {
		u.Read = allow.ReadNotApplicable
	}
	return u
}

// Print writes one line for each result and then the totals for each
// ecosystem.
//
// A line has five tab-separated fields: the name, the ecosystem, the
// outcome, the reasons (comma-separated, "-" for a merge) and a detail.
// For a merge or a wait the detail is the age the pull request needs,
// counted from its creation. For a person it is the Shape fact's value
// when Shape does not hold, and otherwise each update that sends the pull
// request to a person, with that update's reasons, or "-" when the
// reasons are all the pull request's own.
func Print(w io.Writer, results []Result) error {
	type count struct{ total, merge, wait, person int }
	counts := map[string]*count{}
	all := &count{}
	for _, r := range results {
		d := r.Decision
		reasons := make([]string, len(d.Reasons))
		for i, reason := range d.Reasons {
			reasons[i] = string(reason)
		}
		if len(reasons) == 0 {
			reasons = []string{"-"}
		}
		if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			oneLine(r.Name), oneLine(r.Ecosystem), d.Outcome, strings.Join(reasons, ","), oneLine(detail(r))); err != nil {
			return err
		}
		c := counts[r.Ecosystem]
		if c == nil {
			c = &count{}
			counts[r.Ecosystem] = c
		}
		for _, n := range []*count{c, all} {
			n.total++
			switch d.Outcome {
			case allow.Merge:
				n.merge++
			case allow.Wait:
				n.wait++
			default:
				n.person++
			}
		}
	}

	ecosystems := make([]string, 0, len(counts))
	for e := range counts {
		ecosystems = append(ecosystems, e)
	}
	sort.Strings(ecosystems)
	const row = "%-16s %5v %5v %5v %6v\n"
	if _, err := fmt.Fprintf(w, "\n"+row, "ecosystem", "total", "merge", "wait", "person"); err != nil {
		return err
	}
	for _, e := range ecosystems {
		c := counts[e]
		if _, err := fmt.Fprintf(w, row, oneLine(e), c.total, c.merge, c.wait, c.person); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(w, row, "all", all.total, all.merge, all.wait, all.person)
	return err
}

// detail is the last field of a result's line (see Print).
func detail(r Result) string {
	d := r.Decision
	if d.Outcome != allow.Person {
		return fmt.Sprintf("needs %.0fh after creation", d.NotBefore.Sub(r.Created).Hours())
	}
	if r.Shape.Gathered() && !r.Shape.OK {
		return "shape: " + r.Shape.Value
	}
	var parts []string
	for _, u := range d.PerUpdate {
		if u.Outcome != allow.Person {
			continue
		}
		reasons := make([]string, len(u.Reasons))
		for i, reason := range u.Reasons {
			reasons[i] = string(reason)
		}
		from := u.From
		if from == "" {
			from = "(new)"
		}
		parts = append(parts, fmt.Sprintf("%s %s -> %s: %s", u.Name, from, u.To, strings.Join(reasons, ",")))
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, "; ")
}

// oneLine keeps text a record supplied (a name, a path, a version) from
// breaking the line it is printed on.
func oneLine(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
}
