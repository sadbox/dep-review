// Package publish turns the jobs' artifacts into a deterministic decision
// and acts on it: one PR comment, the `dep-review` commit status, a merge
// of the exact classified head once CI is green, and notifications. It
// also implements sweep. No model or dependency text reaches a
// notification, and the only model text in a comment is the sanitized
// summary (SanitizeSummary), on every repository.
package publish

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/sadbox/dep-review/internal/model"
	"github.com/sadbox/dep-review/internal/policy"
)

// Commit status states.
const (
	StateSuccess = "success"
	StateFailure = "failure"
	StateError   = "error"
)

// Inputs are the artifacts publish reads. Evidence and Verdict are nil
// when the job did not produce them.
type Inputs struct {
	Class        model.Classification
	Evidence     *model.Evidence
	Verdict      []byte
	FetchResult  string // needs.fetch.result
	ReviewResult string // needs.review.result
}

// Outcome is the decision and everything rendered from it.
type Outcome struct {
	Decision model.Decision
	Route    model.Route    // "" when there is no evidence
	State    string         // commit status state; "" for DecisionIgnore
	Reason   string         // one line in the gate's own words: safe for notifications
	Codes    []string       // finding codes that forced the route
	Verdict  *model.Verdict // set when a verdict parsed and validated
}

var (
	codeRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	resultRe = map[string]bool{"success": true, "failure": true, "cancelled": true, "skipped": true}
)

func jobResult(s string) string {
	if resultRe[s] {
		return s
	}
	return "unknown"
}

var knownRoute = map[model.Route]int{model.RouteAuto: 0, model.RouteReview: 1, model.RouteHuman: 2, model.RouteRefuse: 3}

// worse is model.Worse, except that an unknown route counts as refuse
// (model.Worse ranks it like auto).
func worse(a, b model.Route) model.Route {
	if _, ok := knownRoute[a]; !ok {
		a = model.RouteRefuse
	}
	if _, ok := knownRoute[b]; !ok {
		b = model.RouteRefuse
	}
	if knownRoute[b] > knownRoute[a] {
		return b
	}
	return a
}

// effectiveRoute recomputes the route from the evidence's own updates and
// findings and takes the worse of that and what fetch recorded.
func effectiveRoute(ev *model.Evidence) (model.Route, []string) {
	findings := make([]model.Finding, len(ev.Findings))
	copy(findings, ev.Findings)
	for i := range findings {
		if _, ok := knownRoute[findings[i].Route]; !ok {
			findings[i].Route = model.RouteRefuse
		}
	}
	r := worse(ev.Route, policy.Combine(ev.Updates, findings, ev.Truncated))
	var codes []string
	seen := map[string]bool{}
	for _, f := range findings {
		if knownRoute[f.Route] < knownRoute[model.RouteHuman] {
			continue
		}
		c := f.Code
		if !codeRe.MatchString(c) {
			c = "unnamed-finding"
		}
		if !seen[c] {
			seen[c] = true
			codes = append(codes, c)
		}
	}
	return r, codes
}

// Decide is the gate's final, deterministic decision.
func Decide(in Inputs) Outcome {
	c := in.Class
	switch c.Kind {
	case model.KindOther, model.KindStale:
		return Outcome{Decision: model.DecisionIgnore, Reason: "not a current Dependabot pull request"}
	case model.KindIgnored:
		// gate.yml does not run publish for these; this is the backstop.
		return Outcome{Decision: model.DecisionIgnore, Reason: "its ecosystem is in ignore_ecosystems"}
	case model.KindDependabotUnverified:
		return human("", "not verified as Dependabot's alone", nil)
	case model.KindPending:
		// No status, no comment, no notification: sweep classifies the
		// PR again and reports it if it stays undecided.
		return Outcome{Decision: model.DecisionPending, Reason: "the branch's push history has not caught up with the head yet"}
	case model.KindDependabot:
	default:
		return human("", "unknown classification", nil)
	}
	ev := in.Evidence
	if ev != nil && ev.Route == model.RouteRefuse {
		_, codes := effectiveRoute(ev)
		return human(model.RouteRefuse, "the gate refused this pull request"+codeList(codes), codes)
	}
	if fr := jobResult(in.FetchResult); fr != "success" || ev == nil {
		reason := "the evidence job did not finish (" + fr + ")"
		if fr == "success" {
			reason = "the evidence job produced no evidence"
		}
		return Outcome{Decision: model.DecisionPending, State: StateError, Reason: reason}
	}
	if ev.Classification.HeadSHA != c.HeadSHA || ev.Classification.PR != c.PR || ev.Classification.Repo != c.Repo {
		return human("", "the evidence is for a different pull request or head", nil)
	}
	route, codes := effectiveRoute(ev)
	switch route {
	case model.RouteAuto:
		return Outcome{Decision: model.DecisionMerge, Route: route, State: StateSuccess,
			Reason: "every update is a proven no-op; merging when CI is green"}
	case model.RouteReview:
		if rr := jobResult(in.ReviewResult); rr != "success" || in.Verdict == nil {
			return human(route, "the review produced no verdict ("+rr+")", nil)
		}
		v, err := ParseVerdict(in.Verdict)
		if err != nil {
			return human(route, "the review's verdict failed validation", nil)
		}
		o := human(route, "", nil)
		o.Verdict = &v
		accounted, why := accounting(ev.Flagged, v.Items)
		switch {
		case v.Verdict != model.Pass:
			o.Reason = "the reviewer answered " + string(v.Verdict)
		case len(v.Flags) > 0:
			o.Reason = "the reviewer answered pass but raised flags"
		case !accounted:
			o.Reason = why
		default:
			o.Decision, o.State = model.DecisionMerge, StateSuccess
			o.Reason = "checks passed and the reviewer approved; merging when CI is green"
		}
		return o
	case model.RouteHuman:
		why := "needs a person"
		if ev.Truncated {
			why = "the evidence was truncated"
		} else if len(codes) == 0 {
			why = "the version policy needs a person (major or 0.x update)"
		}
		return human(route, why+codeList(codes), codes)
	}
	return human(model.RouteRefuse, "the gate refused this pull request"+codeList(codes), codes)
}

func human(route model.Route, reason string, codes []string) Outcome {
	return Outcome{Decision: model.DecisionHuman, Route: route, State: StateFailure, Reason: reason, Codes: codes}
}

func codeList(codes []string) string {
	if len(codes) == 0 {
		return ""
	}
	if len(codes) > 5 {
		return fmt.Sprintf(": %s and %d more", strings.Join(codes[:5], ", "), len(codes)-5)
	}
	return ": " + strings.Join(codes, ", ")
}
