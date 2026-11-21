package fetch_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sadbox/dep-review/internal/evidence"
	"github.com/sadbox/dep-review/internal/fetch"
	"github.com/sadbox/dep-review/internal/model"
)

func TestCompareDeclared(t *testing.T) {
	real := []model.Update{
		{Name: "github.com/a/b", Directory: "/", From: "v1.0.0", To: "v1.0.1", Type: model.Patch, Direct: true},
		{Name: "github.com/c/d", Directory: "/", From: "v2.0.0", To: "v2.1.0", Type: model.Minor},
		{Name: "lodash", Directory: "/web", From: "4.17.20", To: "4.17.21", Type: model.Patch},
	}
	tests := []struct {
		name     string
		declared []model.Update
		want     []string
	}{
		{"exact, Dependabot drops the v", []model.Update{{Name: "github.com/a/b", From: "1.0.0", To: "1.0.1", Directory: "/"}}, nil},
		{"no directory declared", []model.Update{{Name: "lodash", From: "4.17.20", To: "4.17.21"}}, nil},
		{"directory differs", []model.Update{{Name: "lodash", To: "4.17.21", Directory: "/"}}, []string{"declared.missing"}},
		{"not in change set", []model.Update{{Name: "github.com/x/y", To: "1.0.0"}}, []string{"declared.missing"}},
		{"different target", []model.Update{{Name: "github.com/a/b", From: "1.0.0", To: "1.0.2"}}, []string{"declared.to-mismatch"}},
		{"different from", []model.Update{{Name: "github.com/a/b", From: "0.9.0", To: "1.0.1"}}, []string{"declared.from-mismatch"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			updates, findings := fetch.CompareDeclared(model.GoModules, tt.declared, real)
			var codes []string
			for _, f := range findings {
				codes = append(codes, f.Code)
			}
			if !slices.Equal(codes, tt.want) {
				t.Errorf("codes = %q, want %q", codes, tt.want)
			}
			if len(updates) != len(real) {
				t.Errorf("updates changed length: %d", len(updates))
			}
		})
	}

	// The docker fetcher's view of a digest bump (towngear#51) and of an
	// untagged pin; Dependabot declares the tag plus abbreviated digests.
	const (
		dgOld = "sha256:01aa404fa56b604b6f48e90c1d6e2c79fe5cd78f9592f78d80303fbe171cdcc0"
		dgNew = "sha256:205c7636d74e0ffbe3d007162df7d74f859f5a8c8322dfb9f907977686c126cf"
	)
	docker := []model.Update{
		{Name: "golang", Directory: "/", From: "1.27", To: "1.27", FromRef: dgOld, ToRef: dgNew, Type: model.Digest},
		{Name: "busybox", Directory: "/", From: dgOld, To: dgNew, FromRef: dgOld, ToRef: dgNew, Type: model.Unknown},
	}
	dockerTests := []struct {
		name     string
		declared model.Update
		want     []string
	}{
		{"digest bump", model.Update{Name: "golang", To: "1.27", FromRef: "01aa404", ToRef: "205c763"}, nil},
		{"digest bump, other new digest", model.Update{Name: "golang", To: "1.27", FromRef: "01aa404", ToRef: "205c764"}, []string{"declared.to-mismatch"}},
		{"digest bump, other old digest", model.Update{Name: "golang", To: "1.27", FromRef: "01aa405", ToRef: "205c763"}, []string{"declared.from-mismatch"}},
		{"digest bump, other tag", model.Update{Name: "golang", To: "1.28", FromRef: "01aa404", ToRef: "205c763"}, []string{"declared.to-mismatch"}},
		{"digest too short to compare", model.Update{Name: "golang", To: "1.27", ToRef: "205c"}, []string{"declared.to-mismatch"}},
		{"untagged pin, version is the digest", model.Update{Name: "busybox", To: strings.TrimPrefix(dgNew, "sha256:"), FromRef: "01aa404", ToRef: "205c763"}, nil},
		{"untagged pin, other digest", model.Update{Name: "busybox", To: "205c763ff"}, []string{"declared.to-mismatch"}},
		{"nothing declared for the target", model.Update{Name: "golang", FromRef: "01aa404"}, []string{"declared.to-mismatch"}},
	}
	for _, tt := range dockerTests {
		t.Run(tt.name, func(t *testing.T) {
			var same []model.Update // only the declared image: anything else is undeclared
			for _, u := range docker {
				if u.Name == tt.declared.Name {
					same = append(same, u)
				}
			}
			_, findings := fetch.CompareDeclared(model.Docker, []model.Update{tt.declared}, same)
			var codes []string
			for _, f := range findings {
				codes = append(codes, f.Code)
			}
			if !slices.Equal(codes, tt.want) {
				t.Errorf("codes = %q, want %q (%+v)", codes, tt.want, findings)
			}
		})
	}

	updates, _ := fetch.CompareDeclared(model.NPM, []model.Update{{Name: "lodash", To: "4.17.21", Security: true, Advisory: []string{"GHSA-xxxx"}}}, real)
	if !updates[2].Security || !slices.Equal(updates[2].Advisory, []string{"GHSA-xxxx"}) || real[2].Security {
		t.Errorf("security not carried over (or real mutated): %+v / %+v", updates[2], real[2])
	}
}

// Actions and Docker have no transitive updates: anything Dependabot did
// not declare is a change someone slipped in and needs a person, not a
// model review. Lockfile ecosystems keep reviewing undeclared updates.
func TestCompareDeclaredUndeclared(t *testing.T) {
	const (
		shaOld  = "1111111111111111111111111111111111111111"
		shaNew  = "2222222222222222222222222222222222222222"
		shaEvil = "3333333333333333333333333333333333333333"
	)
	checkout := func(dir, to, ref string) model.Update {
		return model.Update{Name: "actions/checkout", Directory: dir, From: "v7.0.0", To: to, FromRef: shaOld, ToRef: ref, Type: model.Patch, Direct: true}
	}
	decl := []model.Update{{Name: "actions/checkout", From: "7.0.0", To: "7.0.1", FromRef: shaOld[:7], ToRef: shaNew[:7]}}
	tests := []struct {
		name string
		eco  model.Ecosystem
		real []model.Update
		want []string
	}{
		{"declared only", model.GitHubActions, []model.Update{checkout("/", "v7.0.1", shaNew)}, nil},
		{"same action in two workflows", model.GitHubActions, []model.Update{checkout("/", "v7.0.1", shaNew), checkout("/", "v7.0.1", shaNew)}, nil},
		{"second copy to another commit", model.GitHubActions, []model.Update{checkout("/", "v7.0.1", shaNew), checkout("/", "v7.0.1", shaEvil)}, []string{"undeclared.update"}},
		{"another action", model.GitHubActions, []model.Update{checkout("/", "v7.0.1", shaNew), {Name: "evil/action", Directory: "/", From: "v1", To: "v1.0.1", FromRef: shaOld, ToRef: shaEvil, Type: model.Patch, Direct: true}}, []string{"undeclared.update"}},
		{"docker: another image", model.Docker, []model.Update{
			{Name: "actions/checkout", Directory: "/", From: "v7.0.0", To: "v7.0.1", FromRef: shaOld, ToRef: shaNew},
			{Name: "golang", Directory: "/", From: "1.27", To: "1.27", Type: model.Digest, NoOp: true},
		}, []string{"undeclared.update"}},
		{"go: transitive updates are reviewed", model.GoModules, []model.Update{
			{Name: "actions/checkout", Directory: "/", From: "v7.0.0", To: "v7.0.1", FromRef: shaOld, ToRef: shaNew},
			{Name: "golang.org/x/sys", Directory: "/", From: "v0.1.0", To: "v0.2.0"},
		}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, findings := fetch.CompareDeclared(tt.eco, decl, tt.real)
			var codes []string
			for _, f := range findings {
				codes = append(codes, f.Code)
				if f.Code == "undeclared.update" && f.Route != model.RouteHuman {
					t.Errorf("route %s", f.Route)
				}
			}
			if !slices.Equal(codes, tt.want) {
				t.Errorf("codes = %q, want %q (%+v)", codes, tt.want, findings)
			}
		})
	}
}

func TestNewDependencies(t *testing.T) {
	f := fetch.NewDependencies([]model.Update{{Name: "a", From: "1", To: "2"}, {Name: "b", To: "1.0.0"}})
	if len(f) != 1 || f[0].Code != "new-dependency" || f[0].Route != model.RouteHuman || f[0].Update != "b" {
		t.Errorf("findings = %+v", f)
	}
}

type fakeEco struct {
	res fetch.Result
	err error
}

func (f fakeEco) Fetch(_ context.Context, env fetch.Env) (fetch.Result, error) {
	if err := env.Evidence.AddUntrusted("x/diff", "a diff", []byte("+x\n")); err != nil {
		return fetch.Result{}, err
	}
	return f.res, f.err
}

func TestRun(t *testing.T) {
	patch := model.Update{Ecosystem: model.GoModules, Name: "m", From: "v1.0.0", To: "v1.0.1", Type: model.Patch, Directory: "/"}
	tests := []struct {
		name      string
		eco       model.Ecosystem
		kind      model.Kind
		reg       fetch.Registry
		wantRoute model.Route
		wantCodes []string
		wantErr   bool
	}{
		{"clean patch", model.GoModules, model.KindDependabot, fetch.Registry{model.GoModules: fakeEco{res: fetch.Result{Updates: []model.Update{patch}}}}, model.RouteReview, nil, false},
		{"finding wins", model.GoModules, model.KindDependabot, fetch.Registry{model.GoModules: fakeEco{res: fetch.Result{
			Updates: []model.Update{patch}, Findings: []model.Finding{{Code: "x", Route: model.RouteRefuse}}}}}, model.RouteRefuse, []string{"x"}, false},
		{"no updates", model.GoModules, model.KindDependabot, fetch.Registry{model.GoModules: fakeEco{}}, model.RouteRefuse, []string{"declared.missing"}, false},
		{"unknown ecosystem", "pip", model.KindDependabot, fetch.Registry{}, model.RouteHuman, []string{"ecosystem.unknown"}, false},
		{"infra error", model.GoModules, model.KindDependabot, fetch.Registry{model.GoModules: fakeEco{err: errors.New("proxy down")}}, "", nil, true},
		{"not dependabot", model.GoModules, model.KindDependabotUnverified, fetch.Registry{}, "", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "ev")
			ev, err := evidence.Create(out)
			if err != nil {
				t.Fatal(err)
			}
			defer ev.Close()
			class := model.Classification{Kind: tt.kind, Ecosystem: tt.eco, Declared: []model.Update{{Name: "m", From: "1.0.0", To: "1.0.1", Type: model.Patch}}}
			got, err := fetch.Run(context.Background(), fetch.Env{Class: class}, tt.reg, ev)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			var codes []string
			for _, f := range got.Findings {
				codes = append(codes, f.Code)
			}
			if got.Route != tt.wantRoute || !slices.Equal(codes, tt.wantCodes) {
				t.Errorf("route %s codes %q; want %s %q", got.Route, codes, tt.wantRoute, tt.wantCodes)
			}
			b, err := os.ReadFile(filepath.Join(out, "evidence.json"))
			if err != nil {
				t.Fatal(err)
			}
			var back model.Evidence
			if err := json.Unmarshal(b, &back); err != nil || back.Route != got.Route {
				t.Errorf("evidence.json: %v route %s", err, back.Route)
			}
		})
	}
}
