package fetch_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
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
			updates, findings := fetch.CompareDeclared(tt.declared, real)
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

	updates, _ := fetch.CompareDeclared([]model.Update{{Name: "lodash", To: "4.17.21", Security: true, Advisory: []string{"GHSA-xxxx"}}}, real)
	if !updates[2].Security || !slices.Equal(updates[2].Advisory, []string{"GHSA-xxxx"}) || real[2].Security {
		t.Errorf("security not carried over (or real mutated): %+v / %+v", updates[2], real[2])
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
		{"placeholder", model.Docker, model.KindDependabot, fetch.Registry{model.Docker: fetch.NotVerified{}}, model.RouteHuman, []string{"ecosystem.not-verified"}, false},
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
