package fetch_test

import (
	"slices"
	"testing"

	"github.com/sadbox/dep-review/internal/fetch"
	"github.com/sadbox/dep-review/internal/model"
)

func TestSameName(t *testing.T) {
	tests := []struct {
		eco  model.Ecosystem
		a, b string
		want bool
	}{
		{model.GitHubActions, "Docker/Login-Action", "docker/login-action", true},
		{model.GitHubActions, "docker/login-action", "docker/login_action", false},
		{model.GitSubmodule, "Vendor/Lib", "vendor/lib", true},
		{model.UV, "Ruamel.YAML", "ruamel-yaml", true},
		{model.UV, "zope__interface", "zope.interface", true},
		{model.UV, "a-._b", "a-b", true},
		{model.UV, "ab", "a-b", false},
		{model.GoModules, "github.com/BurntSushi/toml", "github.com/burntsushi/toml", false},
		{model.NPM, "Lodash", "lodash", false},
		{model.NPM, "@types/node", "@types/node", true},
		{model.Docker, "Golang", "golang", false},
		{"pip", "A", "a", false},
	}
	for _, tt := range tests {
		if got := fetch.SameName(tt.eco, tt.a, tt.b); got != tt.want {
			t.Errorf("SameName(%s, %q, %q) = %v, want %v", tt.eco, tt.a, tt.b, got, tt.want)
		}
	}
}

// Dependabot's declared name and the fetcher's spelling can differ only
// where the ecosystem says they are the same name.
func TestCompareDeclaredNames(t *testing.T) {
	tests := []struct {
		eco        model.Ecosystem
		real, decl string
		want       []string
	}{
		{model.GitHubActions, "Docker/login-action", "docker/login-action", nil},
		{model.UV, "ruamel-yaml", "ruamel.yaml", nil},
		{model.GoModules, "github.com/BurntSushi/toml", "github.com/burntsushi/toml", []string{"declared.missing"}},
		{model.NPM, "Lodash", "lodash", []string{"declared.missing"}},
	}
	for _, tt := range tests {
		real := []model.Update{{Name: tt.real, Directory: "/", From: "1.0.0", To: "1.0.1"}}
		_, findings := fetch.CompareDeclared(tt.eco, []model.Update{{Name: tt.decl, From: "1.0.0", To: "1.0.1"}}, real)
		var codes []string
		for _, f := range findings {
			codes = append(codes, f.Code)
		}
		if !slices.Equal(codes, tt.want) {
			t.Errorf("%s %q vs %q: codes %q, want %q", tt.eco, tt.real, tt.decl, codes, tt.want)
		}
	}
}
