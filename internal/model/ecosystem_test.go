package model

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseEcosystems(t *testing.T) {
	for _, tt := range []struct {
		in   string
		want map[Ecosystem]bool
		err  string
	}{
		{"", nil, ""},
		{"  ", nil, ""},
		{"submodules", map[Ecosystem]bool{GitSubmodule: true}, ""},
		{" submodules , docker,submodules", map[Ecosystem]bool{GitSubmodule: true, Docker: true}, ""},
		{"go_modules,npm_and_yarn,uv,github_actions", map[Ecosystem]bool{GoModules: true, NPM: true, UV: true, GitHubActions: true}, ""},
		// dependabot.yml's package-ecosystem names are not branch names.
		{"gitsubmodule", nil, `unknown ecosystem "gitsubmodule"`},
		{"gomod", nil, "unknown ecosystem"},
		{"Submodules", nil, "unknown ecosystem"},
		{"*", nil, "unknown ecosystem"},
		{"submodules,", nil, `unknown ecosystem ""`},
		{",submodules", nil, "unknown ecosystem"},
		{"submodules,,docker", nil, "unknown ecosystem"},
		{"submodules docker", nil, "unknown ecosystem"},
	} {
		got, err := ParseEcosystems(tt.in)
		switch {
		case tt.err != "":
			if err == nil || !strings.Contains(err.Error(), tt.err) {
				t.Errorf("%q: err %v, want %q", tt.in, err, tt.err)
			} else if !strings.Contains(err.Error(), "submodules, uv") {
				t.Errorf("%q: error does not list the valid names: %v", tt.in, err)
			}
			if got != nil {
				t.Errorf("%q: got %v with an error", tt.in, got)
			}
		case err != nil:
			t.Errorf("%q: %v", tt.in, err)
		case !reflect.DeepEqual(got, tt.want):
			t.Errorf("%q: got %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestEcosystemFromBranch(t *testing.T) {
	for ref, want := range map[string]Ecosystem{
		"dependabot/submodules/tools/upstream/adblock-lists-9778b88": GitSubmodule,
		"dependabot/go_modules/aws-1c8ebe5c54":                       GoModules,
		"dependabot/cargo/x-1":                                       "",
		"dependabot/submodules":                                      "",
		"feature/submodules/x":                                       "",
		"":                                                           "",
	} {
		got, ok := EcosystemFromBranch(ref)
		if got != want || ok != (want != "") {
			t.Errorf("%q: %q %v, want %q", ref, got, ok, want)
		}
	}
}
