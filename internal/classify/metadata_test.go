package classify

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

// Real commit messages from merged Dependabot PRs (testdata/msg_*.txt).
func TestParseDeclaredReal(t *testing.T) {
	tests := []struct {
		file string
		want []Declared
		dir  string
	}{
		{"msg_sadbox_towngear_51.txt", []Declared{{Name: "golang", Version: "1.27", DepType: "direct:production", UpdateType: "version-update:semver-patch", Group: "docker", From: "01aa404"}}, ""},
		{"msg_sadbox_towngear_53.txt", []Declared{{Name: "actions/setup-go", Version: "7.1.0", DepType: "direct:production", UpdateType: "version-update:semver-minor", From: "7.0.0"}}, ""},
		{"msg_sadbox_oncall-sync_87.txt", []Declared{{Name: "actions/setup-go", Version: "7.1.0", DepType: "direct:production", UpdateType: "version-update:semver-minor", From: "7.0.0"}}, ""},
		{"msg_sadbox_oncall-sync_88.txt", []Declared{{Name: "golang", Version: "1.27.4", DepType: "direct:production", UpdateType: "version-update:semver-patch", Group: "docker", From: "1.27.3"}}, ""},
		{"msg_Espresso-Aficionados_sprobot_285.txt", []Declared{{Name: "github.com/aws/aws-sdk-go-v2/credentials", Version: "1.21.1", DepType: "direct:production", UpdateType: "version-update:semver-patch", Group: "aws", From: "1.21.0"}}, ""},
		{"msg_Espresso-Aficionados_sprobot_281.txt", []Declared{
			{Name: "github.com/aws/aws-sdk-go-v2/credentials", Version: "1.21.0", DepType: "direct:production", UpdateType: "version-update:semver-minor", Group: "aws", From: "1.20.17"},
			{Name: "github.com/aws/aws-sdk-go-v2/service/s3", Version: "1.114.10", DepType: "direct:production", UpdateType: "version-update:semver-patch", Group: "aws", From: "1.114.9"},
		}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			b, err := os.ReadFile("testdata/" + tt.file)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ParseDeclared(string(b))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got  %+v\nwant %+v", got, tt.want)
			}
			if d := subjectDirectory(string(b)); d != tt.dir {
				t.Errorf("dir = %q", d)
			}
		})
	}
}

func TestParseDeclaredSynthetic(t *testing.T) {
	const tmpl = "Bump x from 1.0.0 to 1.0.1 in /api\n\nBumps x from 1.0.0 to 1.0.1.\n\n---\nupdated-dependencies:\n%s\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>"
	tests := []struct {
		name    string
		block   string
		wantErr string
		want    []Declared
	}{
		{"double quoted", "- dependency-name: \"x\"\n  dependency-version: \"1.0.1\"\n  dependency-type: indirect\n  update-type: version-update:semver-patch", "",
			[]Declared{{Name: "x", Version: "1.0.1", DepType: "indirect", UpdateType: "version-update:semver-patch", From: "1.0.0"}}},
		{"unknown key tolerated", "- dependency-name: x\n  dependency-version: 1.0.1\n  some-new-field: whatever", "",
			[]Declared{{Name: "x", Version: "1.0.1", From: "1.0.0"}}},
		{"crlf", "- dependency-name: x\r\n  dependency-version: 1.0.1\r", "",
			[]Declared{{Name: "x", Version: "1.0.1", From: "1.0.0"}}},
		{"empty", "", "empty", nil},
		{"duplicate key", "- dependency-name: x\n  dependency-name: y", "duplicate", nil},
		{"nested", "- dependency-name: x\n    nested: y", "unexpected", nil},
		{"flow map", "- {dependency-name: x}", "unexpected", nil},
		{"anchor", "- dependency-name: &a x", "unsupported", nil},
		{"shell in name", "- dependency-name: x$(id)\n  dependency-version: 1", "unexpected characters", nil},
		{"space in name", "- dependency-name: 'a b'", "unexpected characters", nil},
		{"traversal", "- dependency-name: ../../etc", "unexpected characters", nil},
		{"bad version", "- dependency-name: x\n  dependency-version: '1;rm'", "unexpected characters", nil},
		{"unterminated quote", "- dependency-name: 'x", "unterminated", nil},
		{"text outside list", "dependency-name: x", "unexpected", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := strings.Replace(tmpl, "%s", tt.block, 1)
			got, err := ParseDeclared(msg)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got  %+v\nwant %+v", got, tt.want)
			}
			if d := subjectDirectory(msg); d != "/api" {
				t.Errorf("dir = %q", d)
			}
		})
	}
	if _, err := ParseDeclared("Bump x\n\nno metadata"); err != errNoBlock {
		t.Errorf("err = %v", err)
	}
	if _, err := ParseDeclared("x\n---\nupdated-dependencies:\n- dependency-name: x\n"); err == nil {
		t.Error("unterminated block accepted")
	}
}
