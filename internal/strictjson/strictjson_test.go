package strictjson

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

type entry struct {
	Version   string `json:"version"`
	Resolved  string `json:"resolved"`
	Integrity string `json:"integrity"`
	Link      bool   `json:"link"`
	InBundle  bool   `json:"inBundle"`
}

type embedded struct {
	Scripts map[string]string `json:"scripts"`
}

type doc struct {
	Packages map[string]entry `json:"packages"`
	Raw      json.RawMessage  `json:"raw"`
	Ptr      *entry           `json:"ptr"`
	List     []entry          `json:"list"`
	embedded
}

func TestUnmarshal(t *testing.T) {
	ok := []string{
		`{"packages":{"node_modules/a":{"version":"1.0.0","resolved":"https://r/a.tgz","integrity":"sha512-x"}}}`,
		`{"packages":{},"unknown":{"Resolved":1,"x":[]},"raw":{"a":1},"ptr":{"link":true},"list":[{"inBundle":false}],"scripts":{"build":"x"}}`,
		` {"packages":{}} ` + "\n",
		`{"packages":{"a":{"version":"%ud83d%ude00"}}}`, // a valid surrogate pair
		`{"packages":{"a":{"version":"\\ud800"}}}`,      // an escaped backslash, not an escape
	}
	for _, s := range ok {
		var d doc
		if err := Unmarshal([]byte(esc(s)), &d); err != nil {
			t.Errorf("Unmarshal(%s): %v", s, err)
		}
	}
	bad := []string{
		// The PoC from the review (js/case.js): JSON.parse reads the
		// lower-case pair, encoding/json the last one.
		`{"packages":{"node_modules/lodash":{"version":"4.17.21","resolved":"https://evil.example/x.tgz","integrity":"sha512-EVIL","Resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz","Integrity":"sha512-GOOD"}}}`,
		`{"packages":{"a":{"Resolved":"x"}}}`, // lone miscased key binds in encoding/json
		`{"packages":{"a":{"reſolved":"x"}}}`, // long s folds to S
		`{"packages":{"a":{"version":"1","version":"2"}}}`,
		`{"Packages":{}}`,
		`{"packages":{"a":{"InBundle":true}}}`,
		`{"packages":{"a":{"link":"true"}}}`,                     // wrong type is not a zero value
		`{"packages":{"node_modules/x":{},"node_modules/X":{}}}`, // map keys too
		`{"raw":{"a":1,"A":2}}`,                                  // inside a RawMessage
		`{"unknown":{"k":1,"k":2}}`,                              // inside an unknown key
		`{"scripts":{"a":"1"},"Scripts":{}}`,                     // promoted from an embedded struct
		`{"packages":{}} {"packages":{}}`,                        // trailing value
		`{"packages":{}} x`,
		`{"packages":{"a":{"version":"%ud800"}}}`, // lone high surrogate
		`{"packages":{"a":{"version":"%udc00x"}}}`,
		`{"packages":{"a":{"version":"%ud800%u0041"}}}`,
		"{\"packages\":{\"a\":{\"version\":\"\xff\"}}}",
		"\xef\xbb\xbf{\"packages\":{}}", // BOM
		`{"list":[{"version":"1","Version":"2"}]}`,
	}
	for _, s := range bad {
		var d doc
		if err := Unmarshal([]byte(esc(s)), &d); !errors.Is(err, ErrRejected) {
			t.Errorf("Unmarshal(%s) = %v, want ErrRejected", s, err)
		}
	}
}

func TestCheckUntyped(t *testing.T) {
	if err := Check([]byte(`{"a":{"b":1},"c":[{"b":1,"d":2}]}`), nil); err != nil {
		t.Error(err)
	}
	if err := Check([]byte(`{"a":{"b":1,"B":2}}`), nil); !errors.Is(err, ErrRejected) {
		t.Errorf("err = %v", err)
	}
	var x any
	if err := Unmarshal([]byte(`{"a":1,"a":1}`), &x); !errors.Is(err, ErrRejected) {
		t.Errorf("err = %v", err)
	}
}

// esc turns %u into a JSON \u escape (kept out of the literals so no tool
// along the way decodes them).
func esc(s string) string { return strings.ReplaceAll(s, "%u", `\`+"u") }
