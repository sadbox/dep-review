package docker

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/sadbox/dep-review/internal/model"
)

// dirSource serves a recorded case: <root>/base/... and <root>/head/...
type dirSource struct {
	root       string
	base, head string
	files      []string
}

func (d dirSource) side(rev string) (string, error) {
	switch rev {
	case d.base:
		return "base", nil
	case d.head:
		return "head", nil
	}
	return "", errors.New("unknown rev " + rev)
}

func (d dirSource) show(_ context.Context, rev, p string) (string, bool, error) {
	s, err := d.side(rev)
	if err != nil {
		return "", false, err
	}
	b, err := os.ReadFile(filepath.Join(d.root, s, filepath.FromSlash(p)))
	if os.IsNotExist(err) {
		return "", false, nil
	}
	return string(b), err == nil, err
}

func (d dirSource) list(_ context.Context, rev, dir string) ([]string, error) {
	s, err := d.side(rev)
	if err != nil {
		return nil, err
	}
	ents, err := os.ReadDir(filepath.Join(d.root, s, filepath.FromSlash(dir)))
	if os.IsNotExist(err) {
		return nil, nil
	}
	var out []string
	for _, e := range ents {
		out = append(out, dir+"/"+e.Name())
	}
	return out, err
}

func (d dirSource) changed(context.Context, string, string) ([]string, error) { return d.files, nil }

type caseFile struct {
	Repo    string   `json:"repo"`
	BaseSHA string   `json:"base_sha"`
	HeadSHA string   `json:"head_sha"`
	Files   []string `json:"files"`
}

func loadCase(t *testing.T, dir string) (model.Classification, dirSource) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "case.json"))
	if err != nil {
		t.Fatal(err)
	}
	var c caseFile
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	cl := model.Classification{Repo: c.Repo, BaseSHA: c.BaseSHA, HeadSHA: c.HeadSHA, Files: c.Files, Ecosystem: model.Docker, Kind: model.KindDependabot}
	return cl, dirSource{root: dir, base: c.BaseSHA, head: c.HeadSHA, files: c.Files}
}

// memWriter is a fetch.Writer that keeps files in memory.
type memWriter struct {
	mu        sync.Mutex
	files     map[string]string
	untrusted map[string]bool
}

func newMemWriter() *memWriter {
	return &memWriter{files: map[string]string{}, untrusted: map[string]bool{}}
}

func (m *memWriter) Add(name, _ string, content []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.files[name] = string(content)
	return nil
}

func (m *memWriter) AddUntrusted(name, _ string, content []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.files[name] = string(content)
	m.untrusted[name] = true
	return nil
}

func codes(fs []model.Finding) string {
	var c []string
	for _, f := range fs {
		c = append(c, f.Code+"="+string(f.Route))
	}
	return strings.Join(c, " ")
}
