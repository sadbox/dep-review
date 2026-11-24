package veto

import (
	"errors"
	"net"
	"net/url"
	"strings"

	"github.com/sadbox/dep-review/internal/artifact"
	"github.com/sadbox/dep-review/internal/config"
)

// DefaultBaseURL is the Claude API.
const DefaultBaseURL = "https://api.anthropic.com"

// Config is what a Client is built from: the gate's resolved settings,
// of which it reads the model settings (spec section 11, amendment 10),
// and the API's origin. FromConfig is the only way to one with settings.
type Config struct {
	conf config.Config
	// BaseURL is the API's origin. It must be https, except for a
	// loopback address in tests.
	BaseURL string
}

// FromConfig returns the client's settings for the gate's resolved
// configuration. The API is always DefaultBaseURL; where the gate sends
// code is not a setting.
//
// Both jobs go through here: review builds its client from it, and fetch
// takes Limits from it, so a read is prepared within exactly what the
// reviewer accepts.
func FromConfig(c config.Config) Config {
	return Config{conf: c, BaseURL: DefaultBaseURL}
}

// Limits returns the budget internal/artifact must prepare a read within
// for this client to accept it.
func (c Config) Limits() artifact.Limits {
	return artifact.Limits{ChunkBytes: c.conf.ChunkBytes, MaxChunks: c.conf.MaxChunks}
}

// apiOrigin checks that raw is an origin a credential may be sent to and
// returns it without a trailing slash. Plain http is accepted only for a
// loopback address, which is what a test server listens on.
func apiOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("not a URL")
	}
	if u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.Trim(u.Path, "/") != "" {
		return "", errors.New("want scheme and host only")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if ip := net.ParseIP(u.Hostname()); ip == nil || !ip.IsLoopback() {
			return "", errors.New("plain http is only for a loopback address")
		}
	default:
		return "", errors.New("want https")
	}
	return u.Scheme + "://" + u.Host, nil
}

// headerSafe reports whether s can stand in a gate-written line as it is:
// 1 to 256 bytes of printable ASCII with no space. Ecosystem keys, module
// paths, npm names, owner/repo, versions and API keys all are.
func headerSafe(s string) bool {
	if s == "" || len(s) > 256 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}
