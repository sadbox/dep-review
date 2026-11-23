package land

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"time"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/wire"
)

// maxFirstSeen is how many pins the marker remembers a first evaluation
// for. With that many, and every list of notified heads full, the marker
// still fits maxMarkerBytes with no cached verdict in it (a test keeps it
// so): the cache is all that marker.String may drop. An update past this
// number gets no time from the gate's clock, which is person.
const maxFirstSeen = 50

// firstSeenSource is the Source of a first-seen time that is the gate's
// own.
const firstSeenSource = "the gate's own clock: when publish first evaluated this pin on this pull request"

// seen is when publish first evaluated one pin of the pull request that
// no registry had a time for.
type seen struct {
	// Pin is pinKey's name for the pin.
	Pin string `json:"pin"`
	// At is the deciding job's clock at that evaluation.
	At time.Time `json:"at"`
}

var pinRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// pinKey names what an update pins: the ecosystem, the package, the
// version it moves to and the hash Bound was established for. An image's
// digest is part of its To. While Bound does not hold there is no hash,
// and that is a pin of its own: a time remembered for it is never the
// time of a pin that is bound, so nothing merges on it. The four parts
// are written with their lengths, so no two pins have one key.
func pinKey(ecosystem string, u wire.Update) string {
	h := sha256.New()
	for _, part := range []string{ecosystem, u.Name, u.To, u.Hash} {
		fmt.Fprintf(h, "%d:%s,", len(part), part)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// dateUnseen gives every update whose registry has no time the gate
// trusts the gate's own first-seen time (spec section 11, amendment 38):
// the moment publish first evaluated that exact pin on this pull request.
// The gate's comment remembers it, and a pin the comment does not know is
// first evaluated now. A rebase keeps the pin and so the time; a rewrite
// to another version or hash is another pin.
//
// A time the registry gave is left alone, and a registry that was asked
// and did not answer is still waited for: such an update keeps the time it
// has in the comment and gets none now. ev.firstSeen becomes what the next
// comment is to remember: the pins of this pull request that have no
// registry time, and no pin that is gone.
//
// Which pins are gone only a run that knows every update's hash can say.
// While one has none (its Bound does not hold, which an outage also
// does), it may be any pin the comment remembers, so nothing is forgotten
// in such a run: an outage must not start a clock again.
//
// The comment is read only when an update has no registry time. The
// error is GitHub not answering for it.
func dateUnseen(ctx context.Context, cfg Config, ev *Evaluation) error {
	needed, unnamed := false, false
	for i, u := range ev.Facts.Updates {
		needed = needed || !u.FirstSeen.Known()
		// An image's digest is in its To.
		unnamed = unnamed || (ev.Facts.Ecosystem != allow.Docker && ev.file.Facts.Updates[i].Hash == "")
	}
	if !needed {
		return nil
	}
	c, err := findComment(ctx, cfg, ev.PullRequest.Number)
	if err != nil {
		return err
	}
	var before []seen
	if c != nil {
		// A marker that does not parse, or was written before the gate
		// remembered times, has none: every pin is first evaluated now.
		// Whatever the marker's outcome and head, a time in it is one this
		// job wrote for the pin.
		old, _ := parseMarker(c.Body)
		before = old.FirstSeen
	}
	times := map[string]time.Time{}
	for _, s := range before {
		times[s.Pin] = s.At
	}

	kept := map[string]bool{}
	for i := range ev.Facts.Updates {
		u := &ev.Facts.Updates[i]
		if u.FirstSeen.Known() {
			continue
		}
		waits := u.FirstSeen.Unavailable && u.FirstSeen.Source != ""
		pin := pinKey(ev.Facts.Ecosystem, ev.file.Facts.Updates[i])
		at, remembered := times[pin]
		if !remembered {
			if waits {
				continue
			}
			at = ev.now
		}
		// Two updates with one pin (two old versions that move to the same
		// new one) share one time.
		if !kept[pin] {
			if len(ev.firstSeen) == maxFirstSeen {
				if !waits {
					u.FirstSeen.Value += fmt.Sprintf("; the gate's comment remembers a first evaluation for no more than %d pins, and this one is past that", maxFirstSeen)
				}
				continue
			}
			kept[pin], times[pin] = true, at
			ev.firstSeen = append(ev.firstSeen, seen{Pin: pin, At: at})
		}
		if waits {
			continue
		}
		dated := allow.At(at, firstSeenSource)
		if u.FirstSeen.Value != "" {
			dated.Value += "; the registry's clock: " + u.FirstSeen.Value
		}
		u.FirstSeen = dated
	}
	if unnamed {
		for _, s := range before {
			if !kept[s.Pin] && len(ev.firstSeen) < maxFirstSeen {
				kept[s.Pin] = true
				ev.firstSeen = append(ev.firstSeen, s)
			}
		}
	}
	return nil
}
