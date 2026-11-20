package actions

import (
	"fmt"
	"strings"
)

// opKind is one line of an edit script.
type opKind byte

const (
	opEqual  opKind = ' '
	opDelete opKind = '-'
	opInsert opKind = '+'
)

type lineOp struct {
	kind opKind
	a, b int // index into the old (a) and new (b) slices; -1 when absent
}

// splitLines splits text into lines without their terminators. A trailing
// newline does not produce an empty last line.
func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	s = strings.TrimSuffix(s, "\n")
	return strings.Split(s, "\n")
}

// diffLines returns an edit script turning a into b. It is a patience diff:
// lines unique to both sides anchor the alignment, gaps between anchors are
// diffed recursively, and small gaps without anchors fall back to an LCS
// table. Large anchorless gaps are reported as a replacement, which is
// always correct, just not minimal.
func diffLines(a, b []string) []lineOp {
	var ops []lineOp
	diffRange(a, b, 0, len(a), 0, len(b), &ops)
	return ops
}

const lcsCellLimit = 4 << 20

func diffRange(a, b []string, alo, ahi, blo, bhi int, ops *[]lineOp) {
	// Common prefix.
	for alo < ahi && blo < bhi && a[alo] == b[blo] {
		*ops = append(*ops, lineOp{opEqual, alo, blo})
		alo++
		blo++
	}
	// Common suffix, emitted after the middle.
	n := 0
	for alo < ahi-n && blo < bhi-n && a[ahi-1-n] == b[bhi-1-n] {
		n++
	}
	ahiM, bhiM := ahi-n, bhi-n
	diffMiddle(a, b, alo, ahiM, blo, bhiM, ops)
	for i := 0; i < n; i++ {
		*ops = append(*ops, lineOp{opEqual, ahiM + i, bhiM + i})
	}
}

func diffMiddle(a, b []string, alo, ahi, blo, bhi int, ops *[]lineOp) {
	if alo == ahi {
		for j := blo; j < bhi; j++ {
			*ops = append(*ops, lineOp{opInsert, -1, j})
		}
		return
	}
	if blo == bhi {
		for i := alo; i < ahi; i++ {
			*ops = append(*ops, lineOp{opDelete, i, -1})
		}
		return
	}
	anchors := uniqueAnchors(a, b, alo, ahi, blo, bhi)
	if len(anchors) == 0 {
		if (ahi-alo)*(bhi-blo) <= lcsCellLimit {
			lcsDiff(a, b, alo, ahi, blo, bhi, ops)
			return
		}
		for i := alo; i < ahi; i++ {
			*ops = append(*ops, lineOp{opDelete, i, -1})
		}
		for j := blo; j < bhi; j++ {
			*ops = append(*ops, lineOp{opInsert, -1, j})
		}
		return
	}
	pa, pb := alo, blo
	for _, an := range anchors {
		diffRange(a, b, pa, an[0], pb, an[1], ops)
		*ops = append(*ops, lineOp{opEqual, an[0], an[1]})
		pa, pb = an[0]+1, an[1]+1
	}
	diffRange(a, b, pa, ahi, pb, bhi, ops)
}

// uniqueAnchors returns the longest increasing run of (i, j) pairs where
// a[i] == b[j] and that line occurs exactly once in each range.
func uniqueAnchors(a, b []string, alo, ahi, blo, bhi int) [][2]int {
	type cnt struct{ na, nb, ia, ib int }
	m := make(map[string]*cnt)
	for i := alo; i < ahi; i++ {
		c := m[a[i]]
		if c == nil {
			c = &cnt{}
			m[a[i]] = c
		}
		c.na++
		c.ia = i
	}
	for j := blo; j < bhi; j++ {
		c := m[b[j]]
		if c == nil {
			continue
		}
		c.nb++
		c.ib = j
	}
	var pairs [][2]int
	for i := alo; i < ahi; i++ {
		c := m[a[i]]
		if c.na == 1 && c.nb == 1 {
			pairs = append(pairs, [2]int{i, c.ib})
		}
	}
	if len(pairs) == 0 {
		return nil
	}
	// Longest increasing subsequence on j (patience sorting).
	tails := []int{} // index into pairs of the smallest tail of each length
	prev := make([]int, len(pairs))
	for k, p := range pairs {
		lo, hi := 0, len(tails)
		for lo < hi {
			mid := (lo + hi) / 2
			if pairs[tails[mid]][1] < p[1] {
				lo = mid + 1
			} else {
				hi = mid
			}
		}
		if lo > 0 {
			prev[k] = tails[lo-1]
		} else {
			prev[k] = -1
		}
		if lo == len(tails) {
			tails = append(tails, k)
		} else {
			tails[lo] = k
		}
	}
	out := make([][2]int, len(tails))
	k := tails[len(tails)-1]
	for i := len(tails) - 1; i >= 0; i-- {
		out[i] = pairs[k]
		k = prev[k]
	}
	return out
}

func lcsDiff(a, b []string, alo, ahi, blo, bhi int, ops *[]lineOp) {
	n, m := ahi-alo, bhi-blo
	// t[i][j] = LCS length of a[alo+i:] and b[blo+j:].
	t := make([]int32, (n+1)*(m+1))
	at := func(i, j int) int32 { return t[i*(m+1)+j] }
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			v := at(i+1, j)
			if w := at(i, j+1); w > v {
				v = w
			}
			if a[alo+i] == b[blo+j] {
				if w := at(i+1, j+1) + 1; w > v {
					v = w
				}
			}
			t[i*(m+1)+j] = v
		}
	}
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case a[alo+i] == b[blo+j] && at(i, j) == at(i+1, j+1)+1:
			*ops = append(*ops, lineOp{opEqual, alo + i, blo + j})
			i++
			j++
		case at(i+1, j) >= at(i, j+1):
			*ops = append(*ops, lineOp{opDelete, alo + i, -1})
			i++
		default:
			*ops = append(*ops, lineOp{opInsert, -1, blo + j})
			j++
		}
	}
	for ; i < n; i++ {
		*ops = append(*ops, lineOp{opDelete, alo + i, -1})
	}
	for ; j < m; j++ {
		*ops = append(*ops, lineOp{opInsert, -1, blo + j})
	}
}

// hunk is a run of changes: deleted old lines and inserted new lines between
// two equal runs.
type hunk struct {
	del, ins []int // indexes into old and new
}

// changeHunks groups an edit script into hunks of adjacent changes.
func changeHunks(ops []lineOp) []hunk {
	var hs []hunk
	var cur *hunk
	for _, op := range ops {
		if op.kind == opEqual {
			cur = nil
			continue
		}
		if cur == nil {
			hs = append(hs, hunk{})
			cur = &hs[len(hs)-1]
		}
		if op.kind == opDelete {
			cur.del = append(cur.del, op.a)
		} else {
			cur.ins = append(cur.ins, op.b)
		}
	}
	return hs
}

// unifiedDiff renders a unified diff with ctx lines of context, or "" when
// the inputs are equal.
func unifiedDiff(oldName, newName, oldText, newText string, ctx int) string {
	if oldText == newText {
		return ""
	}
	a, b := splitLines(oldText), splitLines(newText)
	ops := diffLines(a, b)
	var sb strings.Builder
	fmt.Fprintf(&sb, "--- %s\n+++ %s\n", oldName, newName)
	i := 0
	for i < len(ops) {
		if ops[i].kind == opEqual {
			i++
			continue
		}
		// Start a hunk ctx lines before the first change.
		start := i - ctx
		if start < 0 {
			start = 0
		}
		end := i
		for {
			for end < len(ops) && ops[end].kind != opEqual {
				end++
			}
			// Merge with the next change if it is within 2*ctx equal lines.
			next := end
			for next < len(ops) && ops[next].kind == opEqual {
				next++
			}
			if next < len(ops) && next-end <= 2*ctx {
				end = next
				continue
			}
			break
		}
		stop := end + ctx
		if stop > len(ops) {
			stop = len(ops)
		}
		aStart, bStart, aLen, bLen := -1, -1, 0, 0
		for _, op := range ops[start:stop] {
			if op.kind != opInsert {
				if aStart < 0 {
					aStart = op.a
				}
				aLen++
			}
			if op.kind != opDelete {
				if bStart < 0 {
					bStart = op.b
				}
				bLen++
			}
		}
		fmt.Fprintf(&sb, "@@ -%s +%s @@\n", hunkRange(aStart, aLen, ops, start, true), hunkRange(bStart, bLen, ops, start, false))
		for _, op := range ops[start:stop] {
			switch op.kind {
			case opEqual:
				sb.WriteString(" " + a[op.a] + "\n")
			case opDelete:
				sb.WriteString("-" + a[op.a] + "\n")
			case opInsert:
				sb.WriteString("+" + b[op.b] + "\n")
			}
		}
		i = stop
	}
	return sb.String()
}

// hunkRange formats "start,len" (1-based). For an empty side, start is the
// line before the hunk, as in GNU diff.
func hunkRange(start, n int, ops []lineOp, from int, old bool) string {
	if n == 0 {
		// Position of the last line on this side before the hunk.
		p := 0
		for _, op := range ops[:from] {
			if old && op.kind != opInsert {
				p = op.a + 1
			}
			if !old && op.kind != opDelete {
				p = op.b + 1
			}
		}
		return fmt.Sprintf("%d,0", p)
	}
	return fmt.Sprintf("%d,%d", start+1, n)
}

// insertedBytes is the size of the lines b has that a does not, by the
// edit script: the "changed bytes" measure used for residuals.
func insertedBytes(oldText, newText string) int {
	if oldText == newText {
		return 0
	}
	a, b := splitLines(oldText), splitLines(newText)
	n := 0
	for _, op := range diffLines(a, b) {
		if op.kind == opInsert {
			n += len(b[op.b]) + 1
		}
	}
	return n
}
