// Package redact masks secret values in a child's output, in audit records
// and in doc text.
//
// Every non-empty secret is masked, however short: a 1–3 byte secret masks
// each occurrence of those bytes in the output (safety over readability).
// Each secret is also masked in its URL-encoded and base64 forms.
//
// Whitelisted (plain) values win over a secret contained in them: secret
// `sample` inside HOST `sample.test` is shown. When a whitelisted value equals
// a secret, the secret wins and it is masked. Forced patterns (values stored
// encrypted) are never cancelled by a plain value: they are masked wherever
// they occur.
package redact

import (
	"encoding/base64"
	"sort"
	"strings"
)

// Mask replaces a secret.
const Mask = "***"

// Patterns returns the byte strings to mask for the given secret values,
// longest first.
func Patterns(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range values {
		if v == "" {
			continue
		}
		for _, f := range []string{v, EncodeURIComponent(v), base64.StdEncoding.EncodeToString([]byte(v))} {
			if !seen[f] {
				seen[f] = true
				out = append(out, f)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
	return out
}

// EncodeURIComponent is JavaScript's encodeURIComponent on UTF-8 text.
func EncodeURIComponent(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.IndexByte("-_.!~*'()", c) >= 0 {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&15])
	}
	return b.String()
}

type span struct {
	s, e   int
	forced bool
}

func occurrences(buf, p string, out []span) []span {
	if p == "" {
		return out
	}
	for i := strings.Index(buf, p); i >= 0; {
		out = append(out, span{i, i + len(p), false})
		j := strings.Index(buf[i+1:], p)
		if j < 0 {
			break
		}
		i += 1 + j
	}
	return out
}

// intervals returns the regions of buf to mask: every occurrence of every
// pattern (overlaps included), minus non-forced ones lying wholly inside a
// strictly longer occurrence of a plain value, merged into disjoint sorted
// intervals. The decision for one occurrence depends only on that occurrence
// and the plain values around it, never on unrelated matches, so the result
// does not depend on how the stream is cut into chunks.
func intervals(buf string, patterns []string, forced map[string]bool, plain []string) []span {
	var all []span
	for _, p := range patterns {
		n := len(all)
		all = occurrences(buf, p, all)
		if forced[p] {
			for i := n; i < len(all); i++ {
				all[i].forced = true
			}
		}
	}
	if len(all) == 0 {
		return nil
	}
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].s != all[j].s {
			return all[i].s < all[j].s
		}
		return all[i].e > all[j].e
	})
	var keep []span
	for _, p := range plain {
		keep = occurrences(buf, p, keep)
	}
	hits := all
	if len(keep) > 0 {
		// Sweep: for each hit (by start), the plain occurrence started at or
		// before it that reaches furthest decides whether the hit is inside it.
		sort.SliceStable(keep, func(i, j int) bool { return keep[i].s < keep[j].s })
		k, bestS, bestE := 0, -1, -1
		hits = hits[:0:0]
		for _, h := range all {
			for ; k < len(keep) && keep[k].s <= h.s; k++ {
				if keep[k].e > bestE || (keep[k].e == bestE && keep[k].s < bestS) {
					bestS, bestE = keep[k].s, keep[k].e
				}
			}
			inside := bestE > h.e || (bestE == h.e && bestS < h.s)
			if h.forced || !inside {
				hits = append(hits, h)
			}
		}
	}
	return merge(hits)
}

// merge joins sorted (by start) spans that overlap or touch.
func merge(spans []span) []span {
	var merged []span
	for _, h := range spans {
		if n := len(merged); n > 0 && h.s <= merged[n-1].e {
			if h.e > merged[n-1].e {
				merged[n-1].e = h.e
			}
			continue
		}
		merged = append(merged, span{h.s, h.e, false})
	}
	return merged
}

// closeOver adds every candidate that overlaps a masked region, repeatedly,
// until nothing changes. masked must be merged; the result is merged.
func closeOver(masked, candidates []span) []span {
	used := make([]bool, len(candidates))
	for changed := true; changed; {
		changed = false
		for i, c := range candidates {
			if used[i] || !overlaps(masked, c) {
				continue
			}
			used[i], changed = true, true
			masked = append(masked, span{c.s, c.e, false})
		}
		if changed {
			sort.SliceStable(masked, func(i, j int) bool { return masked[i].s < masked[j].s })
			masked = merge(masked)
		}
	}
	return masked
}

// overlaps reports whether c shares at least one byte with a merged span.
func overlaps(merged []span, c span) bool {
	i := sort.Search(len(merged), func(i int) bool { return merged[i].e > c.s })
	return i < len(merged) && merged[i].s < c.e
}

// Redactor masks a byte stream.
//
// Rule: a byte is emitted only once its masking decision can no longer
// change. That holds for position i when no secret or plain value could still
// start at or before i and run past the end of what has been seen — no tail
// of the buffer from i on is a proper prefix of any such value. The undecided
// tail is held back (on every chunk, on idle and across pauses).
//
// Emitted text is kept as context (ctx, never re-emitted), so an occurrence
// that began in it is recognised when it completes; its continuation stays
// inside the same ***.
type Redactor struct {
	patterns, plain, values []string
	forced                  map[string]bool
	maxLen                  int
	ctx, carry              string
	maskOpen                bool
	off                     bool
}

// New returns a Redactor for the given patterns and plain values. Forced
// patterns (they must also be in patterns) are masked even inside a plain value.
func New(patterns, forced, plain []string) *Redactor {
	r := &Redactor{patterns: patterns, forced: map[string]bool{}}
	for _, f := range forced {
		r.forced[f] = true
	}
	if len(patterns) == 0 {
		r.off = true
		return r
	}
	for _, p := range plain {
		if p != "" {
			r.plain = append(r.plain, p)
		}
	}
	r.values = append(append([]string(nil), patterns...), r.plain...)
	for _, v := range r.values {
		if len(v) > r.maxLen {
			r.maxLen = len(v)
		}
	}
	return r
}

func (r *Redactor) firstPending(s string, from int) int {
	start := len(s) - r.maxLen + 1
	if from > start {
		start = from
	}
	for i := start; i < len(s); i++ {
		tail := s[i:]
		for _, p := range r.values {
			if len(p) > len(tail) && strings.HasPrefix(p, tail) {
				return i
			}
		}
	}
	return len(s)
}

func (r *Redactor) emit(final bool) string {
	s := r.ctx + r.carry
	base := len(r.ctx)
	cut := len(s)
	if !final {
		cut = r.firstPending(s, base)
	}
	var out strings.Builder
	pos := base
	for _, iv := range intervals(s, r.patterns, r.forced, r.plain) {
		if iv.e <= base {
			continue
		}
		if iv.s >= cut {
			break
		}
		from := iv.s
		if from < base {
			from = base
		}
		out.WriteString(s[pos:from])
		if !(iv.s < base && r.maskOpen) { // a continuation adds no second ***
			out.WriteString(Mask)
		}
		pos = iv.e
		if cut < pos {
			pos = cut
		}
		r.maskOpen = true
	}
	if pos < cut {
		out.WriteString(s[pos:cut])
		r.maskOpen = false
	}
	r.carry = s[cut:]
	c0 := cut - r.maxLen
	if c0 < 0 {
		c0 = 0
	}
	r.ctx = s[c0:cut]
	return out.String()
}

// Push adds a chunk and returns what can be emitted.
func (r *Redactor) Push(chunk string) string {
	if r.off {
		return chunk
	}
	r.carry += chunk
	return r.emit(false)
}

// Flush emits what is decided (idle) or, with final, everything, masked.
func (r *Redactor) Flush(final bool) string {
	if r.off {
		return ""
	}
	return r.emit(final)
}

// All masks a whole string with the same rules as the stream.
func All(s string, patterns, plain []string) string {
	r := New(patterns, nil, plain)
	return r.Push(s) + r.Flush(true)
}

// Words masks secrets in doc text only where a secret stands as a whole
// token (not next to [A-Za-z0-9_.-]), so names like `pay-db` are not
// mangled by a short value that happens to be a common word. Forced patterns
// (encrypted values) are masked wherever they occur, overlaps included; a
// secret occurrence that overlaps an encrypted value's region (directly or
// through other such occurrences) is masked with it, so no tail of a secret
// is left next to the mask of an encrypted value. Doc text is masked in one
// piece, so this is deterministic.
func Words(s string, patterns, forced []string) string {
	if len(patterns) == 0 && len(forced) == 0 {
		return s
	}
	isForced := map[string]bool{}
	for _, f := range forced {
		isForced[f] = true
	}
	word := func(c byte) bool {
		return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-'
	}
	var tokens, forcedSpans, normalAll []span
	// Whole-token matches of the non-forced patterns, scanned left to right
	// like the baseline regular expression (longest alternative first, no
	// overlap between them).
	for i := 0; i < len(s); {
		hit := 0
		if i == 0 || !word(s[i-1]) {
			for _, p := range patterns {
				if isForced[p] {
					continue
				}
				if strings.HasPrefix(s[i:], p) && (i+len(p) == len(s) || !word(s[i+len(p)])) {
					hit = len(p)
					break
				}
			}
		}
		if hit > 0 {
			tokens = append(tokens, span{i, i + hit, false})
			i += hit
		} else {
			i++
		}
	}
	// Every occurrence of every forced pattern, then every other secret
	// occurrence reachable from them by overlap.
	for _, p := range forced {
		forcedSpans = occurrences(s, p, forcedSpans)
	}
	byStart := func(l []span) {
		sort.SliceStable(l, func(i, j int) bool { return l[i].s < l[j].s })
	}
	if len(forcedSpans) > 0 {
		byStart(forcedSpans)
		for _, p := range patterns {
			if !isForced[p] {
				normalAll = occurrences(s, p, normalAll)
			}
		}
		forcedSpans = closeOver(merge(forcedSpans), normalAll)
	}
	all := append(tokens, forcedSpans...)
	if len(all) == 0 {
		return s
	}
	byStart(all)
	merged := merge(all)
	var b strings.Builder
	pos := 0
	for _, m := range merged {
		b.WriteString(s[pos:m.s])
		b.WriteString(Mask)
		pos = m.e
	}
	b.WriteString(s[pos:])
	return b.String()
}
