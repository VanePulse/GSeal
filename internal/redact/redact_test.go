package redact

import (
	"strings"
	"testing"
)

func TestEncodeURIComponent(t *testing.T) {
	cases := map[string]string{
		"abc-_.!~*'()": "abc-_.!~*'()",
		"a b&c=d/e?":   "a%20b%26c%3Dd%2Fe%3F",
		"é":            "%C3%A9",
		"p@ss#1":       "p%40ss%231",
	}
	for in, want := range cases {
		if got := EncodeURIComponent(in); got != want {
			t.Errorf("EncodeURIComponent(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPatternsForms(t *testing.T) {
	p := Patterns([]string{"p@ss", "", "p@ss"})
	want := map[string]bool{"p@ss": true, "p%40ss": true, "cEBzcw==": true}
	if len(p) != 3 {
		t.Fatalf("patterns = %q", p)
	}
	for _, x := range p {
		if !want[x] {
			t.Errorf("unexpected pattern %q", x)
		}
	}
	if len(p[0]) < len(p[2]) {
		t.Error("patterns must be longest first")
	}
}

func TestAll(t *testing.T) {
	pat := Patterns([]string{"abc", "cdef", "sample"})
	cases := map[string]string{
		"x abcdef y":         "x *** y",
		"sample.test sample": "sample.test ***",
		"nothing":            "nothing",
	}
	for in, want := range cases {
		if got := All(in, pat, []string{"sample.test"}); got != want {
			t.Errorf("All(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestStreamPieces(t *testing.T) {
	r := New(Patterns([]string{"abc", "cdef"}), nil, nil)
	out := r.Push("x ab") + r.Flush(false) + r.Push("cd") + r.Flush(false) + r.Push("ef y") + r.Flush(true)
	if out != "x *** y" {
		t.Errorf("stream = %q", out)
	}
}

func TestWords(t *testing.T) {
	pat := Patterns([]string{"alpha"})
	if got := Words("token alpha and mx-alpha, alpha.", pat, nil); got != "token *** and mx-alpha, alpha." {
		t.Errorf("Words = %q", got)
	}
	if got := Words("alpha", pat, nil); got != "***" {
		t.Errorf("Words = %q", got)
	}
	if !strings.Contains(Words("中alpha文", pat, nil), "***") {
		t.Error("non-ASCII neighbours are token boundaries")
	}
}

func TestForced(t *testing.T) {
	enc := Patterns([]string{"marker"})
	pat := Patterns([]string{"marker", "plainsecret"})
	plain := []string{"prefix-marker.invalid", "x-plainsecret-y"}
	r := New(pat, enc, plain)
	out := r.Push("prefix-mar") + r.Flush(false) + r.Push("ker.invalid x-plainsecret-y") + r.Flush(true)
	if out != "prefix-***.invalid x-plainsecret-y" {
		t.Errorf("forced inside plain = %q", out)
	}
	if got := Words("see prefix-marker.invalid", pat, enc); got != "see prefix-***.invalid" {
		t.Errorf("Words forced = %q", got)
	}
}

func TestForcedOverlap(t *testing.T) {
	// Two encrypted values overlapping (review M1-005): no tail left.
	enc := Patterns([]string{"abc", "bcdef"})
	if got := Words("Overlap abcdef", enc, enc); got != "Overlap ***" {
		t.Errorf("Words two forced = %q", got)
	}
	// Encrypted value overlapping a plain (unencrypted) secret: both masked.
	pat := Patterns([]string{"abc", "bcdef"})
	if got := Words("x abcdef y", pat, Patterns([]string{"abc"})); got != "x *** y" {
		t.Errorf("Words forced+normal = %q", got)
	}
	if got := Words("x zabcdef y", pat, Patterns([]string{"bcdef"})); got != "x z*** y" {
		t.Errorf("Words normal before forced = %q", got)
	}
	// Without forced values the whole-token rule is unchanged.
	if got := Words("abcdef and abc", pat, nil); got != "abcdef and ***" {
		t.Errorf("Words token rule = %q", got)
	}
	// An unrelated encrypted value does not change the token rule.
	if got := Words("abcdef! and Z", pat, Patterns([]string{"Z"})); got != "abcdef! and ***" {
		t.Errorf("Words unrelated forced = %q", got)
	}
	// Stream: the encrypted value is masked inside a plain value; an
	// unencrypted secret inside a plain value stays shown (baseline rule),
	// whether or not it touches the encrypted value.
	r := New(pat, Patterns([]string{"abc"}), []string{"x-bcdef-y", "w-abcdef-v"})
	out := r.Push("w-abc") + r.Flush(false) + r.Push("def-v x-bcdef-y") + r.Flush(true)
	if out != "w-***def-v x-bcdef-y" {
		t.Errorf("stream forced inside plain = %q", out)
	}
}

// The review M1-006 case: same text, one push or two pieces with an idle
// flush in between, must give the same output.
func TestStreamChunkInvariantReview(t *testing.T) {
	pat := Patterns([]string{"abc", "bcdef", "Z"})
	forced := Patterns([]string{"Z"})
	plain := []string{"bcdef!"}
	text := "abcdef! Z"
	one := All2(text, pat, forced, plain)
	for cut := 1; cut < len(text); cut++ {
		r := New(pat, forced, plain)
		got := r.Push(text[:cut]) + r.Flush(false) + r.Push(text[cut:]) + r.Flush(true)
		if got != one {
			t.Errorf("cut %d: %q, one push: %q", cut, got, one)
		}
	}
	if one != "***def! ***" {
		t.Errorf("one push = %q", one)
	}
}

func All2(s string, patterns, forced, plain []string) string {
	r := New(patterns, forced, plain)
	return r.Push(s) + r.Flush(true)
}

// Property: for random texts, secrets, encrypted values and plain values,
// the output never depends on chunking or idle flushes, and every encrypted
// value occurrence is masked.
func TestStreamChunkInvariantRandom(t *testing.T) {
	rng := uint64(0x9e3779b97f4a7c15)
	next := func(n int) int {
		rng ^= rng << 13
		rng ^= rng >> 7
		rng ^= rng << 17
		return int(rng % uint64(n))
	}
	word := func(alpha string, min, max int) string {
		n := min + next(max-min+1)
		b := make([]byte, n)
		for i := range b {
			b[i] = alpha[next(len(alpha))]
		}
		return string(b)
	}
	const alpha = "abcd.-"
	for iter := 0; iter < 20000; iter++ {
		var secrets, enc, plain []string
		for i := 0; i < 1+next(3); i++ {
			secrets = append(secrets, word(alpha, 1, 4))
		}
		for i := 0; i < next(3); i++ {
			e := word(alpha, 2, 4)
			secrets, enc = append(secrets, e), append(enc, e)
		}
		for i := 0; i < next(3); i++ {
			plain = append(plain, word(alpha, 3, 7))
		}
		pat, forced := Patterns(secrets), Patterns(enc)
		text := word(alpha+" ", 0, 40)
		one := All2(text, pat, forced, plain)
		r := New(pat, forced, plain)
		var got string
		for rest := text; rest != ""; {
			n := 1 + next(len(rest))
			got += r.Push(rest[:n])
			if next(2) == 0 {
				got += r.Flush(false)
			}
			rest = rest[n:]
		}
		got += r.Flush(true)
		if got != one {
			t.Fatalf("chunking changed the output\ntext %q secrets %q enc %q plain %q\none %q\ngot %q", text, secrets, enc, plain, one, got)
		}
		for _, e := range enc {
			if e != "" && strings.Contains(one, e) {
				// An encrypted value may only appear as part of a mask-free
				// region if it overlaps another mask boundary; check exactly:
				// remove masks and make sure no occurrence survives intact.
				t.Fatalf("encrypted value %q visible\ntext %q out %q", e, text, one)
			}
		}
	}
}
