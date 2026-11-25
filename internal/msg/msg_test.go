package msg

import (
	"strings"
	"testing"
)

func TestPatternMatchesFormatted(t *testing.T) {
	for _, id := range IDs() {
		f := table[id]
		args := []any{}
		for range verb.FindAllString(f, -1) {
			args = append(args, "ARG")
		}
		// %d verbs get a number.
		text := Text(id, fillArgs(f)...)
		if !Pattern(id).MatchString(text) {
			t.Errorf("%s: pattern does not match its own text %q", id, text)
		}
		_ = args
	}
}

func fillArgs(f string) []any {
	var out []any
	for i, v := range verb.FindAllString(f, -1) {
		n := i // argument index this verb uses
		if v[1] == '[' {
			n = int(v[2]-'0') - 1
		}
		for len(out) <= n {
			out = append(out, nil)
		}
		if v[len(v)-1] == 'd' {
			out[n] = 7
		} else {
			out[n] = "x\ny"
		}
	}
	return out
}

func TestNoExtraArgs(t *testing.T) {
	for _, id := range IDs() {
		if text := Text(id, fillArgs(table[id])...); strings.Contains(text, "%!") {
			t.Errorf("%s: bad formatting: %q", id, text)
		}
	}
}

func TestIDOf(t *testing.T) {
	err := Errorf(UnknownName, "a.b")
	if IDOf(err) != UnknownName || err.Error() != "unknown logical name: a.b" {
		t.Errorf("IDOf / text: %q %q", IDOf(err), err.Error())
	}
}
