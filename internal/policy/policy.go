// Package policy decides which values are encrypted at rest and which are
// redacted in output.
//
// Encryption spec (config [encrypt] keys, or a file-level `; @encrypt`):
//
//	(empty) or all   every key
//	@mask            keys that are not on the plain list (the classic rule)
//	NAME, *_SECRET   key names; * and ? are wildcards; case-insensitive
//
// Tokens are comma separated and combine (union), e.g. `@mask, HOST`.
//
// Redaction: a value stored encrypted is always redacted; a plain value is
// redacted unless its key is on the plain list. A key is on the plain list if
// it equals one of the words, or ends in `_<word>` (case-insensitive), so
// SRC_HOST counts as HOST.
package policy

import (
	"path"
	"regexp"
	"strings"

	"github.com/VanePulse/GSeal/internal/ini"
	"github.com/VanePulse/GSeal/internal/msg"
)

// Plain is the list of non-secret key words.
type Plain struct{ words []string }

// NewPlain builds the plain list (words are compared case-insensitively).
func NewPlain(words []string) Plain {
	w := make([]string, len(words))
	for i, x := range words {
		w[i] = strings.ToUpper(x)
	}
	return Plain{w}
}

// Has reports whether key is on the plain list.
func (p Plain) Has(key string) bool {
	k := strings.ToUpper(key)
	for _, w := range p.words {
		if k == w || strings.HasSuffix(k, "_"+w) {
			return true
		}
	}
	return false
}

// Words returns the words.
func (p Plain) Words() []string { return append([]string(nil), p.words...) }

// Redacted reports whether a value of key must be masked in output.
func (p Plain) Redacted(key string, storedEncrypted bool) bool {
	return storedEncrypted || !p.Has(key)
}

// Spec is a parsed encryption spec.
type Spec struct {
	All   bool
	Mask  bool
	Globs []string // upper-cased
	Text  string   // as written
}

var tokenRe = regexp.MustCompile(`^[A-Za-z0-9_*?]+$`)

// Parse parses an encryption spec. The error text names the bad token.
func Parse(spec string) (Spec, error) {
	s := Spec{Text: ini.Trim(spec)}
	if s.Text == "" {
		s.All = true
		return s, nil
	}
	for _, t := range strings.Split(s.Text, ",") {
		t = ini.Trim(t)
		switch strings.ToLower(t) {
		case "":
			continue
		case "all", "@all":
			s.All = true
		case "@mask":
			s.Mask = true
		default:
			if !tokenRe.MatchString(t) {
				return Spec{}, &BadToken{t}
			}
			s.Globs = append(s.Globs, strings.ToUpper(t))
		}
	}
	if !s.All && !s.Mask && len(s.Globs) == 0 {
		s.All = true
	}
	return s, nil
}

// BadToken is a spec token that is not a key name or pattern.
type BadToken struct{ Token string }

func (e *BadToken) Error() string { return msg.Text(msg.ReasonBadToken, e.Token) }

// Encrypt reports whether values of key are to be encrypted.
func (s Spec) Encrypt(key string, plain Plain) bool {
	if s.All {
		return true
	}
	if s.Mask && !plain.Has(key) {
		return true
	}
	k := strings.ToUpper(key)
	for _, g := range s.Globs {
		if ok, _ := path.Match(g, k); ok {
			return true
		}
	}
	return false
}

// Describe returns a short human description.
func (s Spec) Describe(allText string) string {
	if s.All {
		return allText
	}
	return s.Text
}
