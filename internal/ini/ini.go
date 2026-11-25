// Package ini parses credential files: [section], key = value, ; and #
// comments, optional quotes, [DEFAULT] inheritance and Javadoc-style doc tags.
//
// Doc tags: a comment `; @tag text` starts a block; following comment lines
// belong to it until the next @tag or a non-comment line (blank line, key,
// [section]). Only @desc blocks are shown; other tags (@remark ...) and
// untagged comments are skipped. An empty comment `;` inside @desc is a blank
// doc line. Comments shaped like `KEY = value` are always skipped, so a
// commented-out old password is never shown. A file-level `; @encrypt <spec>`
// overrides the configured encryption policy for that file.
package ini

import (
	"regexp"
	"strings"
)

// ws is JavaScript's \s (Unicode white space plus BOM), so files parse
// exactly as the previous implementation parsed them.
const ws = `\t\n\v\f\r \x{00A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}\x{FEFF}`

var (
	tagRe = regexp.MustCompile(`^[;#][` + ws + `]*@(\w+)\b[` + ws + `]?(.*)$`)
	// comment: `;` or `#`, one optional white space, then the text.
	commentRe = regexp.MustCompile(`^[;#][` + ws + `]?(.*)$`)
	// CommentedAssign: any run of word-like tokens before the first `=`
	// (`; PSWD = …`, `; BAD KEY WITH FIVE WORDS = …`); doc prose with `=`
	// after CJK text, punctuation or inside a URL does not match.
	CommentedAssign = regexp.MustCompile(`^[;#][` + ws + `]*[\w.-]+(?:[ \t]+[\w.-]+)*[` + ws + `]*=`)
	sectionRe       = regexp.MustCompile(`^\[([^\]]+)\]$`)
	lineSplit       = regexp.MustCompile(`\r?\n`)
	needQuote       = regexp.MustCompile(`^[` + ws + `]|[` + ws + `]$|[` + ws + `][;#]|^['"]`)
)

// IsSpace reports whether r is white space in the JavaScript sense (\s, trim).
func IsSpace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', '\u00A0', '\u1680', '\u2028', '\u2029', '\u202F', '\u205F', '\u3000', '\uFEFF':
		return true
	}
	return r >= '\u2000' && r <= '\u200A'
}

// Trim trims JavaScript white space from both ends.
func Trim(s string) string { return strings.TrimFunc(s, IsSpace) }

// TrimEnd trims JavaScript white space from the end.
func TrimEnd(s string) string { return strings.TrimRightFunc(s, IsSpace) }

// Map is an insertion-ordered string map. A name that is set again keeps its
// original position (like a JavaScript object).
type Map struct {
	keys []string
	m    map[string]string
}

// NewMap returns an empty Map.
func NewMap() *Map { return &Map{m: map[string]string{}} }

// Set sets k to v.
func (o *Map) Set(k, v string) {
	if _, ok := o.m[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.m[k] = v
}

// Get returns the value of k.
func (o *Map) Get(k string) (string, bool) {
	if o == nil {
		return "", false
	}
	v, ok := o.m[k]
	return v, ok
}

// Keys returns the keys in insertion order.
func (o *Map) Keys() []string {
	if o == nil {
		return nil
	}
	return append([]string(nil), o.keys...)
}

// Len returns the number of keys.
func (o *Map) Len() int {
	if o == nil {
		return 0
	}
	return len(o.keys)
}

// Clone returns a copy.
func (o *Map) Clone() *Map {
	c := NewMap()
	for _, k := range o.Keys() {
		c.Set(k, o.m[k])
	}
	return c
}

// Sections is an insertion-ordered map of section name to its keys.
type Sections struct {
	names []string
	m     map[string]*Map
}

func newSections() *Sections { return &Sections{m: map[string]*Map{}} }

// Get returns the keys of section name.
func (s *Sections) Get(name string) (*Map, bool) {
	if s == nil {
		return nil, false
	}
	v, ok := s.m[name]
	return v, ok
}

// Names returns the section names in order of first appearance.
func (s *Sections) Names() []string {
	if s == nil {
		return nil
	}
	return append([]string(nil), s.names...)
}

func (s *Sections) ensure(name string) *Map {
	if v, ok := s.m[name]; ok {
		return v
	}
	v := NewMap()
	s.names = append(s.names, name)
	s.m[name] = v
	return v
}

func (s *Sections) put(name string, v *Map) {
	if _, ok := s.m[name]; !ok {
		s.names = append(s.names, name)
	}
	s.m[name] = v
}

// File is a parsed credential file.
type File struct {
	// Raw holds the values as written, per section incl. DEFAULT, not merged.
	Raw *Sections
	// Merged holds every section except DEFAULT with DEFAULT values inherited.
	Merged *Sections
	// Desc is the file-level doc (before the first section or in [DEFAULT]).
	Desc []string
	// SecDesc is the doc of each (non-DEFAULT) section.
	SecDesc map[string][]string
	// Encrypt is the file-level @encrypt spec, if any (HasEncrypt tells).
	Encrypt    string
	HasEncrypt bool
	// EncryptIgnored lists sections that carry an @encrypt tag (ignored).
	EncryptIgnored []string
}

// ParseValue returns the value of an assignment's right-hand side.
// Value forms:  plain ; comment  |  "quoted ; kept" ; comment  |  "quoted".
// An inline comment needs white space before ; or #, so `pa;ss` stays intact.
func ParseValue(v string) string {
	r := []rune(v)
	if len(r) > 0 && (r[0] == '"' || r[0] == '\'') {
		q := r[0]
		// "quoted" ; comment — the first closing quote followed by a comment.
		for j := 1; j < len(r); j++ {
			if isLineTerm(r[j]) {
				break
			}
			if r[j] != q {
				continue
			}
			k := j + 1
			for k < len(r) && IsSpace(r[k]) {
				k++
			}
			if k < len(r) && (r[k] == ';' || r[k] == '#') {
				return string(r[1:j])
			}
		}
		// "quoted" — whole value.
		if len(r) >= 2 && r[len(r)-1] == q && !containsLineTerm(r[1:len(r)-1]) {
			return string(r[1 : len(r)-1])
		}
	}
	for i := 0; i < len(r); i++ {
		if !IsSpace(r[i]) {
			continue
		}
		j := i
		for j < len(r) && IsSpace(r[j]) {
			j++
		}
		if j < len(r) && (r[j] == ';' || r[j] == '#') && !containsLineTerm(r[j:]) {
			return string(r[:i])
		}
	}
	return v
}

func isLineTerm(r rune) bool { return r == '\n' || r == '\r' || r == '\u2028' || r == '\u2029' }

func containsLineTerm(r []rune) bool {
	for _, c := range r {
		if isLineTerm(c) {
			return true
		}
	}
	return false
}

// FormatValue is the inverse of ParseValue: it quotes a value when the plain
// form would not read back as-is.
func FormatValue(v string) (string, bool) {
	if !needQuote.MatchString(v) {
		return v, true
	}
	if !strings.Contains(v, `"`) {
		return `"` + v + `"`, true
	}
	if !strings.Contains(v, "'") {
		return "'" + v + "'", true
	}
	return "", false
}

// EncodeValue returns the right-hand side to write for v, or false when no
// form reads back as v (ParseValue of the trimmed line value): a line break,
// both quote characters, or a quoted value holding U+2028 / U+2029 (which
// the parser, like VaneSecret's, does not unquote).
func EncodeValue(v string) (string, bool) {
	if strings.ContainsAny(v, "\r\n") {
		return "", false
	}
	f, ok := FormatValue(v)
	if !ok || ParseValue(Trim(f)) != v {
		return "", false
	}
	return f, true
}

// Parse parses the text of a credential file.
func Parse(text string) *File {
	raw := newSections()
	descs := map[string][]string{"": {}}
	var cur *Map
	curName := ""
	block := ""
	f := &File{SecDesc: map[string][]string{}}
	text = strings.TrimPrefix(text, "\uFEFF")
	for _, rawLine := range lineSplit.Split(text, -1) {
		line := Trim(rawLine)
		scope := curName
		if curName == "DEFAULT" {
			scope = ""
		}
		if t := tagRe.FindStringSubmatch(line); t != nil {
			block = t[1]
			switch block {
			case "desc":
				lines := descs[scope]
				if len(lines) > 0 {
					lines = append(lines, "") // separate consecutive @desc blocks
				}
				if Trim(t[2]) != "" {
					lines = append(lines, TrimEnd(t[2]))
				}
				descs[scope] = lines
			case "encrypt":
				if scope == "" {
					f.Encrypt, f.HasEncrypt = Trim(t[2]), true
				} else {
					f.EncryptIgnored = append(f.EncryptIgnored, curName)
				}
			}
			continue
		}
		if c := commentRe.FindStringSubmatch(line); c != nil {
			if block == "desc" && !CommentedAssign.MatchString(line) {
				descs[scope] = append(descs[scope], TrimEnd(c[1]))
			}
			continue // untagged / other-tag comments: skipped
		}
		block = "" // blank line, key or [section] ends a block
		if line == "" {
			continue
		}
		if s := sectionRe.FindStringSubmatch(line); s != nil {
			curName = Trim(s[1])
			cur = raw.ensure(curName)
			continue
		}
		eq := strings.Index(line, "=")
		if eq < 0 || cur == nil {
			continue
		}
		cur.Set(Trim(line[:eq]), ParseValue(Trim(line[eq+1:])))
	}
	def, _ := raw.Get("DEFAULT")
	merged := newSections()
	for _, name := range raw.Names() {
		if name == "DEFAULT" {
			continue
		}
		m := NewMap()
		if def != nil {
			for _, k := range def.Keys() {
				v, _ := def.Get(k)
				m.Set(k, v)
			}
		}
		sec, _ := raw.Get(name)
		for _, k := range sec.Keys() {
			v, _ := sec.Get(k)
			m.Set(k, v)
		}
		merged.put(name, m)
	}
	f.Raw, f.Merged = raw, merged
	f.Desc = descLines(descs[""])
	for _, name := range merged.Names() {
		f.SecDesc[name] = descLines(descs[name])
	}
	return f
}

// descLines keeps inner blank lines (paragraphs) and drops leading/trailing ones.
func descLines(a []string) []string {
	l := append([]string(nil), a...)
	for len(l) > 0 && Trim(l[0]) == "" {
		l = l[1:]
	}
	for len(l) > 0 && Trim(l[len(l)-1]) == "" {
		l = l[:len(l)-1]
	}
	return l
}
