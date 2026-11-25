package admin

import (
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/VanePulse/GSeal/internal/fault"
	"github.com/VanePulse/GSeal/internal/ini"
	"github.com/VanePulse/GSeal/internal/msg"
	"github.com/VanePulse/GSeal/internal/store"
)

// Import file values: <hold> keep the stored value; <delete> remove the key;
// <fill> must be filled; anything else is the new value. Keys and sections
// missing from the import file are kept. Nothing is written unless the whole
// file validates.

var (
	keyName    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	preRestore = regexp.MustCompile(`^pre-restore-\d{8}T\d+$`)
	lineSplit  = regexp.MustCompile(`\r?\n`)
)

func faultAt(p string) error { return fault.At(p) }
func sortStrings(s []string) { sort.Strings(s) }

func splitLines(text string) []string {
	return lineSplit.Split(strings.TrimPrefix(text, "\uFEFF"), -1)
}

// sectionLine returns the section name of a trimmed line, or nil.
func sectionLine(t string) *string {
	if len(t) < 3 || t[0] != '[' || t[len(t)-1] != ']' {
		return nil
	}
	inner := t[1 : len(t)-1]
	if strings.Contains(inner, "]") {
		return nil
	}
	n := ini.Trim(inner)
	return &n
}

func isComment(t string) bool { return strings.HasPrefix(t, ";") || strings.HasPrefix(t, "#") }

// splitInlineComment returns the inline comment suffix of a raw value
// (" ; comment"), read the same way ini.ParseValue reads it; "" if none.
func splitInlineComment(raw string) string {
	r := []rune(raw)
	if len(r) > 0 && (r[0] == '"' || r[0] == '\'') {
		q := r[0]
		for j := 1; j < len(r); j++ {
			if r[j] == '\n' || r[j] == '\r' || r[j] == '\u2028' || r[j] == '\u2029' {
				break
			}
			if r[j] != q {
				continue
			}
			k := j + 1
			for k < len(r) && ini.IsSpace(r[k]) {
				k++
			}
			if k < len(r) && (r[k] == ';' || r[k] == '#') {
				return string(r[j+1:])
			}
		}
		if len(r) >= 2 && r[len(r)-1] == q {
			return ""
		}
	}
	for i := 0; i < len(r); i++ {
		if !ini.IsSpace(r[i]) {
			continue
		}
		j := i
		for j < len(r) && ini.IsSpace(r[j]) {
			j++
		}
		if j < len(r) && (r[j] == ';' || r[j] == '#') {
			return string(r[i:])
		}
	}
	return ""
}

// storeBlocks returns the lines of each [section] of a stored file, as
// written (for keeping sections the import file leaves out, docs included).
func storeBlocks(text string) map[string][]string {
	blocks := map[string][]string{}
	cur := ""
	in := false
	for _, l := range splitLines(text) {
		if s := sectionLine(ini.Trim(l)); s != nil {
			cur, in = *s, true
			blocks[cur] = []string{l}
			continue
		}
		if in {
			blocks[cur] = append(blocks[cur], l)
		}
	}
	for k, b := range blocks {
		for len(b) > 1 && ini.Trim(b[len(b)-1]) == "" {
			b = b[:len(b)-1]
		}
		blocks[k] = b
	}
	return blocks
}

type block struct {
	name  string
	lines []string
}

type report struct{ added, updated, deleted, kept []string }

// upperSet is a set of upper-cased key names.
type upperSet map[string]bool

func (a *Admin) cmdImport(fac string) (int, error) {
	if err := checkFac(fac); err != nil {
		return ExitFail, err
	}
	ipath := a.importFile(fac)
	rawBytes, err := os.ReadFile(ipath)
	if err != nil {
		return ExitFail, msg.Errorf(msg.ImportNoFile, ipath)
	}
	spath := a.facFile(fac)
	storeText := ""
	if b, err := os.ReadFile(spath); err == nil {
		storeText = string(b)
	}
	st := ini.Parse(storeText).Raw // section -> key -> stored value
	raw := string(rawBytes)
	// NUL bytes never occur in a hand-edited ini; they mean a damaged file.
	if strings.ContainsRune(raw, 0) {
		return ExitFail, msg.Errorf(msg.ImportNUL, ipath, fac)
	}
	spec, err := a.specFor(fac, ini.Parse(raw))
	if err != nil {
		return ExitFail, err
	}
	secret := func(key string) bool { return spec.Encrypt(key, a.Plain) }
	lines := splitLines(raw)

	// Keys are matched without regard to case (variable names are upper-cased
	// on injection): section -> UPPER -> stored spellings.
	storeKeys := map[string]map[string][]string{}
	var storeSecs []string
	for _, sec := range st.Names() {
		m, _ := st.Get(sec)
		g := map[string][]string{}
		for _, k := range m.Keys() {
			K := strings.ToUpper(k)
			g[K] = append(g[K], k)
		}
		storeKeys[sec] = g
		storeSecs = append(storeSecs, sec)
	}
	stored := func(sec, key string) (string, bool) {
		m, ok := st.Get(sec)
		if !ok {
			return "", false
		}
		return m.Get(key)
	}

	var errs, notes []string
	var pre []string
	var blocks []*block
	seen := map[string]upperSet{}
	deleted := map[string]upperSet{}
	reports := map[string]*report{}
	var repOrder []string
	rep := func(sec string) *report {
		if r, ok := reports[sec]; ok {
			return r
		}
		r := &report{}
		reports[sec] = r
		repOrder = append(repOrder, sec)
		return r
	}
	var cur *block
	push := func(l string) {
		if cur != nil {
			cur.lines = append(cur.lines, l)
		} else {
			pre = append(pre, l)
		}
	}
	enc := func(sec, key, plain string) (string, error) {
		dk, err := a.St.DataKey()
		if err != nil {
			return "", err
		}
		return store.Encrypt(dk, fac, sec, key, plain)
	}
	plainOf := func(sec, key, v string) (string, error) {
		if !store.IsEnc(v) {
			return v, nil
		}
		dk, err := a.St.DataKey()
		if err != nil {
			return "", err
		}
		p, err := store.Decrypt(dk, fac, sec, key, v)
		if err != nil {
			return "", msg.Errorf(msg.DecryptFailed, fac, sec, key)
		}
		return p, nil
	}
	// Stored form for key keeping the value old had under oldKey. Encrypted
	// values stay encrypted (an import never decrypts); they are re-encrypted
	// when the spelling changed, since the ciphertext is bound to the key name.
	keepAs := func(sec, key, oldKey, old string) (string, error) {
		if store.IsEnc(old) {
			if oldKey == key {
				return old, nil
			}
			p, err := plainOf(sec, oldKey, old)
			if err != nil {
				return "", err
			}
			return enc(sec, key, p)
		}
		if secret(key) {
			return enc(sec, key, old)
		}
		return old, nil
	}
	format := func(v string) (string, error) {
		f, ok := ini.EncodeValue(v)
		if !ok {
			return "", msg.Errorf(msg.ImpBothQuotes)
		}
		return f, nil
	}

	for i, rawLine := range lines {
		n := i + 1
		t := ini.Trim(rawLine)
		if t == "" {
			push(rawLine)
			continue
		}
		if isComment(t) {
			if ini.CommentedAssign.MatchString(t) {
				errs = append(errs, msg.Text(msg.ImpCommented, n))
			}
			push(rawLine)
			continue
		}
		if s := sectionLine(t); s != nil {
			name := *s
			if !store.NameRe.MatchString(name) {
				errs = append(errs, msg.Text(msg.ImpBadSection, n, name))
			}
			if _, dup := seen[name]; dup {
				errs = append(errs, msg.Text(msg.ImpDupSection, n, name))
			}
			seen[name] = upperSet{}
			deleted[name] = upperSet{}
			cur = &block{name: name, lines: []string{rawLine}}
			blocks = append(blocks, cur)
			continue
		}
		eq := strings.Index(t, "=")
		if eq < 0 {
			errs = append(errs, msg.Text(msg.ImpUnrecognized, n))
			continue
		}
		if cur == nil {
			errs = append(errs, msg.Text(msg.ImpKeyFirst, n))
			continue
		}
		key := ini.Trim(t[:eq])
		rawVal := ini.Trim(t[eq+1:])
		if !keyName.MatchString(key) {
			errs = append(errs, msg.Text(msg.ImpBadKey, n, key))
			continue
		}
		sec := cur.name
		K := strings.ToUpper(key)
		if seen[sec][K] || deleted[sec][K] {
			errs = append(errs, msg.Text(msg.ImpDupKey, n, sec, key))
			continue
		}
		group := storeKeys[sec][K]
		oldKey, old, hasOld := "", "", false
		if len(group) == 1 {
			oldKey = group[0]
			old, hasOld = stored(sec, oldKey)
		}
		v := ini.ParseValue(rawVal)
		comment := splitInlineComment(rawVal)
		if comment != "" && a.hidden(spec, key, v) {
			notes = append(notes, msg.Text(msg.ImpCommentGone, n, key))
			comment = ""
		}
		if len(group) > 1 {
			notes = append(notes, msg.Text(msg.ImpCaseMerged, n, sec, strings.Join(group, ", "), key))
		} else if hasOld && oldKey != key {
			notes = append(notes, msg.Text(msg.ImpRenamed, n, sec, oldKey, key))
		}
		if v == "<fill>" {
			errs = append(errs, msg.Text(msg.ImpFill, n, sec, key))
			continue
		}
		if v == "<delete>" {
			if len(group) == 0 {
				notes = append(notes, msg.Text(msg.ImpDeleteNone, n, sec, key))
			} else {
				rep(sec).deleted = append(rep(sec).deleted, group...)
			}
			deleted[sec][K] = true
			continue
		}
		seen[sec][K] = true
		var out string
		err := func() error {
			switch {
			case v == "<hold>":
				if len(group) > 1 {
					errs = append(errs, msg.Text(msg.ImpHoldAmbig, n, sec, key, strings.Join(group, ", ")))
					return nil
				}
				if !hasOld {
					errs = append(errs, msg.Text(msg.ImpHoldNone, n, sec, key))
					return nil
				}
				s, err := keepAs(sec, key, oldKey, old)
				if err != nil {
					return err
				}
				out = s
				rep(sec).kept = append(rep(sec).kept, key)
			default:
				same := false
				if hasOld {
					p, err := plainOf(sec, oldKey, old)
					if err != nil {
						return err
					}
					same = p == v
				}
				if same { // unchanged: keep the ciphertext
					s, err := keepAs(sec, key, oldKey, old)
					if err != nil {
						return err
					}
					out = s
					rep(sec).kept = append(rep(sec).kept, key)
					break
				}
				if secret(key) {
					s, err := enc(sec, key, v)
					if err != nil {
						return err
					}
					out = s
				} else {
					out = v
				}
				if len(group) > 0 {
					rep(sec).updated = append(rep(sec).updated, key)
				} else {
					rep(sec).added = append(rep(sec).added, key)
				}
			}
			f, err := format(out)
			if err != nil {
				return err
			}
			cur.lines = append(cur.lines, key+" = "+f+comment)
			return nil
		}()
		if err != nil {
			errs = append(errs, msg.Text(msg.ImpValueErr, n, sec, key, err.Error()))
		}
	}

	// Keys and sections missing from the import file are kept. A whole missing
	// section is kept as written (docs and comments included; plaintext
	// secrets get encrypted, as in a migration).
	original := storeBlocks(storeText)
	findBlock := func(sec string) *block {
		for _, b := range blocks {
			if b.name == sec {
				return b
			}
		}
		return nil
	}
	for _, sec := range storeSecs {
		groups := storeKeys[sec]
		var order []string // upper names in store order
		for _, k := range func() []string { m, _ := st.Get(sec); return m.Keys() }() {
			K := strings.ToUpper(k)
			if len(order) == 0 || !contains(order, K) {
				order = append(order, K)
			}
		}
		b := findBlock(sec)
		var missing []string
		for _, K := range order {
			if b != nil && (seen[sec][K] || deleted[sec][K]) {
				continue
			}
			missing = append(missing, K)
		}
		for _, K := range missing {
			if g := groups[K]; len(g) > 1 {
				errs = append(errs, msg.Text(msg.ImpStoreClash, sec, strings.Join(g, ", ")))
			}
		}
		if b == nil {
			lines, ok := original[sec]
			if !ok {
				lines = []string{"[" + sec + "]"}
			}
			out := []string{""}
			for _, l := range lines {
				t := ini.Trim(l)
				eq := strings.Index(t, "=")
				if t == "" || isComment(t) || sectionLine(t) != nil || eq < 0 {
					out = append(out, l)
					continue
				}
				k := ini.Trim(t[:eq])
				v, ok := stored(sec, k)
				if !ok || !secret(k) || store.IsEnc(v) {
					out = append(out, l)
					continue
				}
				s, err := enc(sec, k, v)
				if err == nil {
					s, err = format(s)
				}
				if err != nil {
					errs = append(errs, msg.Text(msg.ImpKeyErr, sec, k, err.Error()))
					out = append(out, l)
					continue
				}
				out = append(out, k+" = "+s)
			}
			blocks = append(blocks, &block{name: sec, lines: out})
			notes = append(notes, msg.Text(msg.ImpSectionKept, sec))
			for _, K := range missing {
				rep(sec).kept = append(rep(sec).kept, groups[K]...)
			}
			continue
		}
		var keepKeys []string
		for _, K := range missing {
			if g := groups[K]; len(g) == 1 {
				keepKeys = append(keepKeys, g[0])
			}
		}
		if len(keepKeys) == 0 {
			continue
		}
		at := len(b.lines)
		for at > 1 && ini.Trim(b.lines[at-1]) == "" {
			at-- // before trailing blank lines
		}
		var add []string
		for _, k := range keepKeys {
			v, _ := stored(sec, k)
			s := v
			var err error
			if secret(k) && !store.IsEnc(v) {
				s, err = enc(sec, k, v)
			}
			if err == nil {
				s, err = format(s)
			}
			if err != nil {
				errs = append(errs, msg.Text(msg.ImpKeyErr, sec, k, err.Error()))
				continue
			}
			add = append(add, k+" = "+s)
		}
		b.lines = append(b.lines[:at], append(add, b.lines[at:]...)...)
		rep(sec).kept = append(rep(sec).kept, keepKeys...)
		notes = append(notes, msg.Text(msg.ImpKeysKept, sec, strings.Join(keepKeys, ", ")))
	}

	if len(errs) > 0 {
		a.say(msg.Text(msg.ImpFailed, fac))
		for _, e := range errs {
			a.say(msg.Text(msg.ItemBad, e))
		}
		for _, x := range notes {
			a.say(msg.Text(msg.ItemNote, x))
		}
		return ExitFail, nil
	}

	all := append([]string{}, pre...)
	for _, b := range blocks {
		all = append(all, b.lines...)
	}
	text := strings.TrimRight(strings.Join(all, "\n"), "\n") + "\n"
	// Sanity check before replacing anything: every value must decrypt, and
	// the key set each node gets on injection ([DEFAULT] merged in) must not
	// contain two keys that differ only in case.
	if err := a.selfCheck(fac, text); err != nil {
		return ExitFail, msg.Errorf(msg.ImpSelfCheck, err.Error())
	}

	bak, err := a.localBackup(spath, fac+".ini")
	if err != nil {
		return ExitFail, err
	}
	if err := faultAt("before-commit"); err != nil {
		return ExitFail, err
	}
	if err := atomicWrite(spath, []byte(text), false); err != nil { // <- commit point
		return ExitFail, err
	}

	// After the commit nothing may report "unchanged": every failure from
	// here on is listed and turned into exit 3.
	var pending []string
	if err := faultAt("after-commit"); err != nil {
		pending = append(pending, msg.Text(msg.ImpShredErr, err.Error()))
	} else if gone, err := a.shred(ipath); err != nil {
		pending = append(pending, msg.Text(msg.ImpShredErr, err.Error()))
	} else if !gone {
		pending = append(pending, msg.Text(msg.ImpShredLeft, ipath+shredding))
	}
	done := msg.Text(msg.ImpDoneNew, fac)
	if bak != "" {
		done = msg.Text(msg.ImpDoneBackup, fac, bak)
	}
	if len(pending) == 0 {
		done += msg.Text(msg.ImpFileDeleted)
	}
	a.say(done)
	for _, sec := range repOrder {
		r := reports[sec]
		var parts []string
		for _, p := range []struct {
			id   msg.ID
			list []string
		}{{msg.RepAdded, r.added}, {msg.RepUpdated, r.updated}, {msg.RepDeleted, r.deleted}} {
			if len(p.list) > 0 {
				parts = append(parts, msg.Text(p.id, strings.Join(p.list, ", ")))
			}
		}
		line := msg.Text(msg.RepNone)
		if len(parts) > 0 {
			line = strings.Join(parts, msg.Text(msg.RepSep))
		}
		a.say(msg.Text(msg.RepLine, sec, line))
	}
	for _, x := range notes {
		a.say(msg.Text(msg.ItemNote, x))
	}
	if ab := a.autoBackup(); ab != "" {
		pending = append(pending, ab)
	}
	if len(pending) > 0 {
		a.warn(msg.Text(msg.Committed, ExitCommittedIncomplete))
		for _, p := range pending {
			a.warn(msg.Text(msg.PendingItem, p))
		}
		a.warn(msg.Text(msg.CommittedHint))
		return ExitCommittedIncomplete, nil
	}
	return ExitOK, nil
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func (a *Admin) selfCheck(fac, text string) error {
	f := ini.Parse(text)
	if _, err := a.St.DecryptRaw(fac, f); err != nil {
		return err
	}
	var def []string
	if m, ok := f.Raw.Get("DEFAULT"); ok {
		def = m.Keys()
	}
	for _, sec := range f.Raw.Names() {
		m, _ := f.Raw.Get(sec)
		type origin struct{ key, from string }
		spell := map[string]origin{}
		sources := []struct {
			from string
			keys []string
		}{{"[" + sec + "]", m.Keys()}}
		if sec != "DEFAULT" {
			sources = append([]struct {
				from string
				keys []string
			}{{"[DEFAULT]", def}}, sources...)
		}
		for _, src := range sources {
			for _, k := range src.keys {
				K := strings.ToUpper(k)
				if o, ok := spell[K]; ok && o.key != k {
					return msg.Errorf(msg.ImpCaseClash, sec, k, o.from, o.key)
				}
				spell[K] = origin{k, src.from}
			}
		}
	}
	return nil
}
