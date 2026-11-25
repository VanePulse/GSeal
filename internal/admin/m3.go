package admin

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/VanePulse/GSeal/internal/ini"
	"github.com/VanePulse/GSeal/internal/keys"
	"github.com/VanePulse/GSeal/internal/msg"
	"github.com/VanePulse/GSeal/internal/store"
)

// rewriteValues returns text with the value of every assignment inside a
// section replaced by fn(section, key, stored) when fn reports a change.
// Comments, blank lines, docs and inline comments are kept.
func rewriteValues(text string, fn func(sec, key, stored string) (string, bool, error)) (string, bool, error) {
	lines := splitLines(text)
	cur := ""
	in := false
	changed := false
	for i, l := range lines {
		t := ini.Trim(l)
		if s := sectionLine(t); s != nil {
			cur, in = *s, true
			continue
		}
		eq := strings.Index(t, "=")
		if !in || t == "" || isComment(t) || eq < 0 {
			continue
		}
		key := ini.Trim(t[:eq])
		raw := ini.Trim(t[eq+1:])
		nv, ok, err := fn(cur, key, ini.ParseValue(raw))
		if err != nil {
			return "", false, err
		}
		if !ok {
			continue
		}
		f, fok := ini.EncodeValue(nv)
		if !fok {
			return "", false, msg.Errorf(msg.ImpKeyErr, cur, key, msg.Text(msg.ImpBothQuotes))
		}
		lines[i] = key + " = " + f + splitInlineComment(raw)
		changed = true
	}
	return strings.Join(lines, "\n"), changed, nil
}

// stageSwap writes files (name -> content) and optional extra staged files
// into env/.<op>-<ts>/ and swaps them in through the journal. Out are the
// names replaced; the previous files go to .backup/pre-<op>-<ts>/.
func (a *Admin) stageSwap(op string, files map[string]string, extra func(staging string) error) (string, error) {
	ts := stamp()
	staging := filepath.Join(a.St.Env, "."+op+"-"+ts)
	err := func() error {
		if err := ensureDir(staging); err != nil {
			return err
		}
		for name, text := range files {
			if err := atomicWrite(filepath.Join(staging, name), []byte(text), false); err != nil {
				return err
			}
		}
		if extra != nil {
			if err := extra(staging); err != nil {
				return err
			}
		}
		return faultAt(op + "-staging")
	}()
	if err != nil {
		os.RemoveAll(staging)
		return "", err
	}
	names := listNames(staging)
	var out []string
	for _, n := range names {
		if exists(filepath.Join(a.St.Env, n)) {
			out = append(out, n)
		}
	}
	aside := filepath.Join(a.localBackupDir(), "pre-"+op+"-"+ts)
	j := &journal{Op: op, TS: ts, Out: nonNil(out), OutDir: aside, In: names, InDir: staging}
	return aside, a.commitSwap(j)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// afterChange finishes a committed change: one automatic backup; exit 3 if
// it did not complete.
func (a *Admin) afterChange() int {
	ab := a.autoBackup()
	if ab == "" {
		return ExitOK
	}
	a.warn(msg.Text(msg.ChangedPending, ExitCommittedIncomplete))
	a.warn(msg.Text(msg.PendingItem, ab))
	a.warn(msg.Text(msg.ChangedHint))
	return ExitCommittedIncomplete
}

// ------------------------------------------------------------ --apply-policy ----

type planItem struct {
	sec, key string
	encrypt  bool
}

func (a *Admin) cmdApplyPolicy(args []string) (int, error) {
	dry, allowDecrypt := false, false
	for _, x := range args {
		switch x {
		case "--dry-run":
			dry = true
		case "--allow-decrypt":
			allowDecrypt = true
		default:
			return ExitFail, msg.Errorf(msg.UnknownCmd, x)
		}
	}
	if !dry {
		if err := a.acquireLock("--apply-policy"); err != nil {
			return ExitFail, err
		}
	}
	var dk []byte
	key := func() ([]byte, error) {
		if dk == nil {
			var err error
			if dk, err = a.St.DataKey(); err != nil {
				return nil, err
			}
		}
		return dk, nil
	}
	newFiles := map[string]string{}
	totEnc, totDec, skipped, nfiles := 0, 0, 0, 0
	facs, err := a.St.Facilities()
	if err != nil {
		return ExitFail, err
	}
	for _, fac := range facs {
		b, err := os.ReadFile(a.facFile(fac))
		if err != nil {
			return ExitFail, err
		}
		text := string(b)
		spec, err := a.specFor(fac, ini.Parse(text))
		if err != nil {
			return ExitFail, err
		}
		var plan []planItem
		_, _, _ = rewriteValues(text, func(sec, k, v string) (string, bool, error) {
			want := spec.Encrypt(k, a.Plain)
			if want != store.IsEnc(v) {
				plan = append(plan, planItem{sec, k, want})
			}
			return "", false, nil
		})
		ne, nd := 0, 0
		for _, p := range plan {
			if p.encrypt {
				ne++
			} else {
				nd++
			}
		}
		a.say(msg.Text(msg.ApplyFile, fac, ne, nd))
		for _, p := range plan {
			switch {
			case p.encrypt:
				a.say(msg.Text(msg.ApplyEncrypt, p.sec, p.key))
			case allowDecrypt:
				a.say(msg.Text(msg.ApplyDecrypt, p.sec, p.key))
			default:
				a.say(msg.Text(msg.ApplyNoDecrypt, p.sec, p.key))
			}
		}
		totEnc += ne
		totDec += nd
		if !allowDecrypt {
			skipped += nd
		}
		applied := ne
		if allowDecrypt {
			applied += nd
		}
		if dry || applied == 0 {
			continue
		}
		nt, changed, err := rewriteValues(text, func(sec, k, v string) (string, bool, error) {
			want := spec.Encrypt(k, a.Plain)
			switch {
			case want && !store.IsEnc(v):
				kk, err := key()
				if err != nil {
					return "", false, err
				}
				s, err := store.Encrypt(kk, fac, sec, k, v)
				return s, true, err
			case !want && store.IsEnc(v) && allowDecrypt:
				kk, err := key()
				if err != nil {
					return "", false, err
				}
				p, err := store.Decrypt(kk, fac, sec, k, v)
				if err != nil {
					return "", false, msg.Errorf(msg.DecryptFailed, fac, sec, k)
				}
				return p, true, nil
			}
			return "", false, nil
		})
		if err != nil {
			return ExitFail, err
		}
		if changed {
			if err := a.selfCheck(fac, nt); err != nil {
				return ExitFail, msg.Errorf(msg.ImpSelfCheck, err.Error())
			}
			newFiles[fac+".ini"] = nt
			nfiles++
		}
	}
	a.say(msg.Text(msg.ApplyTotal, totEnc, totDec, len(facs)))
	if dry {
		a.say(msg.Text(msg.ApplyDryRun))
		return ExitOK, nil
	}
	if len(newFiles) == 0 {
		a.say(msg.Text(msg.ApplyNothing))
		if skipped > 0 {
			a.say(msg.Text(msg.ApplySkipped, skipped))
		}
		return ExitOK, nil
	}
	aside, err := a.stageSwap(opApply, newFiles, nil)
	if err != nil {
		return ExitFail, err
	}
	dec := 0
	if allowDecrypt {
		dec = totDec
	}
	a.say(msg.Text(msg.ApplyDone, totEnc, dec, nfiles))
	a.say(msg.Text(msg.ApplyAside, aside))
	if skipped > 0 {
		a.say(msg.Text(msg.ApplySkipped, skipped))
	}
	return a.afterChange(), nil
}

// --------------------------------------------------------------------- --set ----

var setTarget = regexp.MustCompile(`^([\w-]+)\.([\w-]+)$`)

// setPlan locates key in [sec] of text: the line to replace (-1: none), the
// stored spelling and value, and where a new key would go.
type setPlan struct {
	text       string
	exists     bool // file exists
	secFound   bool
	line       int // assignment line of the key (last one), -1 if none
	spelling   string
	old        string
	spellings  []string
	insertAt   int // line index to insert a new key at (in the section)
	fileParsed *ini.File
}

func (a *Admin) planSet(fac, sec, key string) (*setPlan, error) {
	p := &setPlan{line: -1, insertAt: -1}
	b, err := os.ReadFile(a.facFile(fac))
	if err == nil {
		p.exists = true
		p.text = string(b)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	p.fileParsed = ini.Parse(p.text)
	lines := splitLines(p.text)
	cur, in := "", false
	seen := map[string]bool{}
	for i, l := range lines {
		t := ini.Trim(l)
		if s := sectionLine(t); s != nil {
			cur, in = *s, true
			if cur == sec {
				p.secFound = true
				p.insertAt = i + 1
			}
			continue
		}
		if !in || cur != sec || t == "" {
			continue
		}
		if !isComment(t) {
			p.insertAt = i + 1
		}
		eq := strings.Index(t, "=")
		if isComment(t) || eq < 0 {
			continue
		}
		k := ini.Trim(t[:eq])
		if strings.EqualFold(k, key) {
			p.line, p.spelling, p.old = i, k, ini.ParseValue(ini.Trim(t[eq+1:]))
			if !seen[k] {
				seen[k] = true
				p.spellings = append(p.spellings, k)
			}
		}
	}
	return p, nil
}

func (a *Admin) checkSet(p *setPlan, fac, sec, key string, create bool) error {
	switch {
	case !p.exists && !create:
		return msg.Errorf(msg.SetNoFile, fac)
	case !p.secFound && !create:
		return msg.Errorf(msg.SetNoSection, fac, sec)
	case len(p.spellings) > 1:
		return msg.Errorf(msg.SetAmbiguous, sec, fac, strings.Join(p.spellings, ", "))
	case p.line < 0 && !create:
		return msg.Errorf(msg.SetNoKey, sec, fac, key)
	}
	return nil
}

func (a *Admin) cmdSet(args []string) (int, error) {
	create := false
	var pos []string
	for _, x := range args {
		if x == "--create" {
			create = true
		} else {
			pos = append(pos, x)
		}
	}
	if len(pos) != 2 {
		return ExitFail, msg.Errorf(msg.SetBadTarget)
	}
	m := setTarget.FindStringSubmatch(pos[0])
	if m == nil || !keyName.MatchString(pos[1]) {
		return ExitFail, msg.Errorf(msg.SetBadTarget)
	}
	fac, sec, key := m[1], m[2], pos[1]
	p, err := a.planSet(fac, sec, key)
	if err != nil {
		return ExitFail, err
	}
	if err := a.checkSet(p, fac, sec, key, create); err != nil {
		return ExitFail, err
	}
	// The value first (not holding the lock while typing).
	ans, err := promptSecrets(msg.Text(msg.PromptValue, fac, sec, key))
	if err != nil {
		return ExitFail, err
	}
	value := ans[0]
	if value == "" {
		return ExitFail, msg.Errorf(msg.SetEmpty)
	}
	if err := a.acquireLock("--set"); err != nil {
		return ExitFail, err
	}
	// Under the lock: the file may have changed while typing.
	if p, err = a.planSet(fac, sec, key); err != nil {
		return ExitFail, err
	}
	if err := a.checkSet(p, fac, sec, key, create); err != nil {
		return ExitFail, err
	}
	spec, err := a.specFor(fac, p.fileParsed)
	if err != nil {
		return ExitFail, err
	}
	spelling := key
	if p.line >= 0 {
		spelling = p.spelling
	}
	encrypt := spec.Encrypt(spelling, a.Plain) || (p.line >= 0 && store.IsEnc(p.old))
	stored := value
	if encrypt {
		dk, err := a.St.DataKey()
		if err != nil {
			return ExitFail, err
		}
		if stored, err = store.Encrypt(dk, fac, sec, spelling, value); err != nil {
			return ExitFail, err
		}
	}
	f, ok := ini.EncodeValue(stored)
	if !ok {
		return ExitFail, msg.Errorf(msg.ImpBothQuotes)
	}
	lines := splitLines(p.text)
	switch {
	case p.line >= 0:
		t := ini.Trim(lines[p.line])
		raw := ini.Trim(t[strings.Index(t, "=")+1:])
		comment := splitInlineComment(raw)
		if encrypt || a.hidden(spec, spelling, value) {
			comment = ""
		}
		lines[p.line] = spelling + " = " + f + comment
	case p.secFound:
		lines = append(lines[:p.insertAt], append([]string{spelling + " = " + f}, lines[p.insertAt:]...)...)
	default:
		for len(lines) > 0 && ini.Trim(lines[len(lines)-1]) == "" {
			lines = lines[:len(lines)-1]
		}
		if len(lines) > 0 {
			lines = append(lines, "")
		}
		lines = append(lines, "["+sec+"]", spelling+" = "+f)
	}
	text := strings.TrimRight(strings.Join(lines, "\n"), "\n") + "\n"
	if err := a.selfCheck(fac, text); err != nil {
		return ExitFail, msg.Errorf(msg.ImpSelfCheck, err.Error())
	}
	if got, err := a.readBack(fac, text, sec, spelling); err != nil || got != value {
		return ExitFail, msg.Errorf(msg.ImpSelfCheck, msg.Text(msg.ImpKeyErr, sec, spelling, msg.Text(msg.ImpBothQuotes)))
	}
	if err := ensureDir(a.St.Env); err != nil {
		return ExitFail, err
	}
	bak, err := a.localBackup(a.facFile(fac), fac+".ini")
	if err != nil {
		return ExitFail, err
	}
	if err := faultAt("before-commit"); err != nil {
		return ExitFail, err
	}
	if err := atomicWrite(a.facFile(fac), []byte(text), false); err != nil {
		return ExitFail, err
	}
	how := msg.Text(msg.StoredPlain)
	if encrypt {
		how = msg.Text(msg.StoredEnc)
	}
	a.say(msg.Text(msg.SetDone, fac, sec, spelling, how))
	if bak != "" {
		a.say(msg.Text(msg.SetChanged, bak))
	}
	return a.afterChange(), nil
}

// readBack returns the value of key in [sec] as injection would see it.
func (a *Admin) readBack(fac, text, sec, key string) (string, error) {
	f := ini.Parse(text)
	m, ok := f.Raw.Get(sec)
	if !ok {
		return "", msg.Errorf(msg.SetNoSection, fac, sec)
	}
	v, ok := m.Get(key)
	if !ok {
		return "", msg.Errorf(msg.SetNoKey, sec, fac, key)
	}
	if !store.IsEnc(v) {
		return v, nil
	}
	dk, err := a.St.DataKey()
	if err != nil {
		return "", err
	}
	return store.Decrypt(dk, fac, sec, key, v)
}

// ---------------------------------------------------------- --rotate-datakey ----

func (a *Admin) cmdRotate() (int, error) {
	if !exists(a.St.DataKeyFile()) {
		return ExitFail, msg.Errorf(msg.RotateNoKey)
	}
	old, err := a.St.DataKey()
	if err != nil {
		return ExitFail, err
	}
	nk := make([]byte, 32)
	if _, err := rand.Read(nk); err != nil {
		return ExitFail, err
	}
	files := map[string]string{}
	count := 0
	facs, err := a.St.Facilities()
	if err != nil {
		return ExitFail, msg.Errorf(msg.RotateNotRun, err.Error())
	}
	for _, fac := range facs {
		b, err := os.ReadFile(a.facFile(fac))
		if err != nil {
			return ExitFail, err
		}
		nt, changed, err := rewriteValues(string(b), func(sec, k, v string) (string, bool, error) {
			if !store.IsEnc(v) {
				return "", false, nil
			}
			p, err := store.Decrypt(old, fac, sec, k, v)
			if err != nil {
				return "", false, msg.Errorf(msg.DecryptFailed, fac, sec, k)
			}
			s, err := store.Encrypt(nk, fac, sec, k, p)
			if err != nil {
				return "", false, err
			}
			count++
			return s, true, nil
		})
		if err != nil {
			return ExitFail, msg.Errorf(msg.RotateNotRun, err.Error())
		}
		if !changed {
			continue
		}
		// Every value opens with the new key and none with the old one.
		f := ini.Parse(nt)
		for _, sec := range f.Raw.Names() {
			m, _ := f.Raw.Get(sec)
			for _, k := range m.Keys() {
				v, _ := m.Get(k)
				if !store.IsEnc(v) {
					continue
				}
				_, e1 := store.Decrypt(nk, fac, sec, k, v)
				_, e2 := store.Decrypt(old, fac, sec, k, v)
				if e1 != nil || e2 == nil {
					return ExitFail, msg.Errorf(msg.RotateNotRun, msg.Text(msg.RotateCheck, fac+" ["+sec+"] "+k))
				}
			}
		}
		files[fac+".ini"] = nt
	}
	kb := a.St.KeyBackend()
	aside, err := a.stageSwap(opRotate, files, func(staging string) error {
		f := filepath.Join(staging, ".datakey.cred")
		if err := a.wrapTo(kb, keys.DataKeyName, nk, f, false); err != nil {
			return err
		}
		got, err := kb.Unwrap(keys.DataKeyName, f)
		if err != nil || string(got) != string(nk) {
			return msg.Errorf(msg.RestoreKeyDiff)
		}
		return nil
	})
	if err != nil {
		if _, ok := err.(swapPending); ok {
			return ExitSwapPending, err
		}
		if me, ok := err.(*msg.Error); ok && me.ID == msg.SwapRolledBack {
			return ExitFail, err
		}
		return ExitFail, msg.Errorf(msg.RotateNotRun, err.Error())
	}
	a.St.ForgetDataKey()
	a.say(msg.Text(msg.RotateDone, count, len(files)))
	a.say(msg.Text(msg.RotateOld, aside))
	return a.afterChange(), nil
}
