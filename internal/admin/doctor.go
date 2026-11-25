package admin

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/VanePulse/GSeal/internal/ini"
	"github.com/VanePulse/GSeal/internal/keys"
	"github.com/VanePulse/GSeal/internal/msg"
	"github.com/VanePulse/GSeal/internal/store"
)

// doctor checks the setup and prints one OK / WARN / FAIL line per item. It
// never prints a value, never takes the lock and never changes anything
// (an interrupted operation is reported, not completed). Exit 1 if any FAIL.
type doctor struct {
	a                 *Admin
	nOK, nWarn, nFail int
}

func (d *doctor) ok(id msg.ID, args ...any) {
	d.nOK++
	d.a.say(msg.Text(msg.DocOK, msg.Text(id, args...)))
}

func (d *doctor) warn(id msg.ID, args ...any) {
	d.nWarn++
	d.a.say(msg.Text(msg.DocWarn, msg.Text(id, args...)))
}

func (d *doctor) fail(id msg.ID, args ...any) {
	d.nFail++
	d.a.say(msg.Text(msg.DocFail, msg.Text(id, args...)))
}

const backupMaxAgeDays = 30

var systemdVersion = regexp.MustCompile(`^systemd (\d+)`)

func octal(m os.FileMode) string {
	o := strconv.FormatUint(uint64(m.Perm()), 8)
	for len(o) < 4 {
		o = "0" + o
	}
	return o
}

var errNotRegular = errors.New(msg.Text(msg.ReasonNotRegular))

func readReason(err error) string {
	if err == errNotRegular {
		return msg.Text(msg.ReasonNotRegular)
	}
	return store.ReadReason(err)
}

func backupKeyReason(err error) string {
	switch msg.IDOf(err) {
	case msg.CredsDecrypt, msg.StorePassWrong, msg.PassCredBad, msg.PassCredName:
		return err.Error() // backend messages hold no secret
	}
	return msg.Text(msg.DocBackupKeyBadJSON)
}

func ownedByMe(st os.FileInfo) bool {
	s, ok := st.Sys().(*syscall.Stat_t)
	return !ok || int(s.Uid) == os.Getuid()
}

func (a *Admin) cmdDoctor() (int, error) {
	d := &doctor{a: a}

	// Config and store.
	if a.Cfg.Present {
		d.ok(msg.DocConfig, a.Cfg.Path)
	} else {
		d.ok(msg.DocConfigNone, a.Cfg.Path)
	}
	d.ok(msg.DocStore, a.St.Root, a.Where)
	if v, err := a.St.FormatVersion(); err != nil {
		d.fail(msg.DocVersionBad, filepath.Join(a.St.Env, ".store-version")) // never the file's content
	} else if v > store.Version {
		d.fail(msg.DocVersionNew, v, store.Version)
	} else {
		d.ok(msg.DocVersion, v)
	}

	// Facility files that cannot be read (broken link, permission, ...):
	// FAIL, and the checks below cannot vouch for them.
	unreadable := map[string]bool{}
	var unreadList []string
	facs, listErr := a.St.Facilities()
	if listErr != nil {
		d.fail(msg.DocListFailed, listErr.Error())
		unreadList = append(unreadList, a.St.Env)
	}
	for _, fac := range facs {
		p := a.facFile(fac)
		st, err := os.Stat(p) // follows a link
		if err == nil && !st.Mode().IsRegular() {
			err = errNotRegular
		}
		if err == nil {
			var f *os.File
			if f, err = os.Open(p); err == nil {
				f.Close()
			}
		}
		if err != nil {
			unreadable[fac] = true
			unreadList = append(unreadList, fac+".ini ("+readReason(err)+")")
		}
	}
	if len(unreadList) > 0 && listErr == nil {
		d.fail(msg.DocUnreadable, strings.Join(unreadList, ", "))
	}

	// Permissions: env/ private, files mode 600, all owned by the user.
	permsOK := len(unreadList) == 0
	for _, dir := range []string{a.St.Root, a.St.Env} {
		st, err := os.Stat(dir)
		if err != nil {
			continue
		}
		if !ownedByMe(st) {
			d.fail(msg.DocNotOwned, dir)
			permsOK = false
		}
	}
	if st, err := os.Stat(a.St.Env); err == nil && st.Mode().Perm()&0o077 != 0 {
		d.warn(msg.DocDirMode, a.St.Env, octal(st.Mode().Perm()))
		permsOK = false
	}
	var loose []string
	for _, n := range listNames(a.St.Env) {
		if !strings.HasSuffix(n, ".ini") && !strings.HasSuffix(n, ".cred") && n != ".backup.json" {
			continue
		}
		st, err := os.Lstat(filepath.Join(a.St.Env, n))
		if err != nil || !st.Mode().IsRegular() {
			continue
		}
		if !ownedByMe(st) {
			d.fail(msg.DocNotOwned, filepath.Join(a.St.Env, n))
			permsOK = false
		} else if st.Mode().Perm()&0o077 != 0 {
			loose = append(loose, n)
		}
	}
	if len(loose) > 0 {
		d.warn(msg.DocFileModes, strings.Join(loose, ", "))
		permsOK = false
	}
	if permsOK {
		d.ok(msg.DocModesOK)
	}

	// Key backend and data key.
	kb := a.St.KeyBackend()
	d.ok(msg.DocBackend, kb.Name())
	if _, isSD := kb.(keys.SystemdCreds); isSD {
		out, err := exec.Command("systemd-creds", "--version").Output()
		if err != nil {
			d.fail(msg.DocSystemdNo, err.Error())
		} else if m := systemdVersion.FindSubmatch(out); m != nil {
			v, _ := strconv.Atoi(string(m[1]))
			if v >= 256 {
				d.ok(msg.DocSystemd, v)
			} else {
				d.fail(msg.DocSystemdOld, v)
			}
		}
	}
	_, isPW := kb.(keys.Passphrase)
	encs := 0
	type encVal struct{ fac, sec, key, v string }
	var vals []encVal
	files := 0
	for _, fac := range facs {
		if unreadable[fac] {
			continue
		}
		f, err := a.St.Load(fac)
		if err != nil || f == nil {
			continue
		}
		has := false
		for _, sec := range f.Raw.Names() {
			m, _ := f.Raw.Get(sec)
			for _, k := range m.Keys() {
				if v, _ := m.Get(k); store.IsEnc(v) {
					vals = append(vals, encVal{fac, sec, k, v})
					has = true
				}
			}
		}
		if has {
			files++
		}
	}
	encs = len(vals)
	var dk []byte
	switch {
	case !exists(a.St.DataKeyFile()) && encs > 0:
		d.fail(msg.DocNoKeyEnc, encs)
	case !exists(a.St.DataKeyFile()):
		d.warn(msg.DocNoDataKey)
	case isPW:
		d.ok(msg.DocDataKeyPw)
	default:
		k, err := a.St.DataKey()
		if err != nil {
			d.fail(msg.DocDataKeyBad, err.Error())
		} else {
			dk = k
			d.ok(msg.DocDataKey)
		}
	}
	if len(unreadList) > 0 {
		d.warn(msg.DocPartial)
	} else if encs > 0 {
		if dk == nil {
			d.warn(msg.DocValuesSkip, encs)
		} else {
			var bad []string
			for _, v := range vals {
				if _, err := store.Decrypt(dk, v.fac, v.sec, v.key, v.v); err != nil {
					bad = append(bad, v.fac+" ["+v.sec+"] "+v.key)
				}
			}
			if len(bad) > 0 {
				d.fail(msg.DocValuesBad, strings.Join(bad, ", "))
			} else {
				d.ok(msg.DocValues, encs, files)
			}
		}
	}

	// Encryption policy.
	toEnc, toDec := 0, 0
	policyErr := ""
	for _, fac := range facs {
		if unreadable[fac] {
			continue
		}
		b, err := os.ReadFile(a.facFile(fac))
		if err != nil {
			continue
		}
		spec, err := a.specFor(fac, ini.Parse(string(b)))
		if err != nil {
			// Never the spec text: only where the invalid spec is.
			if msg.IDOf(err) == msg.PolicyBad {
				policyErr = msg.Text(msg.DocPolicyFileBad, fac, fac)
			} else {
				policyErr = msg.Text(msg.DocPolicyCfgBad, a.Cfg.Path)
			}
			continue
		}
		rewriteValues(string(b), func(sec, k, v string) (string, bool, error) {
			want := spec.Encrypt(k, a.Plain)
			switch {
			case want && !store.IsEnc(v):
				toEnc++
			case !want && store.IsEnc(v):
				toDec++
			}
			return "", false, nil
		})
	}
	switch {
	case len(unreadList) > 0:
		// reported above (DocPartial): not "matches the policy"
	case policyErr != "":
		d.fail(msg.DocPolicyBad, policyErr)
	case toEnc+toDec > 0:
		d.warn(msg.DocPolicyDiff, toEnc, toDec)
	default:
		d.ok(msg.DocPolicyOK)
	}

	// Backups.
	var bk *backupKey
	if !exists(a.backupKeyFile()) {
		d.warn(msg.DocNoBackup)
	} else if _, pw := keys.Detect(a.backupKeyFile(), kb).(keys.Passphrase); !pw {
		k, err := a.loadBackupKey(a.backupKeyFile())
		if err != nil {
			d.fail(msg.DocBackupKeyX, backupKeyReason(err)) // a parse error could quote key material
		} else {
			bk = k
			d.ok(msg.DocBackupKey)
		}
	}
	conf, err := a.readConf()
	if err != nil {
		d.fail(msg.DocBkConfBad, err.Error())
		conf = map[string]any{}
	}
	dir := a.autoDir(conf)
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		d.warn(msg.DocBkDirNone, dir)
	} else {
		if isTempDir(dir) {
			d.warn(msg.DocBkDirTemp, dir)
		} else {
			d.ok(msg.DocBkDir, dir)
		}
		var named []string
		for _, f := range listNames(dir) {
			if bundleName.MatchString(f) {
				named = append(named, f)
			}
		}
		// Newest by the time in the name (kind prefixes differ).
		ts := func(f string) string { return strings.SplitN(f, "-", 3)[2] }
		sort.Slice(named, func(i, j int) bool { return ts(named[i]) < ts(named[j]) })
		if len(named) == 0 {
			d.warn(msg.DocLastNone, dir)
		} else {
			last := named[len(named)-1]
			path := filepath.Join(dir, last)
			created := ""
			if b, err := os.ReadFile(path); err == nil {
				if h, _, err := readHeader(b); err == nil {
					created = h.Created
				}
			}
			switch {
			case bk == nil:
				d.warn(msg.DocLastNoKey, last, created)
			default:
				switch bundleStatus(path, bk) {
				case stOK:
					d.ok(msg.DocLastOK, last, created)
					if t, err := time.Parse(time.RFC3339, created); err == nil && now().Sub(t) > backupMaxAgeDays*24*time.Hour {
						d.warn(msg.DocLastOld, last, created, backupMaxAgeDays)
					}
				case stOther:
					d.warn(msg.DocLastOther, last)
				default:
					d.fail(msg.DocLastBad, last)
				}
			}
		}
	}

	// Interrupted work and pending import files.
	clean := true
	if b, err := os.ReadFile(a.journalFile()); err == nil {
		op := "?"
		if m := regexp.MustCompile(`"op"\s*:\s*"([\w-]+)"`).FindSubmatch(b); m != nil {
			op = opName(string(m[1]))
		}
		d.fail(msg.DocJournal, op, a.journalFile())
		clean = false
	}
	var shred, pending []string
	for _, f := range listNames(a.importDir()) {
		if strings.HasSuffix(f, shredding) {
			shred = append(shred, f)
		} else if strings.HasSuffix(f, ".ini") {
			pending = append(pending, f)
		}
	}
	if len(shred) > 0 {
		d.warn(msg.DocShredding, strings.Join(shred, ", "))
		clean = false
	}
	if len(pending) > 0 {
		d.warn(msg.DocImports, a.importDir(), strings.Join(pending, ", "))
		clean = false
	}
	if clean {
		d.ok(msg.DocClean)
	}

	// Audit log.
	if !a.Cfg.AuditEnabled {
		d.warn(msg.DocAuditOff)
	} else {
		logf := filepath.Join(a.St.Logs, "audit.log")
		st, err := os.Lstat(logf)
		switch {
		case err != nil:
			d.ok(msg.DocAuditNone)
		case !ownedByMe(st):
			d.fail(msg.DocAuditOwner, logf)
		case st.Mode().Perm() != 0o600:
			d.warn(msg.DocAuditMode, logf, octal(st.Mode().Perm()))
		default:
			d.ok(msg.DocAudit, logf)
		}
	}

	a.say(msg.Text(msg.DocSummary, d.nOK, d.nWarn, d.nFail))
	if d.nFail > 0 {
		return ExitFail, nil
	}
	return ExitOK, nil
}
