// Package admin implements the management commands of with-secrets. They are
// run by the user in their own terminal; a passphrase is read from /dev/tty
// without echo and never accepted as an argument or environment variable.
//
//	--init                         create the data key
//	--new <file> [<node>]          write an import template env/_import/<file>.ini
//	--export <file>                write env/_import/<file>.ini; secret values -> <hold>
//	--import <file>                validate, merge, encrypt, write back; shred the import file
//	--backup [<dir>] [--new-password]   passphrase-encrypted bundle (sets up auto backup)
//	--restore <bundle>             restore a bundle (new machine / disaster)
//	--undo-restore                 put back the store as it was before the last restore
//	--verify-backup <bundle>       check a bundle opens and every value decrypts
//
// Consistency (same as VaneSecret):
//   - every command that changes or snapshots the store holds an exclusive
//     lock (flock on env/.lock);
//   - files are published atomically: temp file, full write, fsync, rename
//     (or link, when an existing target must be refused);
//   - exit codes: 0 done; 1 failed, store unchanged; 3 store changed
//     (committed) but a follow-up step (shred, auto backup, saving settings)
//     is incomplete; 5 a restore / undo was interrupted, the next management
//     command completes it.
package admin

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/VanePulse/GSeal/internal/config"
	"github.com/VanePulse/GSeal/internal/ini"
	"github.com/VanePulse/GSeal/internal/keys"
	"github.com/VanePulse/GSeal/internal/msg"
	"github.com/VanePulse/GSeal/internal/policy"
	"github.com/VanePulse/GSeal/internal/store"
)

// Exit codes.
const (
	ExitOK                  = 0
	ExitFail                = 1
	ExitCommittedIncomplete = 3
	ExitSwapPending         = 5
)

// Commands lists the management commands.
var Commands = map[string]bool{
	"--init": true, "--new": true, "--export": true, "--import": true, "--backup": true,
	"--restore": true, "--undo-restore": true, "--verify-backup": true,
	"--apply-policy": true, "--set": true, "--rotate-datakey": true, "doctor": true, "--doctor": true,
}

// ReadOnly: commands that never change the store.
var ReadOnly = map[string]bool{"--verify-backup": true, "doctor": true, "--doctor": true}

// locked: commands that take the lock up front (--backup and --restore take
// it after the passphrase prompt; --verify-backup does not change the store).
var locked = map[string]bool{"--init": true, "--new": true, "--export": true, "--import": true, "--undo-restore": true, "--rotate-datakey": true}

// Admin runs management commands on one store.
type Admin struct {
	St     *store.Store
	Cfg    *config.Config
	Plain  policy.Plain
	Stdout io.Writer
	Stderr io.Writer
	// BackendName is --backend (for --init and --restore); "" = default.
	BackendName string
	// Where describes where the store location came from (for doctor).
	Where string

	lock *os.File
}

func (a *Admin) say(s string)  { fmt.Fprintln(a.Stdout, s) }
func (a *Admin) warn(s string) { fmt.Fprintln(a.Stderr, msg.Prefix+s) }

func (a *Admin) importDir() string      { return filepath.Join(a.St.Env, "_import") }
func (a *Admin) localBackupDir() string { return filepath.Join(a.St.Env, ".backup") }
func (a *Admin) backupKeyFile() string  { return filepath.Join(a.St.Env, ".backupkey.cred") }
func (a *Admin) confFile() string       { return filepath.Join(a.St.Env, ".backup.json") }
func (a *Admin) lockFile() string       { return filepath.Join(a.St.Env, ".lock") }
func (a *Admin) journalFile() string    { return filepath.Join(a.St.Env, ".swap-journal.json") }
func (a *Admin) facFile(f string) string {
	return filepath.Join(a.St.Env, f+".ini")
}
func (a *Admin) importFile(f string) string { return filepath.Join(a.importDir(), f+".ini") }

func itoa(i int) string { return strconv.Itoa(i) }

// now is replaceable in tests.
var now = time.Now

// isoNow is JavaScript's new Date().toISOString().
func isoNow() string { return now().UTC().Format("2006-01-02T15:04:05.000Z") }

// stamp is isoNow without - : . Z, e.g. 20261124T055600449.
func stamp() string {
	return strings.NewReplacer("-", "", ":", "", ".", "", "Z", "").Replace(isoNow())
}

// Run runs one management command and returns its exit code.
func (a *Admin) Run(cmd string, args []string) (code int) {
	defer a.releaseLock()
	err := func() error {
		if cmd == "--init" || cmd == "--restore" {
			var rest []string
			for i := 0; i < len(args); i++ {
				if args[i] != "--backend" {
					rest = append(rest, args[i])
					continue
				}
				if i+1 >= len(args) || args[i+1] == "" {
					return msg.Errorf(msg.MissingArg, "--backend")
				}
				a.BackendName = args[i+1]
				if _, err := keys.ByName(a.BackendName, ""); err != nil {
					return err
				}
				i++
			}
			args = rest
		}
		if locked[cmd] {
			if err := a.acquireLock(cmd); err != nil {
				return err
			}
		}
		arg := func(i int) string {
			if i < len(args) {
				return args[i]
			}
			return ""
		}
		var err error
		switch cmd {
		case "--init":
			err = a.cmdInit()
		case "--new":
			node := arg(1)
			if node == "" {
				node = "node1"
			}
			err = a.cmdNew(arg(0), node)
		case "--export":
			err = a.cmdExport(arg(0))
		case "--import":
			code, err = a.cmdImport(arg(0))
		case "--backup":
			code, err = a.cmdBackup(args)
		case "--restore":
			err = a.cmdRestore(arg(0))
		case "--undo-restore":
			err = a.cmdUndoRestore()
		case "--verify-backup":
			code, err = a.cmdVerify(arg(0))
		case "--apply-policy":
			code, err = a.cmdApplyPolicy(args)
		case "--set":
			code, err = a.cmdSet(args)
		case "--rotate-datakey":
			code, err = a.cmdRotate()
		case "doctor", "--doctor":
			code, err = a.cmdDoctor()
		default:
			err = msg.Errorf(msg.UnknownCmd, cmd)
		}
		return err
	}()
	if err == nil {
		return code
	}
	var sp swapPending
	var me *msg.Error
	switch {
	case errors.As(err, &sp):
		a.warn(err.Error())
		return ExitSwapPending
	case errors.As(err, &me):
		a.warn(err.Error())
	default:
		a.warn(msg.Text(msg.Unexpected, err.Error()))
	}
	return ExitFail
}

func checkFac(fac string) error {
	if fac == "" {
		return msg.Errorf(msg.MissingFile)
	}
	if !store.NameRe.MatchString(fac) {
		return msg.Errorf(msg.BadFile, fac)
	}
	return nil
}

// ---------------------------------------------------------------- --init ----

func (a *Admin) cmdInit() error {
	dk := a.St.DataKeyFile()
	if exists(dk) {
		return msg.Errorf(msg.InitExists)
	}
	if err := ensureDir(a.St.Env); err != nil {
		return err
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return err
	}
	b := a.St.Backend
	if a.BackendName != "" {
		var err error
		if b, err = keys.ByName(a.BackendName, dk); err != nil {
			return err
		}
	}
	if err := a.wrapTo(b, keys.DataKeyName, k, dk, true); err != nil {
		if errors.Is(err, os.ErrExist) {
			return msg.Errorf(msg.InitExists)
		}
		return err
	}
	if _, err := a.St.DataKey(); err != nil { // round-trip check
		return err
	}
	a.say(msg.Text(msg.InitDone, dk))
	a.warn(msg.Text(msg.InitNoBackup))
	return nil
}

// ------------------------------------------------------- --new / --export ----

func (a *Admin) writeImportFile(fac, text string) error {
	if err := ensureDir(a.importDir()); err != nil {
		return err
	}
	if err := atomicWrite(a.importFile(fac), []byte(text), true); err != nil {
		if errors.Is(err, os.ErrExist) {
			return msg.Errorf(msg.ImportPending, a.importFile(fac))
		}
		return err
	}
	return nil
}

func (a *Admin) cmdNew(fac, node string) error {
	if err := checkFac(fac); err != nil {
		return err
	}
	if !store.NameRe.MatchString(node) {
		return msg.Errorf(msg.BadNode, node)
	}
	if exists(a.facFile(fac)) {
		return msg.Errorf(msg.NewExists, fac, fac)
	}
	if exists(a.importFile(fac)) {
		return msg.Errorf(msg.ImportExists, a.importFile(fac))
	}
	text := msg.Text(msg.NewTemplate, fac, node, isoNow()[:10])
	if err := a.writeImportFile(fac, text); err != nil {
		return err
	}
	a.say(msg.Text(msg.NewDone, a.importFile(fac)))
	a.say(msg.Text(msg.NewNext, fac))
	return nil
}

// specFor returns the encryption spec of a file: its own @encrypt, else
// config [encrypt] keys, else @mask (the classic rule).
func (a *Admin) specFor(fac string, f *ini.File) (policy.Spec, error) {
	if f != nil && f.HasEncrypt {
		s, err := policy.Parse(f.Encrypt)
		if err != nil {
			return s, msg.Errorf(msg.PolicyBad, fac, err.Error())
		}
		return s, nil
	}
	if a.Cfg.EncryptSet {
		s, err := policy.Parse(a.Cfg.Encrypt)
		if err != nil {
			return s, msg.Errorf(msg.ConfigBadSpec, a.Cfg.Path, err.Error())
		}
		return s, nil
	}
	return policy.Parse("@mask")
}

func (a *Admin) cmdExport(fac string) error {
	if err := checkFac(fac); err != nil {
		return err
	}
	b, err := os.ReadFile(a.facFile(fac))
	if err != nil {
		return msg.Errorf(msg.ExportMissing, fac, fac)
	}
	if exists(a.importFile(fac)) {
		return msg.Errorf(msg.ImportPending, a.importFile(fac))
	}
	text := string(b)
	spec, err := a.specFor(fac, ini.Parse(text))
	if err != nil {
		return err
	}
	inSection := false
	held := 0
	lines := splitLines(text)
	for i, l := range lines {
		t := ini.Trim(l)
		if sectionLine(t) != nil {
			inSection = true
			continue
		}
		eq := strings.Index(t, "=")
		if !inSection || t == "" || isComment(t) || eq < 0 {
			continue
		}
		key := ini.Trim(t[:eq])
		if !a.hidden(spec, key, ini.ParseValue(ini.Trim(t[eq+1:]))) {
			continue
		}
		held++
		lines[i] = key + " = <hold>"
	}
	if err := a.writeImportFile(fac, strings.Join(lines, "\n")); err != nil {
		return err
	}
	a.say(msg.Text(msg.ExportDone, a.importFile(fac), held))
	a.say(msg.Text(msg.ExportNext, fac))
	return nil
}

// hidden: the value of key is a secret (exported as <hold>, no inline
// comment kept): it is or will be encrypted, or it is redacted in output.
func (a *Admin) hidden(spec policy.Spec, key, stored string) bool {
	return store.IsEnc(stored) || spec.Encrypt(key, a.Plain) || !a.Plain.Has(key)
}

// ---------------------------------------------------------------- --backup ----

func (a *Admin) cmdBackup(args []string) (int, error) {
	newPass := false
	dirArg := ""
	for _, x := range args {
		if x == "--new-password" {
			newPass = true
		} else if dirArg == "" {
			dirArg = x
		}
	}
	// Ask for a new passphrase (if needed) before taking the lock; read the
	// stored key only under it, so a concurrent restore / passphrase change
	// cannot mix in.
	fresh := newPass || !exists(a.backupKeyFile())
	var bk *backupKey
	if fresh {
		pass, err := askNewPassphrase()
		if err != nil {
			return ExitFail, err
		}
		if bk, err = makeBackupKey(pass, "", scryptN, scryptR, scryptP); err != nil {
			return ExitFail, err
		}
	}
	if err := a.acquireLock("--backup"); err != nil {
		return ExitFail, err
	}
	if bk == nil {
		var err error
		if bk, err = a.loadBackupKey(a.backupKeyFile()); err != nil {
			return ExitFail, err
		}
		if bk == nil {
			return ExitFail, msg.Errorf(msg.BackupKeyGone)
		}
	}
	conf, err := a.readConf()
	if err != nil {
		if dirArg == "" {
			return ExitFail, err
		}
		a.warn(msg.Text(msg.BackupConfUsing, err.Error(), dirArg))
		conf = map[string]any{}
	}
	dir := a.autoDir(conf)
	if dirArg != "" {
		dir = dirArg
	}
	if dir, err = filepath.Abs(dir); err != nil {
		return ExitFail, err
	}
	// The bundle first: until it exists, neither the passphrase nor the dir changes.
	file, kind, err := a.writeBundle(dir, kindManual, bk)
	if err != nil {
		return ExitFail, err
	}
	a.say(msg.Text(msg.BackupDone, kindText(kind), file))
	var pending []string
	if fresh {
		if err := a.saveBackupKey(a.St.KeyBackend(), bk, a.backupKeyFile()); err != nil {
			pending = append(pending, msg.Text(msg.BackupPassNotSaved, file, err.Error()))
		}
	}
	// Remember the dir, unless it came from config [backup] dir (the config
	// then stays in charge).
	fromConfig := dirArg == "" && confDir(conf) == "" && a.Cfg.BackupDir != ""
	if confDir(conf) != dir && !fromConfig {
		conf["dir"] = dir
		err := func() error {
			if err := ensureDir(a.St.Env); err != nil {
				return err
			}
			if err := faultAt("save-conf"); err != nil {
				return err
			}
			return atomicWrite(a.confFile(), jsonIndent(conf), false)
		}()
		if err != nil {
			delete(conf, "dir")
			old, _ := a.readConf()
			pending = append(pending, msg.Text(msg.BackupDirNotSaved, a.autoDir(old), err.Error()))
		}
	}
	if len(pending) > 0 {
		a.warn(msg.Text(msg.BackupIncomplete, ExitCommittedIncomplete))
		for _, p := range pending {
			a.warn(msg.Text(msg.PendingItem, p))
		}
		a.warn(msg.Text(msg.BackupRetryHint))
		return ExitCommittedIncomplete, nil
	}
	a.say(msg.Text(msg.BackupAutoDir, dir, keepAuto))
	return ExitOK, nil
}

// ------------------------------------------------- --verify-backup / --restore ----

type opened struct {
	h    *header
	p    *payload
	pass string
}

func (a *Admin) openWithPrompt(path string) (*opened, error) {
	if path == "" {
		return nil, msg.Errorf(msg.MissingBundle)
	}
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	h, _, err := readHeader(buf)
	if err != nil {
		return nil, err
	}
	ans, err := promptSecrets(msg.Text(msg.PromptPass, h.Kind, h.Created))
	if err != nil {
		return nil, err
	}
	key, err := derive(ans[0], h.Salt, h.N, h.R, h.P)
	if err != nil {
		return nil, err
	}
	h, p, err := openBundle(buf, key)
	if err != nil {
		return nil, err
	}
	return &opened{h, p, ans[0]}, nil
}

func (a *Admin) cmdVerify(path string) (int, error) {
	o, err := a.openWithPrompt(path)
	if err != nil {
		return ExitFail, err
	}
	c := verifyPayload(o.p)
	a.say(msg.Text(msg.VerifyBundle, path, o.h.Kind, o.h.Created))
	a.say(msg.Text(msg.VerifyCounts, c.facs, c.secs, c.encs))
	if len(c.problems) > 0 {
		for _, x := range c.problems {
			a.say(msg.Text(msg.ItemBad, x))
		}
		return ExitFail, nil
	}
	a.say(msg.Text(msg.VerifyOK))
	return ExitOK, nil
}

func (a *Admin) storeFiles() ([]string, error) {
	facs, err := a.St.Facilities()
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, f := range facs {
		out = append(out, f+".ini")
	}
	for _, f := range []string{".datakey.cred", ".backupkey.cred"} {
		if exists(filepath.Join(a.St.Env, f)) {
			out = append(out, f)
		}
	}
	return out, nil
}

// cmdRestore: (1) verify the bundle; (2) stage the new files, wrap the keys
// and check them (any failure here leaves the store untouched); (3) journal
// and swap.
func (a *Admin) cmdRestore(path string) error {
	o, err := a.openWithPrompt(path)
	if err != nil {
		return err
	}
	c := verifyPayload(o.p)
	if len(c.problems) > 0 {
		for _, x := range c.problems {
			a.say(msg.Text(msg.ItemBad, x))
		}
		return msg.Errorf(msg.RestoreCheck)
	}
	if err := a.acquireLock("--restore"); err != nil {
		return err
	}
	ts := stamp()
	staging := filepath.Join(a.St.Env, ".restore-"+ts)
	err = func() error {
		if err := ensureDir(staging); err != nil {
			return err
		}
		for name, text := range o.p.Files {
			if err := atomicWrite(filepath.Join(staging, name), []byte(text), false); err != nil {
				return err
			}
		}
		if err := faultAt("restore-staging"); err != nil {
			return err
		}
		// The restored keys are wrapped by --backend, else by the backend of
		// the store being replaced (or the default).
		kb := a.St.KeyBackend()
		if a.BackendName != "" {
			if kb, err = keys.ByName(a.BackendName, a.St.DataKeyFile()); err != nil {
				return err
			}
		}
		var dk []byte
		if o.p.DataKey != nil {
			if dk, err = decodeB64(*o.p.DataKey); err != nil {
				return err
			}
			if err := a.wrapTo(kb, keys.DataKeyName, dk, filepath.Join(staging, ".datakey.cred"), false); err != nil {
				return err
			}
		}
		bk, err := makeBackupKey(o.pass, o.h.Salt, o.h.N, o.h.R, o.h.P)
		if err != nil {
			return err
		}
		if err := a.saveBackupKey(kb, bk, filepath.Join(staging, ".backupkey.cred")); err != nil {
			return err
		}
		if dk != nil {
			got, err := kb.Unwrap(keys.DataKeyName, filepath.Join(staging, ".datakey.cred"))
			if err != nil || string(got) != string(dk) {
				return msg.Errorf(msg.RestoreKeyDiff)
			}
		}
		if k, err := a.loadBackupKey(filepath.Join(staging, ".backupkey.cred")); err != nil || k == nil || k.Key == "" {
			return msg.Errorf(msg.RestoreBkBad)
		}
		return nil
	}()
	if err != nil {
		os.RemoveAll(staging)
		return msg.Errorf(msg.RestoreNotStart, err.Error())
	}
	from, _ := filepath.Abs(path)
	aside := filepath.Join(a.localBackupDir(), "pre-restore-"+ts)
	out, err := a.storeFiles()
	if err != nil {
		os.RemoveAll(staging)
		return msg.Errorf(msg.RestoreNotStart, err.Error())
	}
	j := &journal{Op: opRestore, TS: ts, From: from, Out: out, OutDir: aside, In: listNames(staging), InDir: staging}
	if err := a.commitSwap(j); err != nil {
		return err
	}
	if len(j.Out) > 0 {
		a.say(msg.Text(msg.RestoreAside, aside))
	}
	a.say(msg.Text(msg.RestoreDone, c.facs, c.secs, o.h.Kind, o.h.Created))
	conf, err := a.readConf()
	if err != nil {
		conf = map[string]any{} // reported by the next --backup
	}
	a.say(msg.Text(msg.RestoreRebound, a.autoDir(conf)))
	return nil
}

// cmdUndoRestore puts back the store that the last restore moved aside; the
// restored files go to .backup/undone-restore-<ts>/.
func (a *Admin) cmdUndoRestore() error {
	var dirs []string
	for _, d := range listNames(a.localBackupDir()) {
		if preRestore.MatchString(d) && exists(filepath.Join(a.localBackupDir(), d, "restore.json")) {
			dirs = append(dirs, d)
		}
	}
	if len(dirs) == 0 {
		return msg.Errorf(msg.UndoNone)
	}
	sortStrings(dirs)
	aside := filepath.Join(a.localBackupDir(), dirs[len(dirs)-1])
	var back []string
	for _, f := range listNames(aside) {
		if f != "restore.json" {
			back = append(back, f)
		}
	}
	ts := stamp()
	out, err := a.storeFiles()
	if err != nil {
		return err
	}
	j := &journal{Op: opUndo, TS: ts, Out: out, OutDir: filepath.Join(a.localBackupDir(), "undone-restore-"+ts), In: back, InDir: aside}
	if err := a.commitSwap(j); err != nil {
		return err
	}
	a.say(msg.Text(msg.UndoDone, len(back), aside, j.OutDir))
	return nil
}
