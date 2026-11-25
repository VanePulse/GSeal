package test

// M2 additions (not in the VaneSecret baseline):
//   - release builds contain no fault-injection points and no testfile backend;
//   - backup directory precedence: --backup <dir> > remembered > config
//     [backup] dir > default ($TMPDIR/with-secrets-backup);
//   - import / export follow the encryption policy ([encrypt] keys, @encrypt),
//     and an import never decrypts a stored ciphertext.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/VanePulse/GSeal/internal/msg"
)

func Test_e2e_M2ReleaseBuildHasNoFaults(t *testing.T) {
	c := checker{t}
	b, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"GSEAL_FAULT", "GSEAL_CRASH", "GSEAL_HOLD_MS", "GSEAL_TEST_BACKEND"} {
		c.ok("M2.F1", !bytes.Contains(b, []byte(s)), "release executable does not contain "+s)
	}
	tb, _ := os.ReadFile(binTest)
	c.ok("M2.F1", bytes.Contains(tb, []byte("GSEAL_FAULT")), "(the gsealtest executable does)")

	// A store without secret keys: import needs no data key, so this runs
	// with any backend.
	root := filepath.Join(scratch, "m2-release")
	os.RemoveAll(root)
	write(t, filepath.Join(root, "env", "web.ini"), "[n]\nHOST = a.invalid\nPORT = 1\n")
	env := with(baseEnv(t), "GSEAL_STORE="+root)
	for _, point := range []string{"short-write", "before-commit", "after-commit"} {
		r := runEnv(env, "", "--export", "web")
		write(t, filepath.Join(root, "env", "_import", "web.ini"), "[n]\nHOST = "+point+".invalid\nPORT = 1\n")
		r = runEnv(with(env, "GSEAL_FAULT="+point), "", "--import", "web")
		got := runEnv(env, "", "web.n", "--", `printf %s "$WEB_N_HOST"`).stdout
		c.ok("M2.F2", r.status == 0 && got == point+".invalid", "release build ignores GSEAL_FAULT="+point+" (import completes)", r)
	}
	r := runEnv(with(env, "GSEAL_CRASH=after-lock", "GSEAL_HOLD_MS=5000"), "", "--export", "web")
	c.ok("M2.F3", r.status == 0 && exists(filepath.Join(root, "env", "_import", "web.ini")), "release build ignores GSEAL_CRASH and GSEAL_HOLD_MS", r)
}

func Test_e2e_M2BackupDirOrder(t *testing.T) {
	e := newE2E(t, "m2-bkdir")
	c := e.c
	e.write(e.file("web.ini"), "[n]\nHOST = a.invalid\nPSWD = web-secret-1\n")
	e.run("--init")
	first := filepath.Join(e.root, "first")
	r := e.tty(e2ePass+"\n"+e2ePass+"\n", "--backup", first)
	c.ok("M2.B0", r.status == 0, "(backup passphrase set)", r)
	bundles := func(d string) int { return len(filterSuffix(names(d), ".wsbk")) }
	imp := func() res {
		e.run("--export", "web")
		return e.run("--import", "web")
	}
	remembered := func() string {
		var m map[string]any
		json.Unmarshal([]byte(e.store(".backup.json")), &m)
		s, _ := m["dir"].(string)
		return s
	}

	// 1. default: nothing remembered, no config -> $TMPDIR/with-secrets-backup
	tmpd := filepath.Join(e.root, "tmpdir")
	os.Mkdir(tmpd, 0o700)
	os.Remove(e.file(".backup.json"))
	r = e.runE([]string{"TMPDIR=" + tmpd}, "--backup")
	def := filepath.Join(tmpd, "with-secrets-backup")
	c.ok("M2.B1", r.status == 0 && bundles(def) == 1 && has(r.stderr, msg.BackupInTemp), "no dir given, nothing remembered, no config: default $TMPDIR/with-secrets-backup (warns)", r)

	// 2. config [backup] dir, nothing remembered -> config dir (not remembered)
	cfgDir := filepath.Join(e.root, "from-config")
	cfg := filepath.Join(e.root, "config.ini")
	write(t, cfg, "[backup]\ndir = "+cfgDir+"\n")
	e.env = with(e.env, "GSEAL_CONFIG="+cfg)
	os.Remove(e.file(".backup.json"))
	r = e.run("--backup")
	r2 := imp()
	c.ok("M2.B2", r.status == 0 && r2.status == 0 && bundles(cfgDir) == 2 && !exists(e.file(".backup.json")),
		"config [backup] dir is used for manual and automatic backups and is not copied into the remembered dir", r, r2)

	// 3. remembered dir beats the config
	rem := filepath.Join(e.root, "remembered")
	e.run("--backup", rem)
	r = imp()
	r2 = e.run("--backup")
	c.ok("M2.B3", r.status == 0 && r2.status == 0 && remembered() == rem && bundles(rem) == 3 && bundles(cfgDir) == 2,
		"a remembered dir (from --backup <dir>) beats config [backup] dir", r, r2)

	// 4. --backup <dir> beats both, and is remembered
	arg := filepath.Join(e.root, "argument")
	r = e.run("--backup", arg)
	c.ok("M2.B4", r.status == 0 && bundles(arg) == 1 && bundles(rem) == 3 && remembered() == arg, "--backup <dir> beats the remembered dir and the config, and becomes the remembered dir", r)
}

func Test_e2e_M2ImportPolicy(t *testing.T) {
	e := newE2E(t, "m2-policy")
	c := e.c
	e.run("--init")
	cfg := filepath.Join(e.root, "config.ini")
	e.env = with(e.env, "GSEAL_CONFIG="+cfg)

	// [encrypt] keys empty = every key encrypted; export holds every value.
	write(t, cfg, "[encrypt]\nkeys =\n")
	e.write(e.imp("all.ini"), "[n]\nHOST = all.invalid ; note\nPSWD = all-secret-1\n")
	r := e.run("--import", "all")
	s := e.store("all.ini")
	c.ok("M2.P1", r.status == 0 && strings.Count(s, "ENC:v1:") == 2 && !strings.Contains(s, "all.invalid") && !strings.Contains(s, "; note"),
		"config [encrypt] keys empty: HOST is encrypted too (inline comment dropped)", r, s)
	c.ok("M2.P1", e.sh("all.n", `[ "$ALL_N_HOST" = all.invalid ] && echo same`) == "same\n", "(encrypted HOST injects)")
	e.run("--export", "all")
	x := read(e.imp("all.ini"))
	c.ok("M2.P2", strings.Contains(x, "HOST = <hold>") && strings.Contains(x, "PSWD = <hold>"), "export holds every encrypted value", x)
	os.Remove(e.imp("all.ini"))

	// Back to the classic rule: an import never decrypts a stored ciphertext.
	write(t, cfg, "[encrypt]\nkeys = @mask\n")
	e.run("--export", "all")
	r = e.run("--import", "all")
	s = e.store("all.ini")
	c.ok("M2.P3", r.status == 0 && strings.Count(s, "ENC:v1:") == 2, "with @mask, an encrypted HOST stays encrypted on re-import (import never decrypts)", r, s)

	// File-level @encrypt wins over the config.
	e.write(e.imp("tok.ini"), "; @encrypt TOKEN_*\n\n[n]\nHOST = tok.invalid\nTOKEN_A = t-1\nNOTE = plain-note\n")
	write(t, cfg, "[encrypt]\nkeys =\n")
	r = e.run("--import", "tok")
	s = e.store("tok.ini")
	c.ok("M2.P4", r.status == 0 && strings.Contains(s, "HOST = tok.invalid") && strings.Contains(s, "TOKEN_A = ENC:v1:") && strings.Contains(s, "NOTE = plain-note"),
		"file-level @encrypt TOKEN_* overrides config: only TOKEN_A is encrypted", r, s)
}
