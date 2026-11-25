package test

// Port of VaneSecret ca87d68 test/e2e.mjs (and test/echo-check.mjs): the
// management commands against a FAKE store, in the same order, with the
// same checks. Ids are e2e_L<line>. Tool output is matched by message id
// (internal/msg), fixture text (including its Chinese docs) is kept as is.
//
// Runs on the gsealtest build. Key backend: GSEAL_TEST_BACKEND (default
// systemd-creds; testfile anywhere). Assertions marked L-sd in the matrix
// (systemd-creds specifics) run only with systemd-creds.

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/VanePulse/GSeal/internal/msg"
)

var e2eSecrets = []string{"plainPass-1234", "devPass-5678", "newPass-9999", "tok-abcdef", "mailPw-24680"}

const (
	e2ePass    = "correct horse battery"
	e2eNewPass = "another long passphrase"
)

func inTemp(d string) bool {
	d = filepath.Clean(d)
	for _, b := range []string{"/tmp", filepath.Clean(os.TempDir())} {
		if d == b || strings.HasPrefix(d, b+"/") {
			return true
		}
	}
	return false
}

func Test_e2e_Store(t *testing.T) {
	e := newE2E(t, "e2e")
	c := e.c
	sd := e.backend == "systemd-creds"
	BK := filepath.Join(e.root, "bk")
	lk := func(s string) []string { return leaksOf(s, e2eSecrets) }

	e.write(e.file("redis.ini"), strings.Join([]string{
		"; @desc Redis",
		";",
		"; 键：",
		";   HOST  服务器地址",
		";   PSWD  密码",
		"; @remark 内部备注",
		"",
		"[DEFAULT]",
		"PORT = 6379",
		"",
		"[uat]",
		"; @desc Redis：UAT",
		"HOST = 10.0.0.1",
		"PSWD = plainPass-1234",
		"",
		"[dev]",
		"; @desc Redis：dev",
		"HOST = 10.0.0.2 ; 开发机",
		"PSWD = devPass-5678",
		"",
	}, "\n"))

	// --- before migration: plaintext still works
	c.ok("e2e_L055", e.inject("redis.uat", "$REDIS_UAT_PSWD") == "***", "plaintext store: injection works, output redacted")

	// --- init
	r := e.run("--init")
	DK := e.file(".datakey.cred")
	c.ok("e2e_L059", r.status == 0 && exists(DK), "--init creates data key", r)
	c.ok("e2e_L060", has(r.stderr, msg.InitNoBackup), "--init warns that no backup exists", r.stderr)
	st, _ := os.Stat(DK)
	c.ok("e2e_L063", st != nil && st.Mode().Perm() == 0o600, "data key file is mode 600")
	if sd {
		out, err := exec.Command("systemd-creds", "decrypt", "--user", "--name=with-secrets-data", DK, "-").Output()
		c.ok("e2e_L065", err == nil && len(out) == 32, "data key unwraps via systemd-creds --user to 32 bytes")
		err = exec.Command("systemd-creds", "decrypt", "--user", "--name=other-name", DK, "-").Run()
		c.ok("e2e_L067", err != nil, "data key credential rejects a different credential name")
	}
	r = e.run("--init")
	c.ok("e2e_L069", r.status != 0 && has(r.stderr, msg.InitExists), "--init refuses to overwrite existing key", r)

	// --- migrate: export unchanged, import
	r = e.run("--export", "redis")
	c.ok("e2e_L073", r.status == 0, "--export redis", r)
	exported := read(e.imp("redis.ini"))
	c.ok("e2e_L075", len(lk(exported)) == 0 && strings.Contains(exported, "PSWD = <hold>"), "export file holds no secrets (PSWD = <hold>)", exported)
	c.ok("e2e_L076", strings.Contains(exported, "HOST = 10.0.0.2 ; 开发机") && strings.Contains(exported, "@remark 内部备注"), "export keeps plain values, inline comments, @remark")
	r = e.run("--export", "redis")
	c.ok("e2e_L078", r.status != 0 && has(r.stderr, msg.ImportPending), "--export refuses when an import file is pending", r)
	r = e.run("--import", "redis")
	c.ok("e2e_L080", r.status == 0, "--import redis (migration)", r)
	c.ok("e2e_L081", !exists(e.imp("redis.ini")), "import file shredded/removed")
	s1 := e.store("redis.ini")
	c.ok("e2e_L083", len(lk(s1)) == 0 && strings.Count(s1, "ENC:v1:") == 2, "store now has 2 ENC values, no plaintext secrets", s1)
	c.ok("e2e_L084", strings.Contains(s1, "HOST = 10.0.0.2 ; 开发机") && strings.Contains(s1, "@desc Redis：UAT"), "store keeps plain values, comments and docs")
	c.ok("e2e_L085", len(withPrefix(names(e.file(".backup")), "redis.ini.")) > 0, "local pre-import backup written")
	c.ok("e2e_L086", has(r.stderr, msg.AutoNotSetUp), "import hints that auto backup is not set up", r.stderr)
	c.ok("e2e_L087", len(lk(r.stdout+r.stderr)) == 0, "import output leaks nothing")
	st, _ = os.Stat(e.file("redis.ini"))
	c.ok("e2e_L088", st != nil && st.Mode().Perm() == 0o600, "imported store file is mode 600")
	c.ok("e2e_L089", e.inject("redis.uat", "$REDIS_UAT_PSWD|$REDIS_UAT_HOST|$REDIS_UAT_PORT") == "***|10.0.0.1|6379", "encrypted store: injection decrypts, still redacted")
	c.ok("e2e_L090", e.sh("redis.dev", "printf %s ${#REDIS_DEV_PSWD}") == fmt.Sprint(len("devPass-5678")), "decrypted value has the right length")
	r = e.run("--list", "redis.uat")
	c.ok("e2e_L092", r.status == 0 && regexp.MustCompile(`REDIS_UAT_PSWD\s+密码`).MatchString(r.stdout), "--list works on encrypted store", r)

	// --- edit: update, add, delete, omit, new section, unchanged
	e.run("--export", "redis")
	tx := read(e.imp("redis.ini"))
	tx = replaceFirst(tx, `(?s)(\[uat\].*?)PSWD = <hold>`, "${1}PSWD = newPass-9999\nTOKEN = tok-abcdef")
	tx = replaceFirst(tx, `(?s)(\[dev\].*?)PSWD = <hold>\n`, "${1}") // omitted -> kept
	tx = strings.Replace(tx, "HOST = 10.0.0.2 ; 开发机", "HOST = <delete>", 1)
	tx += "\n[prod]\n; @desc Redis：prod\nHOST = 10.0.0.3\nPSWD = \"a ;b\"\n"
	e.write(e.imp("redis.ini"), tx)
	r = e.run("--import", "redis")
	c.ok("e2e_L103", r.status == 0, "--import with edits", r)
	sep := msg.Text(msg.RepSep)
	repLine := func(sec string, parts ...string) string { return msg.Text(msg.RepLine, sec, strings.Join(parts, sep)) }
	c.ok("e2e_L104", strings.Contains(r.stdout, repLine("uat", msg.Text(msg.RepAdded, "TOKEN"), msg.Text(msg.RepUpdated, "PSWD"))) &&
		strings.Contains(r.stdout, repLine("dev", msg.Text(msg.RepDeleted, "HOST"))) &&
		strings.Contains(r.stdout, repLine("prod", msg.Text(msg.RepAdded, "HOST, PSWD"))), "import report lists added/updated/deleted key names", r.stdout)
	c.ok("e2e_L105", strings.Contains(r.stdout, msg.Text(msg.ImpKeysKept, "dev", "PSWD")), "omitted key reported as kept")
	c.ok("e2e_L106", e.inject("redis.uat", "$REDIS_UAT_PSWD") == "***" && e.sh("redis.uat", "printf %s ${#REDIS_UAT_PSWD}") == "12", "updated value injected")
	c.ok("e2e_L107", e.sh("redis.dev", `printf %s "${REDIS_DEV_HOST-unset}:${#REDIS_DEV_PSWD}"`) == "unset:12", "deleted key gone, omitted key kept")
	prodPart := ""
	if p := strings.SplitN(e.store("redis.ini"), "[prod]", 2); len(p) == 2 {
		prodPart = p[1]
	}
	c.ok("e2e_L108", strings.Contains(prodPart, "PSWD = ENC:v1:"), `value with " ;" stored encrypted in [prod]`)
	c.ok("e2e_L109", e.sh("redis.prod", "printf %s ${#REDIS_PROD_PSWD}") == "4", "quoted value length correct")
	c.ok("e2e_L110", len(lk(e.store("redis.ini"))) == 0, "store still has no plaintext secrets")

	// --- validation failures leave the store untouched
	before := e.store("redis.ini")
	for _, v := range []struct {
		label  string
		mutate func(string) string
		id     msg.ID
		args   []string
	}{
		{"<fill> left", func(x string) string { return strings.Replace(x, "PSWD = <hold>", "PSWD = <fill>", 1) }, msg.ImpFill, nil},
		{"<hold> without old value", func(x string) string { return x + "\n[x1]\nPSWD = <hold>\n" }, msg.ImpHoldNone, nil},
		{"commented KEY = value", func(x string) string { return x + "\n; PSWD = oldsecret\n" }, msg.ImpCommented, nil},
		{"duplicate key", func(x string) string { return strings.Replace(x, "[prod]", "[prod]\nHOST = 1\nHOST = 2", 1) }, msg.ImpDupKey, []string{"*", "prod", "HOST"}},
		{"keys differing only in case", func(x string) string { return strings.Replace(x, "[prod]", "[prod]\nTOKEN = a1\ntoken = b2", 1) }, msg.ImpDupKey, []string{"*", "prod", "token"}},
		{"duplicate section", func(x string) string { return x + "\n[uat]\nPSWD = <hold>\n" }, msg.ImpDupSection, []string{"*", "uat"}},
		{"invalid section name", func(x string) string { return x + "\n[bad name!]\nPSWD = x1\n" }, msg.ImpBadSection, []string{"*", "bad name!"}},
		{"invalid key name", func(x string) string { return strings.Replace(x, "[prod]", "[prod]\nBAD-KEY = 1", 1) }, msg.ImpBadKey, []string{"*", "BAD-KEY"}},
		{"line that is not KEY = value", func(x string) string { return strings.Replace(x, "[prod]", "[prod]\njust some words", 1) }, msg.ImpUnrecognized, nil},
	} {
		e.run("--export", "redis")
		e.write(e.imp("redis.ini"), v.mutate(read(e.imp("redis.ini"))))
		r = e.run("--import", "redis")
		c.ok("e2e_L128", r.status != 0 && hasArgs(r.stdout, v.id, v.args...) && e.store("redis.ini") == before && exists(e.imp("redis.ini")),
			"rejects "+v.label+"; store unchanged; import file kept", r)
		os.Remove(e.imp("redis.ini"))
	}

	// --- ciphertext moved to another key is rejected
	s2 := e.store("redis.ini")
	uatEnc := regexp.MustCompile(`(?s)\[uat\].*?PSWD = (ENC:v1:\S+)`).FindStringSubmatch(s2)[1]
	e.write(e.file("redis.ini"), replaceFirst(s2, `(?s)(\[dev\].*?PSWD = )ENC:v1:\S+`, "${1}"+uatEnc))
	r = e.run("redis.dev", "--", "true")
	c.ok("e2e_L137", r.status != 0 && hasArgs(r.stderr, msg.DecryptFailed, "redis", "dev", "PSWD"), "ciphertext copied to another key fails (AAD binding)", r)
	e.write(e.file("redis.ini"), s2)

	// --- --new template
	r = e.run("--new", "mail", "alert")
	tpl := read(e.imp("mail.ini"))
	c.ok("e2e_L143", r.status == 0 && strings.Contains(tpl, "PSWD = <fill>"), "--new writes template with <fill>", r)
	keysLine := strings.Split(msg.Text(msg.NewTemplate, "f", "n", "d"), "\n")[2]
	c.ok("e2e_L144", strings.Contains(tpl, "@desc") && strings.Contains(tpl, keysLine) && strings.Contains(tpl, "[alert]"), "--new template has @desc, key block and the named node", tpl)
	c.ok("e2e_L145", e.run("--new", "redis").status != 0, "--new refuses an existing file")
	tpl = strings.NewReplacer("HOST = <fill>", "HOST = smtp.x", "PORT = <fill>", "PORT = 465", "USER = <fill>", "USER = a@x", "PSWD = <fill>", "PSWD = mailPw-24680").Replace(tpl)
	e.write(e.imp("mail.ini"), tpl)
	r = e.run("--import", "mail")
	c.ok("e2e_L150", r.status == 0 && strings.Contains(r.stdout, repLine("alert", msg.Text(msg.RepAdded, "HOST, PORT, USER, PSWD"))) && len(lk(e.store("mail.ini"))) == 0, "new file imported and encrypted", r)

	// --- backup with passphrase (tty)
	// Passphrase comes only from /dev/tty: without a terminal, even with it in
	// an env var or on the command line, no bundle is written.
	r = e.runE([]string{"WITH_SECRETS_PASSWORD=" + e2ePass, "GSEAL_PASSWORD=" + e2ePass, "PASSWORD=" + e2ePass}, "--backup", BK, e2ePass)
	c.ok("e2e_L157", r.status != 0 && len(names(BK)) == 0, "backup without a tty fails; passphrase not taken from args or env", r)
	r = e.tty("short\nshort\n", "--backup", BK)
	c.ok("e2e_L159", r.status != 0 && has(r.stdout, msg.PassShort), "backup rejects short passphrase", r)
	r = e.tty(e2ePass+"\nwrong-second-entry\n", "--backup", BK)
	c.ok("e2e_L161", r.status != 0 && has(r.stdout, msg.PassMismatch), "backup rejects mismatched passphrase", r)
	r = e.tty(e2ePass+"\n"+e2ePass+"\n", "--backup", BK)
	kBase, kAuto, kManual := msg.Text(msg.KindBase), msg.Text(msg.KindAuto), msg.Text(msg.KindManual)
	c.ok("e2e_L163", r.status == 0 && hasArgs(r.stdout, msg.BackupDone, kBase), "first backup is the permanent base", r)
	c.ok("e2e_L165", has(r.stdout+r.stderr, msg.BackupInTemp) == inTemp(BK), "backup warns exactly when the dir is under /tmp or $TMPDIR")
	r = e.run("--backup", BK) // stored key: no prompt
	c.ok("e2e_L169", r.status == 0 && hasArgs(r.stdout, msg.BackupDone, kManual), "later manual backup needs no passphrase", r)
	c.ok("e2e_L170", exists(e.file(".backupkey.cred")) && !strings.Contains(read(e.file(".backupkey.cred")), e2ePass), "backup key stored wrapped, passphrase not on disk")

	// --- auto backup + rotation (22 imports -> 19 autos kept, base kept)
	for i := 0; i < 22; i++ {
		e.run("--export", "redis")
		e.write(e.imp("redis.ini"), replaceFirst(read(e.imp("redis.ini")), `(?s)(\[prod\].*?HOST = )\S+`, fmt.Sprintf("${1}h%d", i)))
		r = e.run("--import", "redis")
	}
	c.ok("e2e_L178", hasArgs(r.stdout, msg.AutoDone, kAuto), "import triggers auto backup", r)
	files := names(BK)
	c.ok("e2e_L180", len(withPrefix(files, "secrets-auto-")) == 19, "auto backups rotate to 19", files)
	c.ok("e2e_L181", len(withPrefix(files, "secrets-base-")) == 1 && len(withPrefix(files, "secrets-manual-")) == 1, "base and manual backups kept")
	for _, f := range files {
		b := read(filepath.Join(BK, f))
		c.ok("e2e_L182", len(lk(b)) == 0 && !strings.Contains(b, "10.0.0.1"), "bundle "+f[:min(20, len(f))]+"... fully encrypted (no secrets, no hosts)")
	}

	// --- verify backup
	base := filepath.Join(BK, withPrefix(files, "secrets-base-")[0])
	r = e.tty("totally wrong pass\n", "--verify-backup", base)
	c.ok("e2e_L187", r.status != 0 && has(r.stdout, msg.BundleOpenFailed), "verify: wrong passphrase rejected", r)
	r = e.tty(e2ePass+"\n", "--verify-backup", base)
	c.ok("e2e_L189", r.status == 0 && has(r.stdout, msg.VerifyCounts) && has(r.stdout, msg.VerifyOK), "verify: right passphrase, all values decrypt", r)

	// --- disaster: lose keys and files, restore latest auto backup
	latest := newest(BK, "secrets-auto-")
	for _, f := range names(e.envDir) {
		if strings.HasSuffix(f, ".ini") || strings.HasSuffix(f, ".cred") {
			os.Remove(e.file(f))
		}
	}
	c.ok("e2e_L194", e.run("redis.uat", "--", "true").status != 0, "after loss: injection fails")
	r = e.tty(e2ePass+"\n", "--restore", latest)
	c.ok("e2e_L196", r.status == 0 && hasArgs(r.stdout, msg.RestoreDone, "2"), "restore from latest auto backup", r)
	c.ok("e2e_L197", e.sh("redis.uat", "printf %s ${#REDIS_UAT_PSWD}") == "12" && e.sh("mail.alert", "printf %s ${#MAIL_ALERT_PSWD}") == "12", "restored values decrypt with re-wrapped key")
	hostNow := func() string { return e.sh("redis.prod", `printf %s "$REDIS_PROD_HOST"`) }
	c.ok("e2e_L198", hostNow() == "h21", "restored the newest state")
	r = e.run("--backup")
	c.ok("e2e_L200", r.status == 0, "after restore, backups work with the same passphrase (no prompt)", r)
	r = e.tty(e2ePass+"\n", "--restore", latest)
	c.ok("e2e_L202", r.status == 0 && has(r.stdout, msg.RestoreAside), "restore over existing data moves it aside first", r)

	// --- interrupted import: re-running the same import file is safe (idempotent)
	e.run("--export", "redis")
	e.write(e.imp("redis.ini"), replaceFirst(read(e.imp("redis.ini")), `(?s)(\[uat\].*?PSWD = )\S+`, "${1}resumePw-4242"))
	pending := read(e.imp("redis.ini"))
	r = e.run("--import", "redis")
	c.ok("e2e_L209", r.status == 0, "import (before simulated crash)", r)
	afterFirst := e.store("redis.ini")
	e.write(e.imp("redis.ini"), pending)              // crash after write, before the import file was removed
	e.write(e.file("redis.ini.tmp-99999"), "garbage") // leftover temp file from an interrupted write
	r = e.run("--import", "redis")
	changed := false
	for _, id := range []msg.ID{msg.RepAdded, msg.RepUpdated, msg.RepDeleted} {
		changed = changed || strings.Contains(r.stdout, "] "+strings.Split(msg.Text(id), "%s")[0])
	}
	c.ok("e2e_L214", r.status == 0 && !changed && strings.Contains(r.stdout, repLine("uat", msg.Text(msg.RepNone))), "re-import of the same file reports no change", r)
	c.ok("e2e_L215", e.store("redis.ini") == afterFirst, "re-import leaves the store byte-identical (unchanged values keep ciphertext)")
	c.ok("e2e_L216", e.sh("redis.uat", "printf %s ${#REDIS_UAT_PSWD}") == fmt.Sprint(len("resumePw-4242")), "value after re-import is the intended one")
	c.ok("e2e_L217", !strings.Contains(e.run("--list").stdout, "tmp-99999"), "leftover temp file is ignored")
	os.Remove(e.file("redis.ini.tmp-99999"))

	// --- interrupted shred: a crash while shredding leaves only <name>.shredding,
	// which the next command finishes off.
	shreddingLeft := func() bool { return len(filterSuffix(names(e.file("_import")), ".shredding")) > 0 }
	c.ok("e2e_L222", !exists(e.imp("redis.ini")) && !shreddingLeft(), "after import: neither the import file nor a .shredding file is left")
	beforeShred := e.store("redis.ini")
	e.write(e.imp("redis.ini.shredding"), pending)                 // crash after rename, before zeroing
	e.write(e.imp("mail.ini.shredding"), string(make([]byte, 64))) // crash after zeroing, before unlink
	r = e.run("--export", "redis")
	c.ok("e2e_L228", r.status == 0 && hasArgs(r.stderr, msg.SweepDone, "redis.ini.shredding") && hasArgs(r.stderr, msg.SweepDone, "mail.ini.shredding"),
		"next admin command finishes leftover .shredding files and says so", r)
	c.ok("e2e_L230", !shreddingLeft(), "leftover .shredding files are gone")
	c.ok("e2e_L231", e.store("redis.ini") == beforeShred, "store untouched by the sweep")
	// A damaged import file (e.g. zeroed in place by an older version) is refused.
	e.write(e.imp("redis.ini"), string(make([]byte, 40))+"\n[uat]\nHOST = 10.9.9.9\n")
	r = e.run("--import", "redis")
	c.ok("e2e_L235", r.status == 1 && has(r.stderr, msg.ImportNUL) && e.store("redis.ini") == beforeShred && exists(e.imp("redis.ini")),
		"import refuses a file with NUL bytes; store unchanged", r)
	os.Remove(e.imp("redis.ini"))

	// --- auto backup failure: import done, exit 3, fixed by a manual backup
	var conf map[string]any
	json.Unmarshal([]byte(e.store(".backup.json")), &conf)
	e.write(filepath.Join(e.root, "not-a-dir"), "")
	conf["dir"] = filepath.Join(e.root, "not-a-dir", "bk")
	cj, _ := json.Marshal(conf)
	e.write(e.file(".backup.json"), string(cj))
	e.run("--export", "redis")
	e.write(e.imp("redis.ini"), replaceFirst(read(e.imp("redis.ini")), `(?s)(\[prod\].*?HOST = )\S+`, "${1}hfail"))
	r = e.run("--import", "redis")
	c.ok("e2e_L246", r.status == 3 && has(r.stderr, msg.Committed) && has(r.stderr, msg.AutoFailed), "auto backup failure: exit 3 with a clear warning", r)
	c.ok("e2e_L247", hostNow() == "hfail" && !exists(e.imp("redis.ini")), "auto backup failure: the import itself is complete")
	r = e.run("--backup", BK)
	c.ok("e2e_L249", r.status == 0 && hasArgs(r.stdout, msg.BackupDone, kManual), "auto backup failure: manual --backup <dir> recovers", r)

	// --- default backup dir = $TMPDIR/with-secrets-backup (warns); no dir configured
	TMPD := filepath.Join(e.root, "tmpdir")
	os.Mkdir(TMPD, 0o700)
	os.Remove(e.file(".backup.json"))
	r = e.runE([]string{"TMPDIR=" + TMPD}, "--backup")
	defDir := filepath.Join(TMPD, "with-secrets-backup")
	c.ok("e2e_L257", r.status == 0 && len(withPrefix(names(defDir), "secrets-base-")) > 0, "no dir given: backup goes to $TMPDIR/with-secrets-backup", r)
	c.ok("e2e_L258", has(r.stderr, msg.BackupInTemp), "default (temp) backup dir warns", r.stderr)
	AUTO := defDir // auto backups go here from now on

	// ======================================================== M2 round 2 ====
	// --- M2-001: case-insensitive keys; sections left out of the import are kept with their docs
	e.write(e.file("case2.ini"), strings.Join([]string{
		"; @desc 合并", "", "[a]", "Host = h-old", "PSWD = p-old-1234", "",
		"[empty]", "; @desc 空节说明", "", "[docs]", "; @desc 带说明的节", "TOKEN = tok-keep-1", "",
	}, "\n"))
	e.write(e.imp("case2.ini"), "[a]\nHOST = h-new\npswd = <hold>\n")
	r = e.run("--import", "case2")
	s := e.store("case2.ini")
	c.ok("e2e_L312", r.status == 0 && strings.Contains(s, "[empty]") && strings.Contains(s, "空节说明") && strings.Contains(s, "[docs]") && strings.Contains(s, "带说明的节"),
		"sections left out of the import (empty, documented) are kept with their docs", r, s)
	c.ok("e2e_L313", strings.Contains(r.stdout, msg.Text(msg.ImpSectionKept, "empty")) && strings.Contains(r.stdout, msg.Text(msg.ImpSectionKept, "docs")), "kept sections are reported")
	c.ok("e2e_L314", strings.Contains(s, "TOKEN = ENC:v1:") && !strings.Contains(s, "Host =") && strings.Contains(s, "HOST = h-new") && strings.Contains(s, "pswd = ENC:v1:"),
		"keys matched without regard to case; kept plaintext secret encrypted", s)
	r = e.run("case2.a", "--", `printf "%s|%s" "$CASE2_A_HOST" "${#CASE2_A_PSWD}"`)
	c.ok("e2e_L316", r.status == 0 && r.stdout == fmt.Sprintf("h-new|%d", len("p-old-1234")), "renamed key re-encrypted under its new name; injection works (no case clash)", r)
	c.ok("e2e_L317", regexp.MustCompile(`case2\.empty\s+空节说明`).MatchString(e.run("--list", "case2").stdout), "kept empty section still listed with its doc")
	// A store whose keys already clash by case must be resolved explicitly.
	e.write(e.file("case3.ini"), "[a]\nHost = x-1\nHOST = y-2\nPSWD = p3\n")
	case3 := e.store("case3.ini")
	for _, v := range []struct {
		label, body string
		id          msg.ID
	}{
		{"clash left out of the import", "[a]\nPSWD = <hold>\n", msg.ImpStoreClash},
		{"<hold> on a clashing key", "[a]\nHOST = <hold>\nPSWD = <hold>\n", msg.ImpHoldAmbig},
	} {
		e.write(e.imp("case3.ini"), v.body)
		r = e.run("--import", "case3")
		c.ok("e2e_L327", r.status == 1 && has(r.stdout, v.id) && e.store("case3.ini") == case3 && exists(e.imp("case3.ini")), "rejects "+v.label+"; store unchanged", r)
		os.Remove(e.imp("case3.ini"))
	}
	e.write(e.imp("case3.ini"), "[a]\nHOST = z-3\nPSWD = <hold>\n")
	r = e.run("--import", "case3")
	c.ok("e2e_L332", r.status == 0 && hasArgs(r.stdout, msg.ImpCaseMerged, "*", "a", "*", "HOST") && e.sh("case3.a", `printf %s "$CASE3_A_HOST"`) == "z-3",
		"a new value resolves the clash (merged into one key)", r)
	// The check uses the key set injection really sees: [DEFAULT] merged into each node.
	e.write(e.file("case4.ini"), "[DEFAULT]\nPORT = 1\n\n[a]\nHOST = h4\n")
	case4 := e.store("case4.ini")
	for _, v := range []struct{ label, body string }{
		{"[DEFAULT] Host vs [a] HOST", "[DEFAULT]\nPORT = 1\nHost = d4\n\n[a]\nHOST = h4\n"},
		{"[DEFAULT] PORT vs [a] port", "[DEFAULT]\nPORT = 1\n\n[a]\nHOST = h4\nport = 2\n"},
	} {
		e.write(e.imp("case4.ini"), v.body)
		r = e.run("--import", "case4")
		c.ok("e2e_L342", r.status == 1 && has(r.stderr, msg.ImpCaseClash) && e.store("case4.ini") == case4 && exists(e.imp("case4.ini")) &&
			e.run("case4.a", "--", "true").status == 0, "rejects "+v.label+" (merged key set); store and import file unchanged", r)
		os.Remove(e.imp("case4.ini"))
	}
	e.write(e.imp("case4.ini"), "[DEFAULT]\nPORT = 1\n\n[a]\nHOST = h4\nPORT = 2\n")
	r = e.run("--import", "case4")
	c.ok("e2e_L348", r.status == 0 && e.sh("case4.a", `printf %s "$CASE4_A_PORT"`) == "2", "same spelling in a node still overrides [DEFAULT]", r)

	// --- M2-002: commented assignments, names that shadow Object.prototype
	case3b := e.store("case3.ini")
	e.write(e.imp("case3.ini"), "[a]\nHOST = <hold>\nPSWD = <hold>\n; BAD KEY = synthetic\n")
	r = e.run("--import", "case3")
	c.ok("e2e_L354", r.status == 1 && has(r.stdout, msg.ImpCommented) && e.store("case3.ini") == case3b && exists(e.imp("case3.ini")), "rejects a commented assignment with a spaced key; store unchanged", r)
	os.Remove(e.imp("case3.ini"))
	e.write(e.imp("case3.ini"), "[a]\nHOST = <hold>\nPSWD = <hold>\n; BAD KEY WITH FIVE WORDS = synthetic\n; "+strings.Repeat("W ", 40)+"= long\n")
	r = e.run("--import", "case3")
	c.ok("e2e_L358", r.status == 1 && count(r.stdout, msg.ImpCommented) == 2 && e.store("case3.ini") == case3b, "rejects commented assignments with any number of words; store unchanged", r)
	os.Remove(e.imp("case3.ini"))
	e.write(e.imp("case3.ini"), "; @desc 说明：链接 http://x.invalid/?a=b 与 例如 x = y\n;   PORT  端口\n[a]\nHOST = <hold>\nPSWD = <hold>\n")
	r = e.run("--import", "case3")
	c.ok("e2e_L362", r.status == 0 && strings.Contains(e.run("--list", "case3").stdout, "链接 http://x.invalid/?a=b"), "doc prose containing = (URL, CJK) is still accepted and shown", r)
	for _, v := range []struct{ label, body string }{
		{"toString = <hold> in [constructor]", "[constructor]\ntoString = <hold>\n"},
		{"__proto__ = <hold>", "[a]\n__proto__ = <hold>\n"},
		{"constructor = <hold>", "[a]\nconstructor = <hold>\n"},
	} {
		e.write(e.imp("proto.ini"), v.body)
		r = e.run("--import", "proto")
		c.ok("e2e_L370", r.status == 1 && has(r.stdout, msg.ImpHoldNone) && !exists(e.file("proto.ini")) && exists(e.imp("proto.ini")), "rejects "+v.label+` (no inherited "old value")`, r)
		os.Remove(e.imp("proto.ini"))
	}
	e.write(e.imp("proto.ini"), "[constructor]\nHOST = h-c\nvalueOf = v-1-secret\n\n[__proto__]\nPSWD = p-proto-9\n")
	r = e.run("--import", "proto")
	c.ok("e2e_L375", r.status == 0 && e.sh("proto.constructor", `printf "%s|%s" "$PROTO_CONSTRUCTOR_HOST" "${#PROTO_CONSTRUCTOR_VALUEOF}"`) == "h-c|10" &&
		e.sh("proto.__proto__", `printf %s "${#PROTO_PROTO__PSWD}"`) == "9", "legal names constructor / valueOf / __proto__ work as plain names", r)
	c.ok("e2e_L377", strings.Contains(e.run("--list", "proto.constructor").stdout, "PROTO_CONSTRUCTOR_VALUEOF"), "--list handles them too")

	// --- M2-003: failures before the commit leave the store; after it, exit 3
	snap := e.snapshot()
	e.run("--export", "redis")
	e.write(e.imp("redis.ini"), replaceFirst(read(e.imp("redis.ini")), `(?s)(\[prod\].*?HOST = )\S+`, "${1}hshort"))
	for _, point := range []string{"short-write", "before-commit"} {
		r = e.runE([]string{"GSEAL_FAULT=" + point}, "--import", "redis")
		c.ok("e2e_L385", r.status == 1 && same(e.snapshot(), snap) && exists(e.imp("redis.ini")) && e.noTemps(), point+": exit 1, store unchanged, import file kept, no temp files", r)
	}
	r = e.runE([]string{"GSEAL_FAULT=after-commit"}, "--import", "redis")
	c.ok("e2e_L388", r.status == 3 && has(r.stderr, msg.Committed) && hasArgs(r.stderr, msg.FaultAt, "after-commit") && hostNow() == "hshort" && exists(e.imp("redis.ini")),
		"failure right after the commit: exit 3, store changed, import file still there (re-import is safe)", r)
	r = e.run("--import", "redis")
	c.ok("e2e_L391", r.status == 0 && strings.Contains(r.stdout, repLine("prod", msg.Text(msg.RepNone))), "re-running that import finishes it (no change)", r)
	e.run("--export", "redis")
	e.write(e.imp("redis.ini"), replaceFirst(read(e.imp("redis.ini")), `(?s)(\[prod\].*?HOST = )\S+`, "${1}hshred"))
	r = e.runE([]string{"GSEAL_FAULT=shred-overwrite"}, "--import", "redis")
	c.ok("e2e_L395", r.status == 3 && has(r.stderr, msg.Committed) && has(r.stderr, msg.ShredFailed) && has(r.stderr, msg.ImpShredLeft) && hostNow() == "hshred",
		"shred failure after commit: exit 3, store changed, says what is pending", r)
	c.ok("e2e_L397", exists(e.imp("redis.ini.shredding")) && !exists(e.imp("redis.ini")), "the unshredded file is kept as .shredding for retry")
	r = e.run("--export", "mail")
	c.ok("e2e_L399", r.status == 0 && hasArgs(r.stderr, msg.SweepDone, "redis.ini.shredding") && !exists(e.imp("redis.ini.shredding")), "next command retries and finishes the shred", r)
	os.Remove(e.imp("mail.ini"))
	os.Mkdir(e.imp("odd.shredding"), 0o700)
	r = e.run("--export", "mail")
	c.ok("e2e_L403", r.status == 0 && has(r.stderr, msg.ShredSkip) && exists(e.imp("odd.shredding")), "sweep skips a non-regular .shredding entry instead of failing", r)
	os.RemoveAll(e.imp("odd.shredding"))
	os.Remove(e.imp("mail.ini"))
	e.write(e.file(".backup.json"), "{broken")
	e.run("--export", "redis")
	e.write(e.imp("redis.ini"), replaceFirst(read(e.imp("redis.ini")), `(?s)(\[prod\].*?HOST = )\S+`, "${1}hconf"))
	r = e.run("--import", "redis")
	c.ok("e2e_L410", r.status == 3 && has(r.stderr, msg.BackupConfBad) && hostNow() == "hconf", "corrupt backup config: import committed, exit 3, cause named", r)
	r = e.run("--backup", AUTO)
	conf = nil
	json.Unmarshal([]byte(e.store(".backup.json")), &conf)
	c.ok("e2e_L412", r.status == 0 && conf["dir"] == AUTO, "--backup <dir> repairs the config", r)

	// --- M2-004: one management command at a time
	parallel := func(n int, extra []string, args ...string) []res {
		var chs []chan res
		for i := 0; i < n; i++ {
			chs = append(chs, e.async(extra, args...))
		}
		var out []res
		for _, ch := range chs {
			out = append(out, <-ch)
		}
		return out
	}
	countRes := func(rs []res, f func(res) bool) int {
		n := 0
		for _, x := range rs {
			if f(x) {
				n++
			}
		}
		return n
	}
	rs := parallel(5, nil, "--export", "redis")
	c.ok("e2e_L417", countRes(rs, func(x res) bool { return x.status == 0 }) == 1 && countRes(rs, func(x res) bool { return x.status == 1 && has(x.stderr, msg.ImportPending) }) == 4 &&
		strings.Contains(read(e.imp("redis.ini")), "[uat]"), "5 concurrent --export: exactly one wins, the file is intact", rs)
	os.Remove(e.imp("redis.ini"))
	root2 := filepath.Join(e.root, "root2")
	os.MkdirAll(filepath.Join(root2, "env"), 0o700)
	rs = parallel(5, []string{"GSEAL_STORE=" + root2}, "--init")
	dk2 := filepath.Join(root2, "env", ".datakey.cred")
	keyOK := exists(dk2)
	if sd {
		out, err := exec.Command("systemd-creds", "decrypt", "--user", "--name=with-secrets-data", dk2, "-").Output()
		keyOK = err == nil && len(out) == 32
	}
	c.ok("e2e_L427", countRes(rs, func(x res) bool { return x.status == 0 }) == 1 && keyOK, "5 concurrent --init: exactly one key is created and it works", rs)
	// imports and backups at the same time: every bundle is a consistent snapshot
	autoBefore := map[string]bool{}
	for _, f := range names(AUTO) {
		autoBefore[f] = true
	}
	e.run("--export", "redis")
	e.run("--export", "mail")
	e.write(e.imp("redis.ini"), replaceFirst(read(e.imp("redis.ini")), `(?s)(\[prod\].*?HOST = )\S+`, "${1}hpar"))
	e.write(e.imp("mail.ini"), strings.Replace(read(e.imp("mail.ini")), "HOST = smtp.x", "HOST = smtp.par", 1))
	chs := []chan res{e.async(nil, "--import", "redis"), e.async(nil, "--backup"), e.async(nil, "--import", "mail"), e.async(nil, "--backup")}
	allOK := true
	var prs []res
	for _, ch := range chs {
		x := <-ch
		prs = append(prs, x)
		allOK = allOK && x.status == 0
	}
	c.ok("e2e_L434", allOK, "concurrent imports and backups all succeed (serialised by the lock)", prs)
	var fresh []string
	for _, f := range names(AUTO) {
		if !autoBefore[f] && strings.HasSuffix(f, ".wsbk") {
			fresh = append(fresh, f)
		}
	}
	verified := len(fresh) >= 4
	for _, f := range fresh {
		v := e.tty(e2ePass+"\n", "--verify-backup", filepath.Join(AUTO, f))
		verified = verified && v.status == 0 && has(v.stdout, msg.VerifyOK)
	}
	c.ok("e2e_L436", verified, fmt.Sprintf("each of the %d bundles written meanwhile verifies (keys and files match)", len(fresh)))
	// The lock is a kernel flock: released when the holder dies, however it dies.
	lockInfo := func() string { return read(e.file(".lock")) }
	r = e.runE([]string{"GSEAL_CRASH=after-lock"}, "--export", "redis")
	c.ok("e2e_L444", r.signal == "SIGKILL" && len(lockInfo()) > 0, "crash while holding the lock: holder info left behind", r)
	r = e.run("--export", "redis")
	c.ok("e2e_L446", r.status == 0 && has(r.stderr, msg.LockStale) && lockInfo() == "", "next command gets the lock at once (kernel released it) and says the last one did not finish", r)
	os.Remove(e.imp("redis.ini"))
	// several competitors right after a crash: still exactly one at a time
	e.runE([]string{"GSEAL_CRASH=after-lock"}, "--export", "redis")
	rs = parallel(5, nil, "--export", "redis")
	c.ok("e2e_L451", countRes(rs, func(x res) bool { return x.status == 0 }) == 1 && countRes(rs, func(x res) bool { return has(x.stderr, msg.ImportPending) }) == 4,
		"5 competitors after a crash: exactly one export, the rest refused", rs)
	os.Remove(e.imp("redis.ini"))
	// mutual exclusion while a holder is alive: a short waiter gives up, a normal one waits
	{
		t0 := time.Now()
		holderCh := e.async([]string{"GSEAL_HOLD_MS=1500"}, "--export", "redis")
		time.Sleep(400 * time.Millisecond)
		quick := <-e.async([]string{"GSEAL_LOCK_WAIT_MS=300"}, "--export", "mail")
		c.ok("e2e_L459", quick.status == 1 && hasArgs(quick.stderr, msg.LockBusy, "--export") && !exists(e.imp("mail.ini")), "while the lock is held: a short waiter gives up, nothing written", quick)
		patient := e.async(nil, "--export", "mail")
		h, p := <-holderCh, <-patient
		c.ok("e2e_L462", h.status == 0 && p.status == 0 && has(p.stderr, msg.LockWaiting) && time.Since(t0) >= 1500*time.Millisecond, "a normal waiter proceeds after the holder releases", h, p)
		os.Remove(e.imp("redis.ini"))
		os.Remove(e.imp("mail.ini"))
	}
	// a backup that starts while a restore holds the lock uses the restored key and data
	{
		hostBeforeRestore := hostNow()
		restoring := e.ttyInteractive([]string{"GSEAL_HOLD_MS=1500"}, msg.PromptPass, 100*time.Millisecond, e2ePass, "--restore", latest)
		// Start the backup once the restore holds the lock (passphrase typed,
		// scrypt done; the holder info names --restore), not after a fixed delay.
		for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
			if strings.Contains(read(e.file(".lock")), `"--restore"`) {
				break
			}
		}
		backing := e.async(nil, "--backup")
		rr, bb := <-restoring, <-backing
		made := ""
		prefix := msg.Text(msg.BackupDone, kManual, "")
		for _, l := range strings.Split(bb.stdout, "\n") {
			if strings.HasPrefix(l, prefix) {
				made = strings.TrimPrefix(l, prefix)
			}
		}
		c.ok("e2e_L482", rr.status == 0 && bb.status == 0 && hasArgs(bb.stderr, msg.LockWaiting, "--restore") && made != "", "backup started during a restore waits for it", rr, bb)
		prodHost := ""
		var dk *string
		if p, err := openBundleWith(made, e2ePass); err == nil {
			if m := regexp.MustCompile(`(?s)\[prod\].*?HOST = (\S+)`).FindStringSubmatch(p.Files["redis.ini"]); m != nil {
				prodHost = m[1]
			}
			dk = p.DataKey
		}
		c.ok("e2e_L485", hostBeforeRestore != "h21" && prodHost == "h21" && dk != nil, "that backup holds the restored data (decrypted in the test: prod HOST = h21) and a data key")
		e.run("--undo-restore")
	}

	// --- M2-006: a bundle is published only when complete
	BK2 := filepath.Join(e.root, "bk2")
	r = e.runE([]string{"GSEAL_CRASH=bundle-written"}, "--backup", BK2)
	c.ok("e2e_L492", r.signal == "SIGKILL" && len(filterSuffix(names(BK2), ".wsbk")) == 0, "crash while writing the first bundle: no bundle is visible", r)
	r = e.run("--backup", BK2)
	c.ok("e2e_L494", r.status == 0 && hasArgs(r.stdout, msg.BackupDone, kBase) && len(withPrefix(names(BK2), "secrets-base-")) == 1 && !anyContains(names(BK2), ".tmp-"),
		"next backup becomes the base; the partial file is cleaned up", r)
	e.run("--backup", AUTO) // back to the auto dir
	autoCount := func() int { return len(withPrefix(names(AUTO), "secrets-auto-")) }
	for i := autoCount(); i < 19; i++ {
		e.run("--export", "redis")
		e.run("--import", "redis")
	}
	c.ok("e2e_L499", autoCount() == 19, "(rotation full: 19 auto bundles)")
	e.run("--export", "redis")
	r = e.runE([]string{"GSEAL_CRASH=bundle-written"}, "--import", "redis")
	c.ok("e2e_L502", r.signal == "SIGKILL" && !exists(e.imp("redis.ini")) && anyContains(names(AUTO), ".tmp-") && autoCount() == 19,
		"crash during an auto backup (import committed): partial file is not a bundle, none rotated out", r)
	e.run("--export", "redis")
	r = e.run("--import", "redis")
	autos := withPrefix(names(AUTO), "secrets-auto-")
	allBundles := true
	for _, f := range autos {
		allBundles = allBundles && isBundle(filepath.Join(AUTO, f))
	}
	c.ok("e2e_L506", r.status == 0 && len(autos) == 19 && allBundles && !anyContains(names(AUTO), ".tmp-"), "after it: 19 valid auto bundles, no partial file counted or left", r)
	// Damaged files with valid names (e.g. left by an older version) never count.
	{
		newestAuto := newest(AUTO, "secrets-auto-")
		baseFile := withPrefix(names(AUTO), "secrets-base-")[0]
		good := []byte(read(newestAuto))
		bad := map[string][]byte{
			"secrets-auto-29991231T235959000.wsbk": {},                                          // empty
			"secrets-auto-29991231T235959001.wsbk": good[:len(good)-10],                         // truncated
			"secrets-auto-29991231T235959002.wsbk": flipLast(good),                              // bit flip
			"secrets-auto-29991231T235959003.wsbk": []byte(read(filepath.Join(AUTO, baseFile))), // header kind != name
		}
		for f, b := range bad {
			e.write(filepath.Join(AUTO, f), string(b))
		}
		e.run("--export", "redis")
		r = e.run("--import", "redis")
		var intact []string
		for _, f := range withPrefix(names(AUTO), "secrets-auto-") {
			if _, isBad := bad[f]; !isBad {
				intact = append(intact, f)
			}
		}
		badKept := true
		for f := range bad {
			badKept = badKept && exists(filepath.Join(AUTO, f))
		}
		c.ok("e2e_L522", r.status == 0 && count(r.stderr, msg.BundleDamaged) == 4 && len(intact) == 19 && badKept, "damaged auto files are reported, not counted, not deleted; 19 intact remain", r)
		decrypts := true
		for _, f := range intact {
			p, err := openBundleWith(filepath.Join(AUTO, f), e2ePass)
			decrypts = decrypts && err == nil && p.Files != nil
		}
		c.ok("e2e_L524", decrypts, "all 19 counted bundles decrypt (checked in the test)")
		for f := range bad {
			os.Remove(filepath.Join(AUTO, f))
		}
		BK4 := filepath.Join(e.root, "bk4")
		os.Mkdir(BK4, 0o700)
		realBase := read(filepath.Join(AUTO, baseFile))
		e.write(filepath.Join(BK4, "secrets-base-20000101T000000000.wsbk"), "")
		e.write(filepath.Join(BK4, "secrets-base-20000101T000000001.wsbk"), realBase[:len(realBase)-5])
		r = e.run("--backup", BK4)
		c.ok("e2e_L532", r.status == 0 && hasArgs(r.stdout, msg.BackupDone, kBase), "damaged files named as base do not count: a new base is made", r)
		e.run("--backup", AUTO) // back to the auto dir
	}
	keyBefore := e.store(".backupkey.cred")
	confBefore := e.store(".backup.json")
	r = e.ttyE([]string{"GSEAL_FAULT=bundle-written"}, e2eNewPass+"\n"+e2eNewPass+"\n", "--backup", filepath.Join(e.root, "bk3"), "--new-password")
	c.ok("e2e_L539", r.status == 1 && e.store(".backupkey.cred") == keyBefore && e.store(".backup.json") == confBefore, "--new-password with a failed bundle: passphrase and dir settings unchanged", r)
	r = e.ttyE([]string{"GSEAL_FAULT=save-backupkey"}, e2eNewPass+"\n"+e2eNewPass+"\n", "--backup", AUTO, "--new-password")
	c.ok("e2e_L542", r.status == 3 && has(r.stdout+r.stderr, msg.BackupPassNotSaved) && e.store(".backupkey.cred") == keyBefore, "bundle written but new passphrase not saved: exit 3, old key still in use", r)
	r = e.runE([]string{"GSEAL_FAULT=save-conf"}, "--backup", BK2)
	c.ok("e2e_L544", r.status == 3 && has(r.stderr, msg.BackupDirNotSaved) && e.store(".backup.json") == confBefore, "bundle written but new dir not saved: exit 3, config unchanged", r)
	e.run("--export", "redis")
	e.run("--import", "redis")
	c.ok("e2e_L547", e.tty(e2ePass+"\n", "--verify-backup", newest(AUTO, "secrets-auto-")).status == 0, "auto backups still use the old passphrase")

	// --- M2-005: restore stages and checks first; a failed swap rolls back; a crash rolls forward
	journalF := e.file(".swap-journal.json")
	noStaging := func() bool { return len(withPrefix(names(e.envDir), ".restore-")) == 0 }
	before5 := e.snapshot()
	hostBefore := hostNow()
	for _, point := range []string{"restore-staging", "wrap", "swap-in", "swap-out"} {
		r = e.ttyE([]string{"GSEAL_FAULT=" + point}, e2ePass+"\n", "--restore", latest)
		c.ok("e2e_L555", r.status == 1 && same(e.snapshot(), before5) && !exists(journalF) && noStaging() && hostNow() == hostBefore, "restore failing at "+point+": exit 1, store unchanged and usable", r)
	}
	e.ttyE([]string{"GSEAL_CRASH=swap-in"}, e2ePass+"\n", "--restore", latest)
	c.ok("e2e_L559", exists(journalF), "crash in the middle of a restore leaves the journal")
	r = e.run("--export", "mail")
	c.ok("e2e_L561", r.status == 0 && hasArgs(r.stderr, msg.RecoverDone, msg.Text(msg.OpRestore)) && !exists(journalF) && hostNow() == "h21", "next command completes the restore (roll forward)", r)
	os.Remove(e.imp("mail.ini"))
	r = e.run("--undo-restore")
	c.ok("e2e_L564", r.status == 0 && hostNow() == hostBefore && e.sh("mail.alert", `printf %s "$MAIL_ALERT_HOST"`) == "smtp.par", "--undo-restore puts back the previous store (values and key)", r)
	r = e.tty(e2ePass+"\n", "--restore", latest)
	c.ok("e2e_L566", r.status == 0 && hostNow() == "h21", "restore again", r)
	e.runE([]string{"GSEAL_CRASH=swap-in"}, "--undo-restore")
	r = e.run("--export", "mail")
	c.ok("e2e_L569", r.status == 0 && hasArgs(r.stderr, msg.RecoverDone, msg.Text(msg.OpUndo)) && hostNow() == hostBefore, "a crashed undo is completed by the next command", r)
	os.Remove(e.imp("mail.ini"))
	// Failure after the files are swapped (writing restore.json): exit 5, not "unchanged".
	r = e.ttyE([]string{"GSEAL_FAULT=finish-swap"}, e2ePass+"\n", "--restore", latest)
	c.ok("e2e_L573", r.status == 5 && has(r.stdout+r.stderr, msg.SwapFinishFailed) && hostNow() == "h21" && exists(journalF), "bookkeeping failure after the swap: exit 5, store already restored, journal kept", r)
	r = e.run("--export", "mail")
	var asides []string
	for _, d := range names(e.file(".backup")) {
		if regexp.MustCompile(`^pre-restore-\d+T\d+$`).MatchString(d) {
			asides = append(asides, d)
		}
	}
	lastAside := ""
	if len(asides) > 0 {
		lastAside = asides[len(asides)-1]
	}
	c.ok("e2e_L577", r.status == 0 && has(r.stderr, msg.RecoverDone) && !exists(journalF) && exists(filepath.Join(e.file(".backup"), lastAside, "restore.json")) && noStaging(),
		"next command finishes the bookkeeping", r)
	os.Remove(e.imp("mail.ini"))
	r = e.run("--undo-restore")
	c.ok("e2e_L581", r.status == 0 && hostNow() == hostBefore, "and that restore can be undone", r)

	// --- M2-007: --list withholds doc text it cannot reliably mask
	listAll := func() string {
		return e.run("--list").stdout + "\n" + e.run("--list", "redis").stdout + "\n" + e.run("--list", "redis.uat").stdout
	}
	c.ok("e2e_L585", strings.Contains(listAll(), "Redis：UAT"), "(docs shown while everything decrypts)")
	rtext := e.store("redis.ini")
	damaged := rtext // first PSWD ciphertext with its first character changed
	if loc := regexp.MustCompile(`PSWD = ENC:v1:`).FindStringIndex(rtext); loc != nil {
		ch := byte('A')
		if rtext[loc[1]] == 'A' {
			ch = 'B'
		}
		damaged = rtext[:loc[1]] + string(ch) + rtext[loc[1]+1:]
	}
	e.write(e.file("redis.ini"), damaged)
	L := listAll()
	docsGone := !regexp.MustCompile(`Redis：UAT|密码`).MatchString(L)
	c.ok("e2e_L589", docsGone && strings.Contains(L, msg.Text(msg.ListHidden)) && has(L, msg.ListHiddenNote) && strings.Contains(L, "REDIS_UAT_PSWD"), "one damaged ciphertext: docs hidden, names shown, notice given", L)
	e.write(e.file("redis.ini"), rtext)
	os.Rename(e.file(".datakey.cred"), filepath.Join(e.root, "datakey.aside"))
	L = listAll()
	c.ok("e2e_L593", !regexp.MustCompile(`Redis：UAT|密码`).MatchString(L) && strings.Contains(L, msg.Text(msg.ListHidden)) && strings.Contains(L, msg.Text(msg.DataKeyMissing)), "data key unavailable: docs hidden with the reason", L)
	os.Rename(filepath.Join(e.root, "datakey.aside"), e.file(".datakey.cred"))
	c.ok("e2e_L595", strings.Contains(listAll(), "Redis：UAT"), "(docs back once the key is back)")

	// ======================================================== M2 round 3 ====
	// --- M2-005: the journal must actually go away; until it does, no other work
	{
		hostPre := hostNow()
		r = e.ttyE([]string{"GSEAL_FAULT=journal-unlink"}, e2ePass+"\n", "--restore", latest)
		c.ok("e2e_L603", r.status == 5 && has(r.stdout+r.stderr, msg.SwapFinishFailed) && exists(journalF) && hostNow() == "h21", "journal cannot be removed: exit 5 (not 0), journal kept", r)
		r = e.runE([]string{"GSEAL_FAULT=journal-unlink"}, "--export", "mail")
		c.ok("e2e_L605", r.status == 5 && !exists(e.imp("mail.ini")) && exists(journalF), "while it persists, other management commands are refused (exit 5, nothing written)", r)
		r = e.run("--export", "mail")
		c.ok("e2e_L607", r.status == 0 && has(r.stderr, msg.RecoverDone) && !exists(journalF) && exists(e.imp("mail.ini")), "once it clears, the next command finishes the restore and proceeds", r)
		os.Remove(e.imp("mail.ini"))
		r = e.run("--undo-restore")
		c.ok("e2e_L610", r.status == 0 && hostNow() == hostPre, "and the restore can be undone", r)
	}

	// --- M2-006: only bundles verified with the current passphrase count
	{
		BK5 := filepath.Join(e.root, "bk5")
		e.run("--backup", BK5)
		oldBase := withPrefix(names(BK5), "secrets-base-")[0]
		ob := []byte(read(filepath.Join(BK5, oldBase)))
		e.write(filepath.Join(BK5, oldBase), string(flipLast(ob)))
		c.ok("e2e_L620", e.tty(e2ePass+"\n", "--verify-backup", filepath.Join(BK5, oldBase)).status == 1, "(old base damaged: verify fails)")
		r = e.tty(e2eNewPass+"\n"+e2eNewPass+"\n", "--backup", BK5, "--new-password")
		bases5 := withPrefix(names(BK5), "secrets-base-")
		c.ok("e2e_L623", r.status == 0 && hasArgs(r.stdout, msg.BackupDone, kBase) && len(bases5) == 2 && exists(filepath.Join(BK5, oldBase)),
			"passphrase change over a damaged old-passphrase base: a new, verifiable base is made; the old file is kept", r)
		newBase := ""
		for _, f := range bases5 {
			if f != oldBase {
				newBase = f
			}
		}
		p, err := openBundleWith(filepath.Join(BK5, newBase), e2eNewPass)
		c.ok("e2e_L626", err == nil && p.Files != nil, "the new base opens with the new passphrase")
		// old-passphrase autos (one of them damaged, same length) never count toward rotation
		oldAutos := withPrefix(names(AUTO), "secrets-auto-")
		victim := filepath.Join(AUTO, oldAutos[0])
		vb := []byte(read(victim))
		vb[40] ^= 1
		e.write(victim, string(vb))
		r = e.run("--backup", AUTO) // now the new passphrase: new base in AUTO
		c.ok("e2e_L633", r.status == 0 && hasArgs(r.stdout, msg.BackupDone, kBase) && has(r.stderr, msg.BundleOthers), "new passphrase in the auto dir: new base; old-passphrase bundles reported as unverifiable", r)
		for i := 0; i < 3; i++ {
			e.run("--export", "redis")
			e.run("--import", "redis")
		}
		nowAutos := withPrefix(names(AUTO), "secrets-auto-")
		old := map[string]bool{}
		for _, f := range oldAutos {
			old[f] = true
		}
		kept := 0
		var newAutos []string
		for _, f := range nowAutos {
			if old[f] {
				kept++
			} else {
				newAutos = append(newAutos, f)
			}
		}
		c.ok("e2e_L637", kept == len(oldAutos) && len(newAutos) == 3, "old-passphrase autos are neither counted nor rotated out; 3 new autos added", oldAutos, nowAutos)
		opens := true
		for _, f := range newAutos {
			p, err := openBundleWith(filepath.Join(AUTO, f), e2eNewPass)
			opens = opens && err == nil && p.Files != nil
		}
		c.ok("e2e_L638", opens, "the new autos open with the new passphrase")
	}

	// ======================================================== M2 round 4 ====
	// --- M2-009: never publish (or count) a bundle that cannot be restored
	{
		BK7 := filepath.Join(e.root, "bk7")
		conf7 := e.store(".backup.json")
		os.Rename(e.file(".datakey.cred"), filepath.Join(e.root, "datakey.aside"))
		r = e.run("--backup", BK7)
		c.ok("e2e_L648", r.status == 1 && has(r.stderr, msg.BackupRefused) && len(filterSuffix(names(BK7), ".wsbk")) == 0 && e.store(".backup.json") == conf7,
			"ENC values but no data key: backup refused (exit 1), no bundle, settings unchanged", r)
		os.Rename(filepath.Join(e.root, "datakey.aside"), e.file(".datakey.cred"))
		r = e.run("--backup", BK7)
		c.ok("e2e_L652", r.status == 0 && hasArgs(r.stdout, msg.BackupDone, kBase), "with the key back, the first real backup becomes the base", r)
		// an unrestorable bundle already present (made with the current passphrase, no data key) does not count
		BK8 := filepath.Join(e.root, "bk8")
		os.Mkdir(BK8, 0o700)
		ref := filepath.Join(BK7, withPrefix(names(BK7), "secrets-base-")[0])
		crafted := filepath.Join(BK8, "secrets-base-20000101T000000000.wsbk")
		e.write(crafted, string(sealWith(e2eNewPass, ref, "base", &bundleFile{Created: "x", Files: map[string]string{"redis.ini": e.store("redis.ini")}})))
		p, err := openBundleWith(crafted, e2eNewPass)
		c.ok("e2e_L659", err == nil && p.DataKey == nil, "(crafted: opens with the current passphrase, but has no data key)")
		r = e.run("--backup", BK8)
		c.ok("e2e_L661", r.status == 0 && hasArgs(r.stdout, msg.BackupDone, kBase) && has(r.stderr, msg.BundleDamaged), "an unrestorable base does not count: a restorable base is made", r)
		e.run("--backup", AUTO)
	}

	// --- echo-check.mjs: type the passphrase only after the prompt appears
	// (like a human), then check it was not echoed.
	x := <-e.ttyInteractive(nil, msg.PromptPass, 300*time.Millisecond, e2ePass, "--verify-backup", base)
	c.ok("echo-check", x.status == 0 && strings.Contains(x.signal, "prompt-seen") && has(x.stdout, msg.VerifyOK) && !strings.Contains(x.stdout, e2ePass),
		"passphrase prompt on the terminal, typed after the prompt, verified, not echoed", x)
}

func filterSuffix(l []string, suf string) []string {
	var out []string
	for _, x := range l {
		if strings.HasSuffix(x, suf) {
			out = append(out, x)
		}
	}
	return out
}

func anyContains(l []string, sub string) bool {
	for _, x := range l {
		if strings.Contains(x, sub) {
			return true
		}
	}
	return false
}
