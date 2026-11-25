package test

// M3: --apply-policy, --set, --rotate-datakey, doctor, the passphrase key
// backend, and the prompt line ending. Fake stores only; ids M3.<x>.

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/VanePulse/GSeal/internal/ini"
	"github.com/VanePulse/GSeal/internal/msg"
)

var m3Secrets = []string{"pol-secret-111", "tok-secret-222", "two-key-333", "set-value-444", "set-new-555"}

const m3Fixture = "; @desc policy fixture\n\n[n]\nHOST = pol.invalid\nPSWD = pol-secret-111\nTOKEN = tok-secret-222\n"
const m3Fixture2 = "[x]\nUSER = alice\nKEY = two-key-333\n"

// m3Store: a store with two files imported (default policy @mask) and the
// automatic backup set up in <root>/bk.
func m3Store(t *testing.T, name string) (*e2e, string) {
	e := newE2E(t, name)
	if r := e.run("--init"); r.status != 0 {
		t.Fatal(r)
	}
	e.write(e.imp("pol.ini"), m3Fixture)
	e.write(e.imp("two.ini"), m3Fixture2)
	e.run("--import", "pol")
	e.run("--import", "two")
	bk := filepath.Join(e.root, "bk")
	if r := e.tty(e2ePass+"\n"+e2ePass+"\n", "--backup", bk); r.status != 0 {
		t.Fatal(r)
	}
	return e, bk
}

// sameValues: every fixture value injects exactly.
func (e *e2e) m3Same() bool {
	return e.sh("pol.n", `[ "$POL_N_HOST|$POL_N_PSWD|$POL_N_TOKEN" = 'pol.invalid|pol-secret-111|tok-secret-222' ] && echo same`) == "same\n" &&
		e.sh("two.x", `[ "$TWO_X_USER|$TWO_X_KEY" = 'alice|two-key-333' ] && echo same`) == "same\n"
}

func encCount(s string) int { return strings.Count(s, "ENC:v1:") }

func Test_M3_ApplyPolicy(t *testing.T) {
	e, bk := m3Store(t, "m3-apply")
	c := e.c
	cfg := filepath.Join(e.root, "config.ini")
	e.env = with(e.env, "GSEAL_CONFIG="+cfg)
	bundles := func() int { return len(filterSuffix(names(bk), ".wsbk")) }
	all := func(r res) string { return r.stdout + r.stderr }

	r := e.run("--apply-policy", "--dry-run")
	c.ok("M3.A1", r.status == 0 && strings.Contains(r.stdout, msg.Text(msg.ApplyFile, "pol", 0, 0)) && strings.Contains(r.stdout, msg.Text(msg.ApplyFile, "two", 0, 0)) &&
		strings.Contains(r.stdout, msg.Text(msg.ApplyTotal, 0, 0, 2)), "@mask on a store imported with @mask: dry run shows 0 changes everywhere", r)

	// Widen: every key encrypted.
	write(t, cfg, "[encrypt]\nkeys =\n")
	pol, two, nb := e.store("pol.ini"), e.store("two.ini"), bundles()
	r = e.run("--apply-policy", "--dry-run")
	c.ok("M3.A2", r.status == 0 && strings.Contains(r.stdout, msg.Text(msg.ApplyFile, "pol", 1, 0)) && strings.Contains(r.stdout, msg.Text(msg.ApplyEncrypt, "n", "HOST")) &&
		strings.Contains(r.stdout, msg.Text(msg.ApplyFile, "two", 1, 0)) && has(r.stdout, msg.ApplyDryRun) &&
		e.store("pol.ini") == pol && e.store("two.ini") == two && bundles() == nb && read(e.file(".lock")) == "",
		"dry run lists per file what would be encrypted and changes nothing (no write, no backup)", r)
	r = e.run("--apply-policy")
	c.ok("M3.A3", r.status == 0 && encCount(e.store("pol.ini")) == 3 && encCount(e.store("two.ini")) == 2 && e.m3Same() && bundles() == nb+1 &&
		strings.Contains(r.stdout, msg.Text(msg.ApplyDone, 2, 0, 2)) && len(withPrefix(names(e.file(".backup")), "pre-apply-policy-")) == 1,
		"apply: every value encrypted, values unchanged, previous files kept aside, exactly one backup", r)
	c.ok("M3.A3", strings.Contains(e.store("pol.ini"), "; @desc policy fixture"), "(docs and comments kept)")

	// Narrow back to @mask: no decryption without --allow-decrypt.
	write(t, cfg, "[encrypt]\nkeys = @mask\n")
	pol, nb = e.store("pol.ini"), bundles()
	r = e.run("--apply-policy", "--dry-run")
	c.ok("M3.A4", r.status == 0 && strings.Contains(r.stdout, msg.Text(msg.ApplyFile, "pol", 0, 1)) && strings.Contains(r.stdout, msg.Text(msg.ApplyNoDecrypt, "n", "HOST")), "narrowed policy: dry run lists the values to decrypt", r)
	r = e.run("--apply-policy")
	c.ok("M3.A4", r.status == 0 && e.store("pol.ini") == pol && bundles() == nb && has(r.stdout, msg.ApplyNothing) && hasArgs(r.stdout, msg.ApplySkipped, "2"),
		"narrowed policy without --allow-decrypt: nothing decrypted, nothing written, the values are listed", r)
	r = e.run("--apply-policy", "--allow-decrypt")
	c.ok("M3.A5", r.status == 0 && encCount(e.store("pol.ini")) == 2 && encCount(e.store("two.ini")) == 1 && strings.Contains(e.store("pol.ini"), "HOST = pol.invalid") &&
		e.m3Same() && bundles() == nb+1, "with --allow-decrypt: HOST / USER back to plain text, values unchanged, one backup", r)

	// Failures roll back; a crash rolls forward.
	write(t, cfg, "[encrypt]\nkeys =\n")
	snap := e.snapshot()
	for _, point := range []string{"apply-policy-staging", "swap-in", "swap-out"} {
		r = e.runE([]string{"GSEAL_FAULT=" + point}, "--apply-policy")
		c.ok("M3.A6", r.status == 1 && same(e.snapshot(), snap) && !exists(e.file(".swap-journal.json")) && len(withPrefix(names(e.envDir), ".apply-policy-")) == 0 && e.m3Same(),
			"apply failing at "+point+": exit 1, store unchanged", r)
	}
	e.runE([]string{"GSEAL_CRASH=swap-in"}, "--apply-policy")
	c.ok("M3.A7", exists(e.file(".swap-journal.json")), "(crash in the middle of apply leaves the journal)")
	r = e.run("--export", "pol")
	c.ok("M3.A7", r.status == 0 && hasArgs(r.stderr, msg.RecoverDone, msg.Text(msg.OpApply)) && encCount(e.store("pol.ini")) == 3 && encCount(e.store("two.ini")) == 2 && e.m3Same(),
		"next command completes the interrupted apply (both files)", r)
	os.Remove(e.imp("pol.ini"))
	c.ok("M3.A8", len(leaksOf(all(r), m3Secrets)) == 0, "apply output names keys, never values")
}

func Test_M3_Set(t *testing.T) {
	e, bk := m3Store(t, "m3-set")
	c := e.c
	bundles := func() int { return len(filterSuffix(names(bk), ".wsbk")) }
	nb := bundles()
	r := e.tty("set-value-444\n", "--set", "pol.n", "PSWD")
	c.ok("M3.S1", r.status == 0 && hasArgs(r.stdout, msg.SetDone, "pol", "n", "PSWD", msg.Text(msg.StoredEnc)) &&
		e.sh("pol.n", `[ "$POL_N_PSWD" = set-value-444 ] && echo same`) == "same\n" && !strings.Contains(e.store("pol.ini"), "set-value-444") && bundles() == nb+1,
		"--set reads the value from the terminal, stores it encrypted, backs up once", r)
	r = e.tty("pol2.invalid\n", "--set", "pol.n", "HOST")
	c.ok("M3.S2", r.status == 0 && hasArgs(r.stdout, msg.SetDone, "pol", "n", "HOST", msg.Text(msg.StoredPlain)) && strings.Contains(e.store("pol.ini"), "HOST = pol2.invalid"),
		"a plain key by the policy is stored as plain text", r)
	before := e.store("pol.ini")
	for _, v := range []struct {
		id     msg.ID
		target string
		key    string
	}{{msg.SetNoKey, "pol.n", "NEWKEY"}, {msg.SetNoSection, "pol.other", "PSWD"}, {msg.SetNoFile, "nofile.n", "PSWD"}} {
		r = e.run("--set", v.target, v.key) // no terminal: refused before any prompt
		c.ok("M3.S3", r.status == 1 && has(r.stderr, v.id) && e.store("pol.ini") == before && !exists(e.file("nofile.ini")), "without --create: "+string(v.id)+", nothing asked, nothing written", r)
	}
	r = e.tty("set-new-555\n", "--set", "pol.n", "NEWKEY", "--create")
	r2 := e.tty("set-new-555\n", "--set", "pol.other", "TOKEN", "--create")
	r3 := e.tty("set-new-555\n", "--set", "fresh.n", "PSWD", "--create")
	c.ok("M3.S4", r.status == 0 && r2.status == 0 && r3.status == 0 &&
		e.sh("pol.n", `[ "$POL_N_NEWKEY" = set-new-555 ] && echo same`) == "same\n" &&
		e.sh("pol.other", `[ "$POL_OTHER_TOKEN" = set-new-555 ] && echo same`) == "same\n" &&
		e.sh("fresh.n", `[ "$FRESH_N_PSWD" = set-new-555 ] && echo same`) == "same\n" && strings.Contains(e.store("pol.ini"), "; @desc policy fixture"),
		"--create adds a key, a node, a file", r, r2, r3)
	before = e.store("pol.ini")
	r = e.run("--set", "pol.n", "PSWD")
	c.ok("M3.S5", r.status == 1 && has(r.stderr, msg.PromptNoTTY) && e.store("pol.ini") == before, "no terminal: refused, value never taken from elsewhere", r)
	r = e.tty("\n", "--set", "pol.n", "PSWD")
	c.ok("M3.S6", r.status == 1 && has(r.stdout, msg.SetEmpty) && e.store("pol.ini") == before, "empty value: refused, nothing written", r)
	r = e.tty("set-value-444\n", "--set", "pol.n", "pswd")
	c.ok("M3.S7", r.status == 0 && hasArgs(r.stdout, msg.SetDone, "pol", "n", "PSWD") && strings.Count(e.store("pol.ini"), "PSWD =") == 1, "key matched without regard to case; the stored spelling is kept", r)
	r = e.ttyE([]string{"GSEAL_FAULT=before-commit"}, "set-new-555\n", "--set", "pol.n", "PSWD")
	c.ok("M3.S8", r.status == 1 && e.sh("pol.n", `[ "$POL_N_PSWD" = set-value-444 ] && echo same`) == "same\n", "failure before the commit: exit 1, old value kept", r)
	// Line ends after a prompt: raw mode turns off output processing, so the
	// prompt's line must be ended with CR LF (the next line starts at column 0).
	x := <-e.ttyInteractive(nil, msg.PromptValue, 300*time.Millisecond, "set-new-555", "--set", "pol.n", "PSWD")
	c.ok("M3.S9", x.status == 0 && strings.Contains(x.signal, "prompt-seen") && !strings.Contains(x.stdout, "set-new-555") &&
		e.sh("pol.n", `[ "$POL_N_PSWD" = set-new-555 ] && echo same`) == "same\n", "typed after the prompt: stored, not echoed", x)
	c.ok("M3.T1", strings.Contains(r.raw, msg.Text(msg.PromptValue, "pol", "n", "PSWD")+"\r\n"), "after typing, the next output starts on a new line (CR LF)", r.raw)
}

// unwrapTestKey returns the data key in file, read outside the program.
func (e *e2e) unwrapTestKey(file string) []byte {
	if e.backend == "testfile" {
		var c struct{ Secret string }
		json.Unmarshal([]byte(read(file)), &c)
		b, _ := base64.StdEncoding.DecodeString(c.Secret)
		return b
	}
	out, _ := exec.Command("systemd-creds", "decrypt", "--user", "--name=with-secrets-data", file, "-").Output()
	return out
}

// decryptWith opens a stored ENC:v1: value with key (independent of the program).
func decryptWith(key []byte, fac, sec, k, v string) bool {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(strings.TrimPrefix(v, "ENC:v1:"), "="))
	if err != nil || len(b) < 28 {
		return false
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return false
	}
	g, _ := cipher.NewGCM(blk)
	_, err = g.Open(nil, b[:12], b[12:], []byte("with-secrets\x00"+fac+"\x00"+sec+"\x00"+k))
	return err == nil
}

// encValues returns fac -> every stored ENC value as (sec, key, value).
func (e *e2e) allEnc() [][4]string {
	var out [][4]string
	for _, f := range names(e.envDir) {
		if !strings.HasSuffix(f, ".ini") {
			continue
		}
		fac := strings.TrimSuffix(f, ".ini")
		p := ini.Parse(e.store(f))
		for _, sec := range p.Raw.Names() {
			m, _ := p.Raw.Get(sec)
			for _, k := range m.Keys() {
				if v, _ := m.Get(k); strings.HasPrefix(v, "ENC:v1:") {
					out = append(out, [4]string{fac, sec, k, v})
				}
			}
		}
	}
	return out
}

func Test_M3_RotateDataKey(t *testing.T) {
	e, bk := m3Store(t, "m3-rotate")
	c := e.c
	oldKey := e.unwrapTestKey(e.file(".datakey.cred"))
	snap := e.snapshot()
	for _, point := range []string{"rotate-datakey-staging", "wrap", "swap-in", "swap-out"} {
		r := e.runE([]string{"GSEAL_FAULT=" + point}, "--rotate-datakey")
		c.ok("M3.R1", r.status == 1 && same(e.snapshot(), snap) && !exists(e.file(".swap-journal.json")) && len(withPrefix(names(e.envDir), ".rotate-datakey-")) == 0 && e.m3Same(),
			"rotation failing at "+point+": exit 1, store and data key unchanged, values usable", r)
	}
	nb := len(filterSuffix(names(bk), ".wsbk"))
	r := e.run("--rotate-datakey")
	newKey := e.unwrapTestKey(e.file(".datakey.cred"))
	vals := e.allEnc()
	allNew, noneOld := len(vals) == 3, true
	for _, v := range vals {
		allNew = allNew && decryptWith(newKey, v[0], v[1], v[2], v[3])
		noneOld = noneOld && !decryptWith(oldKey, v[0], v[1], v[2], v[3])
	}
	c.ok("M3.R2", r.status == 0 && hasArgs(r.stdout, msg.RotateDone, "3", "2") && len(newKey) == 32 && string(newKey) != string(oldKey) && allNew && noneOld && e.m3Same(),
		"after --rotate-datakey every ENC value opens with the new key and none with the old key; values unchanged", r)
	latest := newest(bk, "secrets-auto-")
	v := e.tty(e2ePass+"\n", "--verify-backup", latest)
	c.ok("M3.R3", len(filterSuffix(names(bk), ".wsbk")) == nb+1 && v.status == 0 && has(v.stdout, msg.VerifyOK), "one backup afterwards, holding the new key (verifies)", r, v)
	c.ok("M3.R4", len(leaksOf(r.stdout+r.stderr, m3Secrets)) == 0, "rotation output holds no value")
	// A crash in the middle is completed by the next command.
	oldKey = newKey
	e.runE([]string{"GSEAL_CRASH=swap-in"}, "--rotate-datakey")
	c.ok("M3.R5", exists(e.file(".swap-journal.json")), "(crash in the middle of a rotation leaves the journal)")
	r = e.run("--export", "pol")
	newKey = e.unwrapTestKey(e.file(".datakey.cred"))
	ok := true
	for _, v := range e.allEnc() {
		ok = ok && decryptWith(newKey, v[0], v[1], v[2], v[3]) && !decryptWith(oldKey, v[0], v[1], v[2], v[3])
	}
	c.ok("M3.R5", r.status == 0 && hasArgs(r.stderr, msg.RecoverDone, msg.Text(msg.OpRotate)) && string(newKey) != string(oldKey) && ok && e.m3Same(),
		"next command completes the rotation: files and key replaced together", r)
}

func Test_M3_Doctor(t *testing.T) {
	e, _ := m3Store(t, "m3-doctor")
	c := e.c
	lines := func(out string) bool {
		for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
			if !strings.HasPrefix(l, "OK    ") && !strings.HasPrefix(l, "WARN  ") && !strings.HasPrefix(l, "FAIL  ") && !has(l, msg.DocSummary) {
				return false
			}
		}
		return true
	}
	r := e.run("doctor")
	c.ok("M3.D1", r.status == 0 && lines(r.stdout) && strings.Contains(r.stdout, msg.Text(msg.DocValues, 3, 2)) && has(r.stdout, msg.DocLastOK) &&
		strings.Contains(r.stdout, msg.Text(msg.DocPolicyOK)) && !strings.Contains("\n"+r.stdout, "\nFAIL  "), "healthy store: every item OK or WARN, values decrypt, latest backup verifies", r)
	c.ok("M3.D2", len(leaksOf(r.stdout+r.stderr, m3Secrets)) == 0 && !strings.Contains(r.stdout, "ENC:v1:"), "doctor output holds no value")
	snap := e.snapshot()
	// Problems are reported, nothing is changed or completed.
	os.Chmod(e.file("two.ini"), 0o644)
	e.write(e.imp("pol.ini"), "[n]\nPSWD = <hold>\n")
	cfg := filepath.Join(e.root, "config.ini")
	write(t, cfg, "[encrypt]\nkeys =\n")
	r = e.runE([]string{"GSEAL_CONFIG=" + cfg}, "doctor")
	c.ok("M3.D3", r.status == 0 && hasArgs(r.stdout, msg.DocFileModes, "two.ini") && has(r.stdout, msg.DocImports) && strings.Contains(r.stdout, msg.Text(msg.DocPolicyDiff, 2, 0)),
		"WARN for a loose file mode, a pending import file, values the policy would encrypt", r)
	os.Chmod(e.file("two.ini"), 0o600)
	os.Remove(e.imp("pol.ini"))
	pol := e.store("pol.ini")
	if loc := strings.Index(pol, "PSWD = ENC:v1:"); loc >= 0 {
		i := loc + len("PSWD = ENC:v1:")
		ch := byte('A')
		if pol[i] == 'A' {
			ch = 'B'
		}
		e.write(e.file("pol.ini"), pol[:i]+string(ch)+pol[i+1:])
	}
	r = e.run("doctor")
	c.ok("M3.D4", r.status == 1 && hasArgs(r.stdout, msg.DocValuesBad, "pol [n] PSWD") && len(leaksOf(r.stdout, m3Secrets)) == 0, "damaged ciphertext: FAIL naming the key (no value), exit 1", r)
	e.write(e.file("pol.ini"), pol)
	e.runE([]string{"GSEAL_CRASH=swap-in"}, "--rotate-datakey")
	r = e.run("doctor")
	c.ok("M3.D5", r.status == 1 && hasArgs(r.stdout, msg.DocJournal, msg.Text(msg.OpRotate)) && exists(e.file(".swap-journal.json")), "interrupted rotation: FAIL, and doctor does not complete it (read-only)", r)
	e.run("--export", "pol") // completes it
	os.Remove(e.imp("pol.ini"))
	write(t, cfg, "[nope]\n")
	r = e.runE([]string{"GSEAL_CONFIG=" + cfg}, "doctor")
	c.ok("M3.D6", r.status == 1 && has(r.stdout, msg.DocFail) && strings.Contains(r.stdout, msg.Text(msg.CfgSafeLine, cfg, 1, msg.Text(msg.CfgKindUnknownSec, ""))) && !strings.Contains(r.stdout, "nope"), "config error: FAIL, exit 1, section name not echoed", r)
	_ = snap
}

func Test_M3_PassphraseBackend(t *testing.T) {
	if _, err := exec.LookPath("script"); err != nil {
		t.Skip("script(1) not available")
	}
	c := checker{t}
	// A PATH with bash only: systemd-creds cannot be used.
	pbin := filepath.Join(scratch, "m3-pw-path")
	os.MkdirAll(pbin, 0o700)
	bash, _ := exec.LookPath("bash")
	os.Symlink(bash, filepath.Join(pbin, "bash"))
	_, err := exec.LookPath(filepath.Join(pbin, "systemd-creds"))
	c.ok("M3.P0", err != nil, "(no systemd-creds on the PATH used)")
	mk := func(name string) *e2e {
		root := filepath.Join(scratch, name)
		os.RemoveAll(root)
		os.MkdirAll(filepath.Join(root, "env"), 0o700)
		return &e2e{t: t, c: c, root: root, envDir: filepath.Join(root, "env"), exe: bin,
			env: with(baseEnv(t), "GSEAL_STORE="+root, "PATH="+pbin), backend: "passphrase"}
	}
	const sp, sp2, bp = "store passphrase 1", "store passphrase 2", "backup passphrase"
	e := mk("m3-pw")
	r := e.tty(sp+"\n"+sp+"\n", "--init", "--backend", "passphrase")
	c.ok("M3.P1", r.status == 0 && strings.HasPrefix(read(e.file(".datakey.cred")), "GSPW1\n"), "release build, no systemd-creds: --init --backend passphrase", r)
	e.write(e.imp("pol.ini"), m3Fixture)
	r = e.tty(sp+"\n", "--import", "pol")
	c.ok("M3.P2", r.status == 0 && encCount(e.store("pol.ini")) == 2 && has(r.stdout, msg.PromptStorePass), "import asks for the store passphrase and encrypts", r)
	check := `[ "$POL_N_HOST|$POL_N_PSWD|$POL_N_TOKEN" = 'pol.invalid|pol-secret-111|tok-secret-222' ] && echo same`
	r = e.tty(sp+"\n", "pol.n", "--", check)
	c.ok("M3.P3", r.status == 0 && strings.Contains(r.stdout, "same"), "injection with the store passphrase", r)
	r = e.tty("wrong passphrase\n", "pol.n", "--", check)
	c.ok("M3.P3", r.status != 0 && !strings.Contains(r.stdout, "same") && has(r.stdout, msg.StorePassWrong), "wrong store passphrase: refused", r)
	bk := filepath.Join(e.root, "bk")
	r = e.tty(bp+"\n"+bp+"\n"+sp+"\n", "--backup", bk)
	bundle := newest(bk, "secrets-base-")
	c.ok("M3.P4", r.status == 0 && bundle != "" && strings.HasPrefix(read(e.file(".backupkey.cred")), "GSPW1\n"), "backup (backup key wrapped with the store passphrase too)", r)
	e2 := mk("m3-pw-restore")
	r = e2.tty(bp+"\n"+sp2+"\n"+sp2+"\n", "--restore", bundle, "--backend", "passphrase")
	c.ok("M3.P5", r.status == 0 && strings.HasPrefix(read(e2.file(".datakey.cred")), "GSPW1\n"), "restore on another store with a new store passphrase", r)
	r = e2.tty(sp2+"\n", "pol.n", "--", check)
	c.ok("M3.P6", r.status == 0 && strings.Contains(r.stdout, "same"), "restored values inject with the new store passphrase", r)
	r = e2.run("doctor")
	c.ok("M3.P7", r.status == 0 && strings.Contains(r.stdout, msg.Text(msg.DocBackend, "passphrase")) && has(r.stdout, msg.DocDataKeyPw), "doctor on a passphrase store: no prompt, backend reported", r)
}

// Review M3-001: a value is written only if it reads back unchanged; when no
// INI form can hold it, the command refuses before the commit.
func Test_M3_ValueRoundTrip(t *testing.T) {
	e, _ := m3Store(t, "m3-roundtrip")
	c := e.c
	// Values that need quoting but round-trip: stored and injected exactly.
	for i, v := range []string{" lead", "trail ", "a ;b", `"q"`, "x # y", "it's"} {
		r := e.tty(v+"\n", "--set", "pol.n", "HOST")
		got := e.sh("pol.n", `printf '%s' "$POL_N_HOST"`)
		c.ok("M3.V1", r.status == 0 && got == v, "plain --set of a value that needs quoting injects exactly: case "+string(rune('a'+i)), r, got)
	}
	// U+2028 inside a value that needs quotes (trailing space): refused, nothing written.
	ls := "prefix\u2028suffix "
	before := e.store("pol.ini")
	r := e.tty(ls+"\n", "--set", "pol.n", "HOST")
	c.ok("M3.V2", r.status == 1 && has(r.stdout+r.stderr, msg.ImpBothQuotes) && e.store("pol.ini") == before, "plain --set of a value no INI form holds unchanged (U+2028 + trailing space): refused, file unchanged", r)
	r = e.tty("a'b\"c \n", "--set", "pol.n", "HOST")
	c.ok("M3.V2", r.status == 1 && e.store("pol.ini") == before, "plain --set with both quote characters and a trailing space: refused", r)
	// Encrypted, the same value is fine; decrypting it by the policy is refused.
	r = e.tty(ls+"\n", "--set", "pol.n", "PSWD")
	got := e.sh("pol.n", `[ "$POL_N_PSWD" = "$(printf 'prefix\342\200\250suffix ')" ] && echo same`)
	c.ok("M3.V3", r.status == 0 && got == "same\n", "the same value stored encrypted injects exactly", r, got)
	cfg := filepath.Join(e.root, "config.ini")
	write(t, cfg, "[encrypt]\nkeys = TOKEN\n")
	snap := e.snapshot()
	r = e.runE([]string{"GSEAL_CONFIG=" + cfg}, "--apply-policy", "--allow-decrypt")
	c.ok("M3.V4", r.status == 1 && hasArgs(r.stderr, msg.ImpKeyErr, "n", "PSWD") && same(e.snapshot(), snap) && !exists(e.file(".swap-journal.json")),
		"--apply-policy --allow-decrypt of a value that cannot be stored as plain text: refused, store unchanged", r)
	// Values that do round-trip are decrypted exactly.
	e.tty("dec ;val \n", "--set", "pol.n", "PSWD")
	r = e.runE([]string{"GSEAL_CONFIG=" + cfg}, "--apply-policy", "--allow-decrypt")
	got = e.sh("pol.n", `[ "$POL_N_PSWD" = 'dec ;val ' ] && echo same`) // compared in the child: PSWD output is masked
	c.ok("M3.V5", r.status == 0 && got == "same\n" && !strings.Contains(e.store("pol.ini"), "PSWD = ENC:"), "decrypting a value that needs quoting keeps it exactly", r, got)
}

// Review M3-002: facility files that cannot be read are FAIL, and the checks
// that could not cover them are not reported as passed.
func Test_M3_DoctorUnreadable(t *testing.T) {
	e, _ := m3Store(t, "m3-doctor-broken")
	c := e.c
	broken := e.file("broken" + ".ini")
	os.Symlink(filepath.Join(e.root, "missing-target"), broken)
	r := e.run("doctor")
	c.ok("M3.D7", r.status == 1 && hasArgs(r.stdout, msg.DocUnreadable, "broken.ini ("+msg.Text(msg.ReasonMissing)+")") &&
		!strings.Contains(r.stdout, msg.Text(msg.DocModesOK)) && !strings.Contains(r.stdout, msg.Text(msg.DocPolicyOK)) && has(r.stdout, msg.DocPartial) &&
		!has(r.stdout, msg.DocValues) && exists(broken), "broken link: FAIL with the file name and reason, no 'passed' for permissions / values / policy, exit 1, nothing changed", r)
	os.Remove(broken)
	if os.Getuid() != 0 {
		two := e.file("two" + ".ini")
		os.Chmod(two, 0)
		r = e.run("doctor")
		c.ok("M3.D8", r.status == 1 && hasArgs(r.stdout, msg.DocUnreadable, "two.ini ("+msg.Text(msg.ReasonPerm)+")") && len(leaksOf(r.stdout, m3Secrets)) == 0,
			"unreadable file (mode 000): FAIL with reason permission denied, exit 1", r)
		os.Chmod(two, 0o600)
	}
	r = e.run("doctor")
	c.ok("M3.D9", r.status == 0 && has(r.stdout, msg.DocValues), "(fixed again: doctor passes)", r)
}

// Review M3-002 / M3-003: env/ that cannot be listed is an error, never an
// empty store: dry run, apply, rotation, backup and doctor all fail, and
// files and data key stay as they were.
func Test_M3_UnlistableStore(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can list any directory")
	}
	e, bk := m3Store(t, "m3-unlistable")
	c := e.c
	cfg := filepath.Join(e.root, "config.ini")
	write(t, cfg, "[encrypt]\nkeys =\n") // a policy that would change values
	snap := e.snapshot()
	key := read(e.file(".datakey.cred"))
	nb := len(names(bk))
	os.Chmod(e.envDir, 0o300) // files open by name, but env/ cannot be listed
	r1 := e.runE([]string{"GSEAL_CONFIG=" + cfg}, "--apply-policy", "--dry-run")
	r2 := e.runE([]string{"GSEAL_CONFIG=" + cfg}, "--apply-policy")
	r3 := e.run("--rotate-datakey")
	r4 := e.run("--backup")
	r5 := e.run("doctor")
	os.Chmod(e.envDir, 0o700)
	c.ok("M3.E1", r1.status == 1 && has(r1.stderr, msg.ListEnvFailed) && !has(r1.stdout, msg.ApplyTotal), "dry run: listing failure is an error, not '0 changes'", r1)
	c.ok("M3.E2", r2.status == 1 && has(r2.stderr, msg.ListEnvFailed), "apply: refused", r2)
	c.ok("M3.E3", r3.status == 1 && has(r3.stderr, msg.ListEnvFailed) && read(e.file(".datakey.cred")) == key, "rotation: refused before anything is re-keyed; data key unchanged", r3)
	c.ok("M3.E4", r4.status == 1 && len(names(bk)) == nb, "backup: refused, no bundle", r4)
	c.ok("M3.E5", r5.status == 1 && has(r5.stdout, msg.DocListFailed) && has(r5.stdout, msg.DocPartial) && !strings.Contains(r5.stdout, msg.Text(msg.DocModesOK)) &&
		!strings.Contains(r5.stdout, msg.Text(msg.DocPolicyOK)) && !has(r5.stdout, msg.DocValues), "doctor: FAIL, nothing reported as passed", r5)
	c.ok("M3.E6", same(e.snapshot(), snap) && e.m3Same() && !exists(e.file(".swap-journal.json")), "listable again: files and key as before, every value injects")
}

// Review M3-004: doctor reports config errors without any text from the file.
func Test_M3_DoctorConfigSafe(t *testing.T) {
	e, _ := m3Store(t, "m3-doctor-config")
	c := e.c
	cfg := filepath.Join(e.root, "config.ini")
	for i, body := range []string{
		"[redact]\nplain = HOST, MARK-one!\n",
		"[audit]\nenabled = MARK-two\n",
		"just MARK-three here\n",
		"[MARK-four]\n",
		"[store]\nMARK_five = x\n",
		"[backup]\ndir = MARK-six/rel\n",
	} {
		write(t, cfg, body)
		r := e.runE([]string{"GSEAL_CONFIG=" + cfg}, "doctor")
		c.ok("M3.C1", r.status == 1 && has(r.stdout, msg.DocFail) && !strings.Contains(r.stdout+r.stderr, "MARK"), "config error "+string(rune('a'+i))+": FAIL without any text from the file", r)
	}
	write(t, cfg, "[redact]\nplain = HOST, MARK-one!\n")
	r := e.runE([]string{"GSEAL_CONFIG=" + cfg}, "doctor")
	c.ok("M3.C2", strings.Contains(r.stdout, msg.Text(msg.CfgSafeLine, cfg, 2, msg.Text(msg.CfgKindBadValue, "redact.plain"))), "the line and the known field name are given", r)
}

// Review M3-004 (round 3): values checked after loading (the encryption
// spec in the config or in a file, the store version file) are not echoed
// by doctor either.
func Test_M3_DoctorValueFree(t *testing.T) {
	e, _ := m3Store(t, "m3-doctor-valuefree")
	c := e.c
	cfg := filepath.Join(e.root, "config.ini")
	write(t, cfg, "[encrypt]\nkeys = MARK-bad!, HOST\n")
	r := e.runE([]string{"GSEAL_CONFIG=" + cfg}, "doctor")
	c.ok("M3.C3", r.status == 1 && strings.Contains(r.stdout, msg.Text(msg.DocPolicyCfgBad, cfg)) && !strings.Contains(r.stdout+r.stderr, "MARK"),
		"invalid [encrypt] keys: FAIL naming the config field, not its value", r)
	pol := e.store("pol.ini")
	e.write(e.file("pol.ini"), "; @encrypt MARK-file!\n"+pol)
	r = e.run("doctor")
	c.ok("M3.C4", r.status == 1 && strings.Contains(r.stdout, msg.Text(msg.DocPolicyFileBad, "pol", "pol")) && !strings.Contains(r.stdout+r.stderr, "MARK"),
		"invalid file-level @encrypt: FAIL naming the file, not the spec", r)
	e.write(e.file("pol.ini"), pol)
	e.write(e.file(".store-version"), "MARK-ver\n")
	r = e.run("doctor")
	c.ok("M3.C5", r.status == 1 && has(r.stdout, msg.DocVersionBad) && !strings.Contains(r.stdout+r.stderr, "MARK"),
		"invalid store version file: FAIL without its content", r)
	os.Remove(e.file(".store-version"))
	r = e.run("doctor")
	c.ok("M3.C6", r.status == 0, "(fixed again: doctor passes)", r)
}
