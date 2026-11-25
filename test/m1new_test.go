package test

// M1 acceptance beyond the baseline: store resolution (R3), configuration,
// encryption policy, encrypted values always redacted, store format version,
// English-only text, dependencies and a static executable.

import (
	"bytes"
	"crypto/rand"
	"debug/elf"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/VanePulse/GSeal/internal/msg"
	"github.com/VanePulse/GSeal/internal/store"
)

// mkStore creates a minimal fake store with one facility.
func mkStore(t *testing.T, dir, host string) string {
	write(t, filepath.Join(dir, "env", "app.ini"), "; @desc App\n\n[n]\nHOST = "+host+"\nPSWD = p-"+host+"\n")
	return dir
}

// R3 (replaces m1:244): store resolution order, --where, and no guessing.
func TestM1R3StoreResolution(t *testing.T) {
	c := checker{t}
	base := filepath.Join(scratch, "r3")
	os.RemoveAll(base)
	sFlag := mkStore(t, filepath.Join(base, "flag"), "flag.invalid")
	sEnv := mkStore(t, filepath.Join(base, "env1"), "env.invalid")
	sLegacy := mkStore(t, filepath.Join(base, "legacy"), "legacy.invalid")
	sConf := mkStore(t, filepath.Join(base, "conf"), "conf.invalid")
	cfg := filepath.Join(base, "config.ini")
	write(t, cfg, "[store]\npath = "+sConf+"\n")
	env := with(baseEnv(t), "GSEAL_CONFIG="+cfg)
	host := func(e []string, args ...string) string {
		return runEnv(e, "", append(args, "app.n", "--", `printf %s "$APP_N_HOST"`)...).stdout
	}
	all := with(env, "GSEAL_STORE="+sEnv, "WITH_SECRETS_ROOT="+sLegacy)
	c.ok("R3.1a", host(all, "--store", sFlag) == "flag.invalid", "--store wins over everything")
	c.ok("R3.1b", host(all, "--store="+sFlag) == "flag.invalid", "--store=<dir> form")
	c.ok("R3.1c", host(all) == "env.invalid", "GSEAL_STORE next")
	c.ok("R3.1d", host(with(env, "WITH_SECRETS_ROOT="+sLegacy)) == "legacy.invalid", "WITH_SECRETS_ROOT next")
	c.ok("R3.1e", host(env) == "conf.invalid", "config [store] path next")
	fakeHome := filepath.Join(base, "home")
	sDef := mkStore(t, filepath.Join(fakeHome, ".local", "share", "gseal"), "default.invalid")
	xdg := filepath.Join(base, "xdgdata")
	mkStore(t, filepath.Join(xdg, "gseal"), "xdg.invalid")
	noCfg := with(baseEnv(t), "HOME="+fakeHome)
	c.ok("R3.1f", host(noCfg) == "default.invalid", "default ~/.local/share/gseal last")
	c.ok("R3.1g", host(with(noCfg, "XDG_DATA_HOME="+xdg)) == "default.invalid", "XDG_DATA_HOME does not move the default store")

	w := runEnv(env, "", "--where")
	c.ok("R3.2a", w.status == 0 && strings.Contains(w.stdout, sConf) && strings.Contains(w.stdout, "config "+cfg) && msg.Pattern(msg.WhereVersion).MatchString(w.stdout),
		"--where shows the path and its source (config)", w)
	w = runEnv(all, "", "--store", sFlag, "--where")
	c.ok("R3.2b", w.status == 0 && strings.Contains(w.stdout, sFlag) && strings.Contains(w.stdout, "(from --store)"), "--where names --store", w)
	w = runEnv(with(noCfg, "XDG_DATA_HOME="+xdg), "", "--where")
	c.ok("R3.2c", w.status == 0 && strings.Contains(w.stdout, sDef) && strings.Contains(w.stdout, "(from default)") && msg.Pattern(msg.WhereConfigNone).MatchString(w.stdout),
		"--where names the default and the missing config", w)

	// No guessing: a set source that is wrong is an error, never a fallback.
	r := runEnv(with(env, "GSEAL_STORE="+filepath.Join(base, "nope")), "", "app.n", "--", "true")
	c.ok("R3.3a", r.status == 2 && msg.Pattern(msg.StoreMissing).MatchString(r.stderr) && strings.Contains(r.stderr, "GSEAL_STORE"),
		"GSEAL_STORE pointing nowhere: error, no fallback to config", r)
	notStore := filepath.Join(base, "plain-dir")
	os.MkdirAll(notStore, 0o700)
	r = runEnv(env, "", "--store", notStore, "--list")
	c.ok("R3.3b", r.status == 2 && msg.Pattern(msg.StoreNotStore).MatchString(r.stderr), "directory without env/: not a store", r)
	badCfg := filepath.Join(base, "bad.ini")
	write(t, badCfg, "[store]\npath = "+filepath.Join(base, "gone")+"\n")
	r = runEnv(with(baseEnv(t), "GSEAL_CONFIG="+badCfg, "HOME="+fakeHome), "", "--list")
	c.ok("R3.3c", r.status == 2 && msg.Pattern(msg.StoreMissing).MatchString(r.stderr) && strings.Contains(r.stderr, "config "+badCfg),
		"config path missing: error naming the config, default not used", r)
	write(t, badCfg, "[store]\npath = relative/dir\n")
	r = runEnv(with(baseEnv(t), "GSEAL_CONFIG="+badCfg), "", "--list")
	c.ok("R3.3d", r.status == 2 && msg.Pattern(msg.ConfigBadValue).MatchString(r.stderr), "config path must be absolute", r)

	empty := with(baseEnv(t), "HOME="+filepath.Join(base, "empty-home"))
	r = runEnv(empty, "", "--list")
	c.ok("R3.4a", r.status == 2 && msg.Pattern(msg.DefaultMissing).MatchString(r.stderr), "default store missing: error with --init / --store hint", r)
	r = runEnv(empty, "", "app.n", "--", "true")
	c.ok("R3.4b", r.status == 2 && msg.Pattern(msg.DefaultMissing).MatchString(r.stderr), "injection too", r)
	_, err := os.Stat(filepath.Join(base, "empty-home", ".local"))
	c.ok("R3.4c", os.IsNotExist(err), "nothing created on the way")
	r = runEnv(empty, "", "--init")
	c.ok("R3.4d", !msg.Pattern(msg.DefaultMissing).MatchString(r.stderr), "--init is not refused for a missing default store", r)
}

func TestM1Config(t *testing.T) {
	c := checker{t}
	base := filepath.Join(scratch, "cfg")
	os.RemoveAll(base)
	s := mkStore(t, filepath.Join(base, "s"), "h.invalid")
	write(t, filepath.Join(s, "env", "db.ini"), "; @desc DB\n\n[n]\nHOST = db.invalid\nREGION = eu-x1\nPSWD = dbpass-1\n")
	cfg := filepath.Join(base, "config.ini")
	env := with(baseEnv(t), "GSEAL_CONFIG="+cfg, "GSEAL_STORE="+s)
	// Each error line is exactly the message-table text (prefix included).
	bad := []struct {
		id, text, want string
	}{
		{"C.1a", "[stor]\npath = /x\n", msg.Text(msg.ConfigUnknownSec, cfg, 1, "stor")},
		{"C.1b", "[store]\nroot = /x\n", msg.Text(msg.ConfigUnknownKey, cfg, 2, "root", "store")},
		{"C.1c", "[audit]\nenabled = maybe\n", msg.Text(msg.ConfigBadValue, cfg, 2, "audit.enabled", msg.Text(msg.ReasonNotBool))},
		{"C.1d", "[audit]\nenabled = true\nenabled = false\n", msg.Text(msg.ConfigDupKey, cfg, 3, "enabled", "audit")},
		{"C.1e", "path = /x\n", msg.Text(msg.ConfigSyntax, cfg, 1, "path = /x")},
		{"C.1f", "[redact]\nplain = HOST, NOT-A-WORD\n", msg.Text(msg.ConfigBadValue, cfg, 2, "redact.plain", msg.Text(msg.ReasonNotWord, "NOT-A-WORD"))},
		{"C.1g", "[store]\npath =\n", msg.Text(msg.ConfigBadValue, cfg, 2, "store.path", msg.Text(msg.ReasonEmpty))},
		{"C.1h", "[store]\npath = rel/dir\n", msg.Text(msg.ConfigBadValue, cfg, 2, "store.path", msg.Text(msg.ReasonNotAbs))},
		{"C.1i", "[backup]\ndir = rel/dir\n", msg.Text(msg.ConfigBadValue, cfg, 2, "backup.dir", msg.Text(msg.ReasonNotAbs))},
	}
	for _, b := range bad {
		write(t, cfg, b.text)
		r := runEnv(env, "", "db.n", "--", "true")
		c.ok(b.id, r.status == 2 && r.stderr == msg.Prefix+b.want+"\n", "config error text comes from the message table: "+b.want, r)
	}
	// [redact] plain replaces the default whitelist.
	write(t, cfg, "[redact]\nplain = HOST, REGION\n")
	r := runEnv(env, "", "db.n", "--", `printf %s "$DB_N_HOST|$DB_N_REGION|$DB_N_PSWD"`)
	c.ok("C.2a", r.stdout == "db.invalid|eu-x1|***", "[redact] plain: REGION shown, PSWD masked", r)
	write(t, cfg, "; comment\n[redact]\nplain = PORT\n")
	r = runEnv(env, "", "db.n", "--", `printf %s "$DB_N_HOST|$DB_N_REGION"`)
	c.ok("C.2b", r.stdout == "***|***", "[redact] plain without HOST: HOST masked", r)
	// [audit] enabled = false writes no record.
	write(t, cfg, "[audit]\nenabled = false\n")
	os.RemoveAll(filepath.Join(s, "logs"))
	runEnv(env, "", "db.n", "--", "true")
	_, err := os.Stat(filepath.Join(s, "logs", "audit.log"))
	c.ok("C.3", os.IsNotExist(err), "[audit] enabled = false: no audit record")
}

func TestM1Policy(t *testing.T) {
	c := checker{t}
	base := filepath.Join(scratch, "pol")
	os.RemoveAll(base)
	s := filepath.Join(base, "s")
	write(t, filepath.Join(s, "env", "a.ini"), "; @desc A\n\n[DEFAULT]\nPORT = 1\n\n[n]\nHOST = a.invalid\nPSWD = x\nAPI_SECRET = y\nREGION = r\n")
	write(t, filepath.Join(s, "env", "b.ini"), "; @desc B\n; @encrypt all\n\n[n]\nHOST = b.invalid\nPSWD = z\n\n[m]\n; @encrypt HOST\nUSER = u\n")
	write(t, filepath.Join(s, "env", "bad.ini"), "; @encrypt PS-WD\n\n[n]\nK = v\n")
	cfg := filepath.Join(base, "config.ini")
	env := with(baseEnv(t), "GSEAL_CONFIG="+cfg, "GSEAL_STORE="+s)
	row := func(out, key, want string) bool {
		return regexp.MustCompile(`(?m)^  ` + regexp.QuoteMeta(key) + `\s+` + want + `\s`).MatchString(out)
	}
	enc, pl := msg.Text(msg.PolicyWant), msg.Text(msg.PolicyPlain)

	r := runEnv(env, "", "--policy", "a") // no config: @mask
	c.ok("P.1", r.status == 0 && row(r.stdout, "[n] PSWD", enc) && row(r.stdout, "[n] API_SECRET", enc) && row(r.stdout, "[n] REGION", enc) &&
		row(r.stdout, "[n] HOST", pl) && row(r.stdout, "[DEFAULT] PORT", pl), "default @mask: non-whitelisted keys encrypt", r)
	c.ok("P.1b", !strings.Contains(r.stdout, "a.invalid") && !regexp.MustCompile(`(?m)= `).MatchString(r.stdout), "--policy shows no values", r)
	c.ok("P.1c", regexp.MustCompile(`3 value\(s\) would be encrypted, 0`).MatchString(r.stdout), "summary counts", r)

	write(t, cfg, "[encrypt]\nkeys =\n")
	r = runEnv(env, "", "--policy", "a")
	c.ok("P.2", row(r.stdout, "[n] HOST", enc) && row(r.stdout, "[DEFAULT] PORT", enc) && strings.Contains(r.stdout, "encrypt: all keys"), "empty keys = all keys", r)
	write(t, cfg, "[encrypt]\nkeys = PSWD, *_secret\n")
	r = runEnv(env, "", "--policy", "a")
	c.ok("P.3", row(r.stdout, "[n] PSWD", enc) && row(r.stdout, "[n] API_SECRET", enc) && row(r.stdout, "[n] REGION", pl) && row(r.stdout, "[n] HOST", pl),
		"key list with wildcard, case-insensitive", r)
	write(t, cfg, "[encrypt]\nkeys = @mask, HOST\n")
	r = runEnv(env, "", "--policy", "a")
	c.ok("P.4", row(r.stdout, "[n] HOST", enc) && row(r.stdout, "[n] REGION", enc) && row(r.stdout, "[DEFAULT] PORT", pl), "@mask combined with a name", r)

	write(t, cfg, "[encrypt]\nkeys = PSWD\n")
	r = runEnv(env, "", "--policy", "b")
	c.ok("P.5", row(r.stdout, "[n] HOST", enc) && row(r.stdout, "[m] USER", enc) && strings.Contains(r.stdout, msg.Text(msg.PolicySrcFile)),
		"file-level @encrypt overrides the config", r)
	c.ok("P.6", msg.Pattern(msg.PolicySecIgnore).MatchString(r.stdout) && strings.Contains(r.stdout, "[m]"), "@encrypt inside a section is reported as ignored", r)
	r = runEnv(env, "", "--policy", "bad")
	c.ok("P.7", r.status == 2 && r.stderr == msg.Prefix+msg.Text(msg.PolicyBad, "bad", msg.Text(msg.ReasonBadToken, "PS-WD"))+"\n",
		"invalid @encrypt spec: error text from the message table", r)
	write(t, cfg, "[encrypt]\nkeys = A B\n")
	r = runEnv(env, "", "--policy", "a")
	c.ok("P.8", r.status == 2 && r.stderr == msg.Prefix+msg.Text(msg.ConfigBadSpec, cfg, msg.Text(msg.ReasonBadToken, "A B"))+"\n",
		"invalid config spec: error text from the message table", r)
}

// Encrypted values are always redacted, also under a whitelisted key; the
// Node-format store (ENC:v1:, .datakey.cred via systemd-creds) is read as is.
func TestM1EncryptedRedaction(t *testing.T) {
	if !haveSystemdCreds() {
		t.Skip("systemd-creds --user not available (needs systemd >= 256); covered on the Linux acceptance machine")
	}
	c := checker{t}
	s := filepath.Join(scratch, "enc", "s")
	os.RemoveAll(filepath.Dir(s))
	os.MkdirAll(filepath.Join(s, "env"), 0o700)
	key := make([]byte, 32)
	rand.Read(key)
	cm := exec.Command("systemd-creds", "encrypt", "--user", "--name=with-secrets-data", "-", filepath.Join(s, "env", ".datakey.cred"))
	cm.Stdin = bytes.NewReader(key)
	if out, err := cm.CombinedOutput(); err != nil {
		t.Fatalf("systemd-creds: %v %s", err, out)
	}
	eFor := func(fac, sec, k, v string) string {
		x, err := store.Encrypt(key, fac, sec, k, v)
		if err != nil {
			t.Fatal(err)
		}
		return x
	}
	e := func(sec, k, v string) string { return eFor("vault", sec, k, v) }
	write(t, filepath.Join(s, "env", "vault.ini"), "; @desc V enc-host.invalid\n\n[n]\nHOST = "+e("n", "HOST", "enc-host.invalid")+
		"\nPORT = 5432\nPSWD = "+e("n", "PSWD", "encPass-9")+"\n")
	env := with(baseEnv(t), "GSEAL_STORE="+s)
	r := runEnv(env, "", "vault.n", "--", `printf %s "${#VAULT_N_HOST}|$VAULT_N_HOST|$VAULT_N_PORT|$VAULT_N_PSWD|${#VAULT_N_PSWD}"`)
	c.ok("E.1", r.status == 0 && r.stdout == "16|***|5432|***|9", "ENC values decrypt; encrypted HOST is redacted although whitelisted", r)
	// An encrypted value inside a longer whitelisted plain value is still
	// masked (stdout, stderr, written in pieces across pauses); a plain
	// secret inside a plain value keeps the baseline behaviour (shown).
	write(t, filepath.Join(s, "env", "wrap.ini"), "; @desc W see prefix-review-marker.invalid\n\n[n]\nHOST = prefix-review-marker.invalid\n"+
		"TOKEN = "+eFor("wrap", "n", "TOKEN", "review-marker")+"\nURL_HOST = x-plain-sec.invalid\nPLAIN_SEC = plain-sec\n")
	out2 := func(cmd string) [2]string {
		x := runEnv(env, "", "wrap.n", "--", cmd)
		y := runEnv(env, "", "wrap.n", "--", "{ "+cmd+"; } >&2")
		return [2]string{x.stdout, y.stderr}
	}
	for _, k := range []struct{ id, cmd, want, desc string }{
		{"E.5a", `printf "%s|%s" "$WRAP_N_HOST" "$WRAP_N_TOKEN"`, "prefix-***.invalid|***", "encrypted value masked inside a plain value (stdout and stderr)"},
		{"E.5b", `printf prefix-review; sleep 0.3; printf -- -marker.inv; sleep 0.3; printf alid`, "prefix-***.invalid", "same, written in pieces across pauses"},
		{"E.5c", `printf %s "$WRAP_N_URL_HOST"`, "x-plain-sec.invalid", "a plain (unencrypted) secret inside a plain value is still shown (baseline rule)"},
	} {
		p := out2(k.cmd)
		c.ok(k.id, p[0] == k.want && p[1] == k.want, k.desc, p)
	}
	r = runEnv(env, "", "--list", "wrap")
	c.ok("E.5d", r.status == 0 && strings.Contains(r.stdout, "see prefix-***.invalid") && !strings.Contains(r.stdout, "review-marker"),
		"encrypted value masked inside a longer token in @desc", r)

	// Overlapping values in @desc (review M1-005), at all three --list levels:
	// two encrypted values (abc, bcdef), and an encrypted value overlapping a
	// plain secret (xyz encrypted, yzw-q plain); a plain secret that is not a
	// whole token and overlaps nothing keeps the baseline rule.
	write(t, filepath.Join(s, "env", "ovl.ini"), "; @desc Overlap abcdef and xyzw-q and keep-mm-tail\n\n[n]\n; @desc Node abcdef xyzw-q\n"+
		"A = "+eFor("ovl", "n", "A", "abc")+"\nB = "+eFor("ovl", "n", "B", "bcdef")+"\nX = "+eFor("ovl", "n", "X", "xyz")+
		"\nW = yzw-q\nM = mm\n")
	for _, lv := range [][]string{{"--list"}, {"--list", "ovl"}, {"--list", "ovl.n"}} {
		r = runEnv(env, "", lv...)
		out := r.stdout
		c.ok("E.6 "+strings.Join(lv, " "), r.status == 0 && !strings.Contains(out, "def") && !strings.Contains(out, "bcd") &&
			!strings.Contains(out, "zw-q") && !strings.Contains(out, "yz"),
			"overlapping encrypted / plain secrets leave no tail in @desc", out)
	}
	r = runEnv(env, "", "--list", "ovl")
	c.ok("E.6b", strings.Contains(r.stdout, "Overlap *** and *** and keep-mm-tail") && strings.Contains(r.stdout, "Node *** ***"),
		"exact masking; unencrypted mm inside a longer token is not masked (baseline whole-token rule)", r.stdout)
	r = runEnv(env, "", "ovl.n", "--", `printf "abcdef|xyzw-q|keep-mm-tail"`)
	c.ok("E.6c", r.stdout == "***|***|keep-***-tail", "stream: same text fully masked (stream masks every occurrence)", r)

	// Chunking does not change the output (review M1-006): plain secrets abc,
	// bcdef; encrypted Z elsewhere; whitelisted HOST bcdef! contains bcdef.
	write(t, filepath.Join(s, "env", "chunk.ini"), "; @desc C\n\n[n]\nA = abc\nB = bcdef\nHOST = bcdef!\nK = "+eFor("chunk", "n", "K", "Z")+"\n")
	const want = "***def! ***"
	for _, k := range []struct{ id, cmd string }{
		{"E.7a", `printf "abcdef! Z"`},
		{"E.7b", `printf abcdef!; sleep 0.3; printf " Z"`},
		{"E.7c", `printf ab; sleep 0.3; printf cd; sleep 0.3; printf "ef! "; sleep 0.3; printf Z`},
		{"E.7d", `printf "abcdef! "; sleep 0.3; printf Z; sleep 0.3`},
	} {
		x := runEnv(env, "", "chunk.n", "--", k.cmd)
		y := runEnv(env, "", "chunk.n", "--", "{ "+k.cmd+"; } >&2")
		c.ok(k.id, x.stdout == want && y.stderr == want, "same text, different chunks and pauses: same output (stdout, stderr): "+k.cmd, x.stdout, " | ", y.stderr)
	}

	r = runEnv(env, "", "--list", "vault")
	c.ok("E.2", r.status == 0 && strings.Contains(r.stdout, "V ***") && !strings.Contains(r.stdout, "enc-host"), "encrypted HOST masked in @desc", r)
	// A damaged ciphertext: injection fails, docs are hidden.
	write(t, filepath.Join(s, "env", "vault.ini"), "; @desc V doc\n\n[n]\nPSWD = "+e("n", "OTHER", "x")+"\n")
	r = runEnv(env, "", "vault.n", "--", "true")
	c.ok("E.3", r.status == 2 && msg.Pattern(msg.DecryptFailed).MatchString(r.stderr), "ciphertext moved to another key fails (AAD)", r)
	r = runEnv(env, "", "--list", "vault")
	c.ok("E.4", r.status == 0 && strings.Contains(r.stdout, msg.Text(msg.ListHidden)) && !strings.Contains(r.stdout, "V doc"), "undecryptable store: docs hidden with notice", r)
}

func TestM1StoreVersion(t *testing.T) {
	c := checker{t}
	s := mkStore(t, filepath.Join(scratch, "ver", "s"), "v.invalid")
	env := with(baseEnv(t), "GSEAL_STORE="+s)
	r := runEnv(env, "", "--where")
	c.ok("V.1", strings.Contains(r.stdout, msg.Text(msg.WhereVersion, 1)), "no version file: version 1", r)
	write(t, filepath.Join(s, "env", ".store-version"), "2\n")
	r = runEnv(env, "", "--where")
	c.ok("V.2", strings.Contains(r.stdout, msg.Text(msg.WhereVersionNew, 2, store.Version)), "--where flags a newer format", r)
	for _, cmd := range []string{"--import", "--backup", "--init", "--restore"} {
		r = runEnv(env, "", cmd, "app")
		c.ok("V.3"+cmd, r.status == 1 && msg.Pattern(msg.StoreVersionNew).MatchString(r.stderr), cmd+" refused on a newer store format", r)
	}
	r = runEnv(env, "", "app.n", "--", `printf %s "$APP_N_HOST"`)
	c.ok("V.4", r.stdout == "v.invalid", "reading still works", r)
}

// All user-visible text is English and lives in internal/msg.
func TestM1EnglishOnly(t *testing.T) {
	c := checker{t}
	cjk := regexp.MustCompile(`[\p{Han}\p{Hiragana}\p{Katakana}\p{Hangul}\x{3000}-\x{303F}\x{FF00}-\x{FFEF}]`)
	// Strings handed to the user outside the message table.
	inline := regexp.MustCompile(`Fprint(f|ln)?\(a\.std(out|err), "[A-Za-z]|Errorf\("|errors\.New\("[A-Z]`)
	var bad []string
	filepath.WalkDir("..", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "testdata" || d.Name() == "vendor" || d.Name() == "test" || d.Name() == "tools") {
			return filepath.SkipDir
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		b, _ := os.ReadFile(p)
		if cjk.Match(b) {
			bad = append(bad, p+": CJK text")
		}
		if !strings.Contains(p, "internal/msg") && inline.Match(b) {
			bad = append(bad, p+": inline user text")
		}
		return nil
	})
	c.ok("L.1", len(bad) == 0, "sources contain no CJK and no inline user-facing strings", bad)
	for _, id := range msg.IDs() {
		if cjk.MatchString(msg.Text(id)) {
			c.ok("L.2", false, "message is English: "+string(id))
		}
	}
}

func TestM1DepsAndStatic(t *testing.T) {
	c := checker{t}
	out, err := exec.Command("go", "list", "-deps", "-f", "{{if not .Standard}}{{.ImportPath}}{{end}}", "../...").Output()
	if err != nil {
		t.Fatal(err)
	}
	allowed := regexp.MustCompile(`^(github\.com/VanePulse/GSeal(/.*)?|golang\.org/x/(crypto|term|sys)(/.*)?)$`)
	var extra []string
	for _, l := range strings.Fields(string(out)) {
		if !allowed.MatchString(l) {
			extra = append(extra, l)
		}
	}
	c.ok("D.1", len(extra) == 0, "dependencies: only the standard library and golang.org/x/{crypto,term,sys}", extra)
	mod, _ := os.ReadFile("../go.mod")
	req := regexp.MustCompile(`(?m)^\s*(require\s+)?([a-z0-9.\-]+\.[a-z]+/\S+)\s+v`).FindAllSubmatch(mod, -1)
	for _, m := range req {
		p := string(m[2])
		_, err := os.Stat(filepath.Join("..", "vendor", p))
		c.ok("D.2", err == nil, "module vendored: "+p)
	}
	if runtime.GOOS == "linux" {
		f, err := elf.Open(bin)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		interp := false
		for _, p := range f.Progs {
			interp = interp || p.Type == elf.PT_INTERP
		}
		libs, _ := f.ImportedLibraries()
		c.ok("D.3", !interp && len(libs) == 0, "static executable (no interpreter, no shared libraries)", libs)
	}
}
