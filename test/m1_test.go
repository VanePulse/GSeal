package test

// Port of VaneSecret ca87d68 test/m1.mjs: prefixed injection, redaction
// whitelist, audit log, @desc doc blocks, three-level --list. The shim cases
// (m1:235–244) are replaced by R1/R3 (store resolution, symlinked entry).

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

type m1Fixture struct {
	root, storeDir, auditFile string
	env                       []string
}

var m1Secrets = []string{"gPass-7788", "dbname-secret", "ops@example.invalid", "alpha"}

func leaks(out string, secrets []string) []string {
	var l []string
	for _, s := range secrets {
		if strings.Contains(out, s) {
			l = append(l, s)
		}
	}
	return l
}

func newM1(t *testing.T) *m1Fixture {
	root := filepath.Join(scratch, "m1", "ws", "secrets")
	os.RemoveAll(filepath.Join(scratch, "m1"))
	f := &m1Fixture{root: root, storeDir: filepath.Join(root, "env"), auditFile: filepath.Join(root, "logs", "audit.log")}
	f.env = with(baseEnv(t), "WITH_SECRETS_ROOT="+root)
	w := func(name, content string) { write(t, filepath.Join(f.storeDir, name), content) }
	w("deploy.ini", strings.Join([]string{
		"; @desc Deploy 代码托管",
		";",
		"; 第二段说明",
		"; 键：",
		";   HOST      服务器地址",
		";   PSWD      登录密码",
		";   SRC_HOST  源库地址",
		"; @remark v2 升级备注-不应显示",
		"; 普通代码注释-不应显示",
		"",
		"[DEFAULT]",
		"PORT = 443",
		"",
		"[prod]",
		"; @desc 生产节点 token alpha 与 mx-alpha",
		"; PSWD = oldPass-commented",
		"HOST = git.example.invalid",
		"USER = robot",
		"SRC_HOST = src.example.invalid",
		"PSWD = gPass-7788",
		"DBNAME = dbname-secret",
		"MAIL_TO = ops@example.invalid",
		"TOKEN = alpha",
		"",
		"[uat]",
		"; @desc UAT 节点",
		"HOST = uat.example.invalid",
		"PSWD = uPass-1122",
		"",
	}, "\n"))
	w("redis.ini", "; @desc Redis 缓存\n\n[dev]\nHOST = r.example.invalid\nPSWD = rPass-3344\n")
	w("short.ini", "; @desc 短值\n\n[n]\nHOST = h.example.invalid\nT1 = Q\nT2 = Zx\nT3 = K9w\n")
	w("with.ini", "; @desc 保留前缀\n\n[secrets]\nSHELL = zsh\n")
	w("gseal.ini", "; @desc 保留前缀 2\n\n[x]\nA = 1\n")
	w("case.ini", "; @desc 大小写\n\n[n]\nhost = lower.example.invalid\nPswd = mixPw-5566\n")
	w("clash.ini", "; @desc 冲突\n\n[n]\ntoken = a1x-token\nTOKEN = b2y-token\n")
	w("stream.ini", "; @desc 流式\n\n[n]\nA = abc\nB = cdef\nHOST = sample.test\nPSWD = sample\n")
	w("eq.ini", "; @desc 相等\n\n[n]\nUSER = same-val\nPSWD = same-val\n")
	w("deflt.ini", strings.Join([]string{
		"; @desc 默认值 sample-default 覆盖", "", "[DEFAULT]", "TOKEN = sample-default", "",
		"[node]", "; @desc 节点 sample-default 说明", "TOKEN = node-token-1", "",
	}, "\n"))
	return f
}

func (f *m1Fixture) run(args ...string) result { return runEnv(f.env, "", args...) }

func (f *m1Fixture) lastAudit(t *testing.T) map[string]any {
	t.Helper()
	b, _ := os.ReadFile(f.auditFile)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	var m map[string]any
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &m); err != nil {
		t.Fatalf("audit line: %v", err)
	}
	return m
}

func (f *m1Fixture) auditLines() int {
	b, _ := os.ReadFile(f.auditFile)
	s := strings.TrimSpace(string(b))
	if s == "" {
		return 0
	}
	return len(strings.Split(s, "\n"))
}

func mode(path string) os.FileMode {
	st, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return st.Mode().Perm()
}

func lines(s string) []string { return strings.Split(s, "\n") }

func hasLine(s, want string) bool {
	for _, l := range lines(s) {
		if l == want {
			return true
		}
	}
	return false
}

func anyPrefix(s string, prefixes ...string) bool {
	for _, l := range lines(s) {
		for _, p := range prefixes {
			if strings.HasPrefix(l, p) {
				return true
			}
		}
	}
	return false
}

func TestM1Injection(t *testing.T) {
	f := newM1(t)
	c := checker{t}

	r := f.run("deploy.prod", "--", "compgen -e")
	names := r.stdout
	c.ok("m1_L090", r.status == 0 && hasLine(names, "DEPLOY_PROD_HOST") && hasLine(names, "DEPLOY_PROD_PSWD") &&
		hasLine(names, "DEPLOY_PROD_PORT") && hasLine(names, "DEPLOY_PROD_SRC_HOST"), "injects prefixed names, incl. [DEFAULT] keys", r)
	bare := false
	for _, n := range []string{"HOST", "PSWD", "PORT", "DBNAME", "TOKEN"} {
		bare = bare || hasLine(names, n)
	}
	c.ok("m1_L092", !bare, "no bare key names injected")
	c.ok("m1_L093", !anyPrefix(names, "WITH_SECRETS_", "GSEAL_"), "WITH_SECRETS_* (and GSEAL_*) not passed to child")

	r = runEnv(with(f.env, "WITH_SECRETS_EXAMPLE=x", "WITH_SECRETS_SHELL=bash", "WITH_SECRETS_BASH=/bin/bash", "GSEAL_EXAMPLE=y"), "",
		"deploy.prod", "--", "compgen -e")
	c.ok("m1_L097", r.status == 0 && !anyPrefix(r.stdout, "WITH_SECRETS_", "GSEAL_") && strings.Contains(r.stdout, "DEPLOY_PROD_HOST"),
		"extra WITH_SECRETS_* / GSEAL_* from the parent are filtered from the child env", r)

	r = f.run("with.secrets", "--", "true")
	c.ok("m1_L100", r.status != 0 && regexp.MustCompile(`reserved WITH_SECRETS_ prefix`).MatchString(r.stderr),
		"injection may not produce WITH_SECRETS_* names", r)
	r = f.run("gseal.x", "--", "true")
	c.ok("m1_L100b", r.status != 0 && strings.Contains(r.stderr, "reserved GSEAL_ prefix"), "injection may not produce GSEAL_* names", r)

	r = f.run("deploy.prod", "redis.dev", "--", `printf %s "${#DEPLOY_PROD_PSWD}:${#REDIS_DEV_PSWD}"`)
	c.ok("m1_L102", r.stdout == "10:10", "several logical names combine without clashing", r)

	r = f.run("case.n", "--", `printf "%s|%s|%s" "$CASE_N_HOST" "${#CASE_N_PSWD}" "${CASE_N_host-unset}"`)
	c.ok("m1_L105", r.status == 0 && r.stdout == "lower.example.invalid|10|unset", "lower / mixed case keys inject as upper-case names only", r)
	l := f.run("--list", "case.n").stdout
	c.ok("m1_L106", strings.Contains(l, "CASE_N_HOST") && strings.Contains(l, "CASE_N_PSWD") &&
		!regexp.MustCompile(`CASE_N_host|CASE_N_Pswd`).MatchString(l), "--list shows the same upper-case names", l)
	r = f.run("clash.n", "--", "true")
	c.ok("m1_L109", r.status != 0 && strings.Contains(r.stderr, "keys token and TOKEN both map to CLASH_N_TOKEN"),
		"keys colliding after upper-casing are an error", r)

	// --- redaction whitelist
	show := func(expr string) string { return f.run("deploy.prod", "--", `printf '%s' "`+expr+`"`).stdout }
	got := show("$DEPLOY_PROD_HOST|$DEPLOY_PROD_PORT|$DEPLOY_PROD_USER|$DEPLOY_PROD_SRC_HOST")
	c.ok("m1_L113", got == "git.example.invalid|443|robot|src.example.invalid", "whitelisted keys (incl. prefixed *_HOST) shown as-is", got)
	got = show("$DEPLOY_PROD_PSWD|$DEPLOY_PROD_DBNAME|$DEPLOY_PROD_MAIL_TO")
	c.ok("m1_L115", got == "***|***|***", "PSWD, DBNAME, MAIL_TO redacted", got)
	r = f.run("deploy.prod", "--", `printf "%s" "$DEPLOY_PROD_PSWD" >&2`)
	c.ok("m1_L117", r.stderr == "***", "stderr redacted too", r)
	c.ok("m1_L118", len(leaks(show("$DEPLOY_PROD_PSWD$DEPLOY_PROD_TOKEN"), m1Secrets)) == 0, "adjacent secrets do not leak")

	// --- short secrets
	r = f.run("short.n", "--", `printf "%s|%s|%s|%s" "$SHORT_N_T1" "$SHORT_N_T2" "$SHORT_N_T3" "$SHORT_N_HOST"`)
	c.ok("m1_L123", r.status == 0 && r.stdout == "***|***|***|h.example.invalid", "short secrets masked on stdout; whitelisted HOST shown", r)
	r = f.run("short.n", "--", `printf "%s %s %s" "$SHORT_N_T1" "$SHORT_N_T2" "$SHORT_N_T3" >&2`)
	c.ok("m1_L125", r.stderr == "*** *** ***", "short secrets masked on stderr", r)
	f.run("short.n", "--", "echo Q Zx K9w >/dev/null")
	rec := f.lastAudit(t)
	cmd, _ := rec["cmd"].(string)
	c.ok("m1_L128", !strings.Contains(cmd, "Q") && !strings.Contains(cmd, "Zx") && !strings.Contains(cmd, "K9w") &&
		strings.Contains(cmd, "echo *** *** ***"), "short secrets masked in the audit command", cmd)
}

func TestM1Streaming(t *testing.T) {
	f := newM1(t)
	c := checker{t}
	both := func(cmd string) [2]string {
		x := f.run("stream.n", "--", cmd)
		y := f.run("stream.n", "--", "{ "+cmd+"; } >&2")
		return [2]string{x.stdout, y.stderr}
	}
	same := func(p [2]string, want string) bool { return p[0] == want && p[1] == want }
	cases := []struct{ id, cmd, want, desc string }{
		{"m1_L133", `printf %s "$STREAM_N_A"; sleep 0.25`, "***", "secret followed by an idle pause is masked (stdout, stderr)"},
		{"m1_L134", `printf ab; sleep 0.25; printf c; sleep 0.25`, "***", "secret written in two slow pieces is masked"},
		{"m1_L135", `printf abcdef`, "***", "overlapping secrets (abc, cdef) are masked as a whole"},
		{"m1_L136", `printf "x abcdef y"`, "x *** y", "overlap inside other text"},
		{"m1_L137", `printf %s "$STREAM_N_HOST"`, "sample.test", "whitelisted value containing a secret fragment is shown as-is"},
		{"m1_L138", `printf "%s %s" "$STREAM_N_HOST" "$STREAM_N_PSWD"`, "sample.test ***", "the secret itself is still masked next to it"},
		{"m1_L139", `printf %s "$STREAM_N_HOST"; sleep 0.25; printf " %s" "$STREAM_N_PSWD"`, "sample.test ***", "same with a pause in between"},
		{"m1_L143", `printf abc; sleep 0.3; printf def`, "***", "overlap written in two pieces across a pause: one ***, no tail left"},
		{"m1_L144", `printf "x abc"; sleep 0.3; printf "def y"`, "x *** y", "same, inside other text"},
		{"m1_L145", `printf sample; sleep 0.3; printf .test`, "sample.test", "whitelisted value written in two pieces across a pause is shown as-is"},
		{"m1_L146", `printf sample; sleep 0.3; printf " x"`, "*** x", "secret that turns out not to be part of the whitelisted value is masked"},
		{"m1_L147", `printf sample.te; sleep 0.3; printf st; sleep 0.3; printf " sample"`, "sample.test ***", "whitelisted value in three pieces, then the secret"},
	}
	for _, k := range cases {
		p := both(k.cmd)
		c.ok(k.id, same(p, k.want), k.desc, p)
	}
	r := f.run("eq.n", "--", `printf "%s|%s" "$EQ_N_USER" "$EQ_N_PSWD"`)
	c.ok("m1_L141", r.stdout == "***|***", "whitelisted value equal to a secret: the secret wins (masked)", r)
	r = f.run("eq.n", "--", `printf same; sleep 0.3; printf %s -val; sleep 0.3`)
	c.ok("m1_L149", r.stdout == "***", "equal whitelisted/secret value written in pieces: masked", r)

	t0 := time.Now()
	cm := exec.Command(bin, "stream.n", "--", `yes "x abc sample.test sample Q cdef y" | head -c 8000000`)
	cm.Env = f.env
	out, err := cm.Output()
	el := time.Since(t0)
	s := string(out)
	c.ok("m1_L156", err == nil && !regexp.MustCompile(`abc|cdef| sample `).MatchString(s) && strings.Contains(s, "sample.test") && el < 30*time.Second,
		"8 MB of dense output redacted in "+el.String()+" (limit 30 s)")
}

func TestM1Audit(t *testing.T) {
	f := newM1(t)
	c := checker{t}
	r := f.run("deploy.prod", "--", "echo gPass-7788 >/dev/null; exit 3")
	c.ok("m1_L162", r.status == 3, "child exit code propagated", r)
	last := f.lastAudit(t)
	names, _ := json.Marshal(last["names"])
	cmd, _ := last["cmd"].(string)
	c.ok("m1_L164", string(names) == `["deploy.prod"]` && last["exit"] == float64(3) && strings.Contains(cmd, "exit 3") && last["ts"] != "",
		"audit records logical names, command, exit code, time", last)
	b, _ := os.ReadFile(f.auditFile)
	c.ok("m1_L166", len(leaks(string(b), m1Secrets)) == 0 && strings.Contains(cmd, "***"), "audit log holds no secret values (masked in command)")
	c.ok("m1_L167", mode(f.auditFile) == 0o600, "audit log is mode 600")

	n0 := f.auditLines()
	r = f.run("deploy.nope", "--", "echo gPass-7788")
	a := f.lastAudit(t)
	nm, _ := json.Marshal(a["names"])
	c.ok("m1_L174", r.status == 2 && f.auditLines() == n0+1 && string(nm) == "[]" && a["unknownNames"] == float64(1) && a["exit"] == float64(2) &&
		a["error"] == "unknown-name" && a["cmd"] == nil && a["cmdChars"] == float64(len("echo gPass-7788")),
		"unknown logical name: failure audited (exit 2, category, no name or command text)", a)
	n0 = f.auditLines()
	r = f.run("deploy.prod", "--")
	a = f.lastAudit(t)
	nm, _ = json.Marshal(a["names"])
	c.ok("m1_L179", r.status == 2 && f.auditLines() == n0+1 && a["exit"] == float64(2) && a["error"] == "usage" && string(nm) == `["deploy.prod"]`,
		"usage error: failure audited, existing name kept", a)
	f.run("clash.n", "--", "true")
	a = f.lastAudit(t)
	c.ok("m1_L181", a["exit"] == float64(2) && a["error"] == "name-collision", "name collision: failure audited", a)
	for _, bogus := range []string{"gPass-7788", "gPass-7788.x", "x.gPass-7788"} {
		n0 = f.auditLines()
		r = f.run(bogus, "--", "true")
		a = f.lastAudit(t)
		raw, _ := json.Marshal(a)
		c.ok("m1_L187", r.status == 2 && f.auditLines() == n0+1 && a["unknownNames"] == float64(1) && !strings.Contains(string(raw), "gPass-7788"),
			"secret given as logical name ("+strings.ReplaceAll(bogus, "gPass-7788", "<secret>")+"): audited without it", a)
	}
	n0 = f.auditLines()
	r = f.run("bad!.n", "--", "true")
	a = f.lastAudit(t)
	c.ok("m1_L194", r.status == 2 && f.auditLines() == n0+1 && a["exit"] == float64(2) && a["unknownNames"] == float64(1) && a["cmd"] == nil,
		"invalid facility name: failure audited with exit code", a)
	b, _ = os.ReadFile(f.auditFile)
	c.ok("m1_L195", len(leaks(string(b), m1Secrets)) == 0, "failure records hold no secret values")
	os.Chmod(f.auditFile, 0o644)
	n0 = f.auditLines()
	r = f.run("deploy.prod", "--", "true")
	c.ok("m1_L200", r.status == 0 && f.auditLines() == n0+1 && mode(f.auditFile) == 0o600, "existing 0644 log: appended and reset to 600")
	os.Remove(f.auditFile)
	f.run("deploy.prod", "--", "true")
	c.ok("m1_L203", f.auditLines() == 1 && mode(f.auditFile) == 0o600, "new log: created as 600")
}

func TestM1List(t *testing.T) {
	f := newM1(t)
	c := checker{t}
	r := f.run("--list")
	c.ok("m1_L207", r.status == 0 && regexp.MustCompile(`(?m)^deploy\s+Deploy 代码托管$`).MatchString(r.stdout) &&
		regexp.MustCompile(`(?m)^redis\s+Redis 缓存$`).MatchString(r.stdout), "--list: one line per file with first @desc line", r)
	c.ok("m1_L209", !regexp.MustCompile(`prod|uat|DEPLOY_`).MatchString(r.stdout), "--list: no nodes or variables at top level")
	r = f.run("--list", "deploy")
	L2 := r.stdout
	c.ok("m1_L212", r.status == 0 && regexp.MustCompile(`(?m)^  Deploy 代码托管\n\n  第二段说明$`).MatchString(L2), "--list file: doc block, lone ; is a blank line", L2)
	c.ok("m1_L213", regexp.MustCompile(`deploy\.prod\s+生产节点`).MatchString(L2) && regexp.MustCompile(`deploy\.uat\s+UAT 节点`).MatchString(L2),
		"--list file: nodes with first desc line")
	c.ok("m1_L214", !regexp.MustCompile(`升级备注|普通代码注释|oldPass|DEPLOY_PROD_`).MatchString(L2),
		"--list file: @remark, code comments, commented assignments, variables hidden")
	r = f.run("--list", "deploy.prod")
	L3 := r.stdout
	c.ok("m1_L217", r.status == 0 && regexp.MustCompile(`DEPLOY_PROD_PSWD\s+登录密码`).MatchString(L3) &&
		regexp.MustCompile(`DEPLOY_PROD_SRC_HOST\s+源库地址`).MatchString(L3), "--list node: prefixed variables with key meanings", L3)
	c.ok("m1_L219", strings.Contains(L3, "token *** 与 mx-alpha"), "--list node: secret in @desc masked as whole token only", L3)
	c.ok("m1_L221", len(leaks(strings.ReplaceAll(L2+L3, "mx-alpha", ""), m1Secrets)) == 0 && !strings.Contains(L3, "oldPass"),
		"--list output leaks no values")
	r = f.run("--list", "deploy.nope")
	c.ok("m1_L223", r.status != 0 && strings.Contains(r.stderr, "deploy.prod"), "unknown node: error lists available nodes", r)
	r = f.run("--list", "deflt")
	c.ok("m1_L226", r.status == 0 && strings.Contains(r.stdout, "默认值 *** 覆盖") && regexp.MustCompile(`deflt\.node\s+节点 \*\*\* 说明`).MatchString(r.stdout) &&
		!strings.Contains(r.stdout, "sample-default"), "--list file: overridden [DEFAULT] secret masked in file and node docs", r)
	r = f.run("--list", "deflt.node")
	c.ok("m1_L229", r.status == 0 && strings.Contains(r.stdout, "节点 *** 说明") && !strings.Contains(r.stdout, "sample-default"),
		"--list node: overridden [DEFAULT] secret masked", r)
	c.ok("m1_L230", !strings.Contains(f.run("--list").stdout, "sample-default"), "--list top level: overridden [DEFAULT] secret masked")
}

// R1 (replaces m1:235, m1:239): the executable is called directly and through
// two levels of symlinks; the launcher's variables never reach the child.
func TestM1R1Entry(t *testing.T) {
	f := newM1(t)
	c := checker{t}
	r := runEnv(f.env, "", "--list")
	c.ok("R1.1", r.status == 0 && regexp.MustCompile(`(?m)^deploy`).MatchString(r.stdout), "direct call finds the store", r)
	dir := filepath.Join(scratch, "m1", "links")
	os.MkdirAll(filepath.Join(dir, "prefix", "bin"), 0o700)
	os.MkdirAll(filepath.Join(dir, "home", ".local", "bin"), 0o700)
	l1 := filepath.Join(dir, "prefix", "bin", "with-secrets")
	l2 := filepath.Join(dir, "home", ".local", "bin", "with-secrets")
	os.Symlink(bin, l1)
	os.Symlink(l1, l2)
	cm := exec.Command(l2, "deploy.prod", "--", `printf %s "${WITH_SECRETS_ROOT-unset}:${GSEAL_STORE-unset}:${GSEAL_CONFIG-unset}:$DEPLOY_PROD_HOST"`)
	cm.Env = with(f.env, "GSEAL_STORE="+f.root)
	out, err := cm.Output()
	c.ok("R1.2", err == nil && string(out) == "unset:unset:unset:git.example.invalid", "two-level symlink works; WITH_SECRETS_ROOT / GSEAL_* not leaked", string(out))
}
