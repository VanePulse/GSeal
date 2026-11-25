package test

// Backup and store interop with VaneSecret (Node, ca87d68), matrix v2 §5.
//
//   - Node -> Go: golden bundles in testdata/interop (written by VaneSecret,
//     see tools/geninterop) are verified and restored by GSeal, with the
//     passphrase typed precomposed and decomposed; a passphrase whose NFC
//     differs must fail. Runs everywhere (any key backend).
//   - Go -> Node: bundles written by GSeal are verified and restored by
//     VaneSecret, and a store written by VaneSecret is used, exported and
//     re-imported by GSeal byte for byte. Needs GSEAL_INTEROP_NODE_SRC (the
//     ca87d68 src directory), node and systemd-creds --user; required on the
//     reviewer's Linux machine.

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/VanePulse/GSeal/internal/msg"
)

const (
	interopASCII = "interop test passphrase"
	interopPre   = "café passphrase été"
	interopDec   = "cafe\u0301 passphrase e\u0301te\u0301"
	interopWrong = "cafe passphrase ete"
)

const interopFixture = `; @desc Interop fixture: fake values only
;
; Keys:
;   HOST  server
;   PSWD  password

[n1]
; @desc Node 1 (说明)
HOST = interop.invalid
PORT = 6379
PSWD = interop-secret-1234
TOKEN = "tok ;with comment char"

[n2]
USER = alice
PSWD = 密码-ünïcode-5678
`

// interopValues is a bash check that prints "same" when every fixture value
// is injected exactly.
const interopValues = `[ "$INTEROP_N1_HOST|$INTEROP_N1_PORT|$INTEROP_N1_PSWD|$INTEROP_N1_TOKEN" = 'interop.invalid|6379|interop-secret-1234|tok ;with comment char' ] && echo same`
const interopValues2 = `[ "$INTEROP_N2_USER|$INTEROP_N2_PSWD" = 'alice|密码-ünïcode-5678' ] && echo same`

func (e *e2e) interopSame() bool {
	return e.sh("interop.n1", interopValues) == "same\n" && e.sh("interop.n2", interopValues2) == "same\n"
}

func Test_Interop_NodeToGo(t *testing.T) {
	if _, err := exec.LookPath("script"); err != nil {
		t.Skip("script(1) not available")
	}
	c := checker{t}
	golden := func(f string) string {
		p, _ := filepath.Abs(filepath.Join("..", "testdata", "interop", f))
		return p
	}
	for _, v := range []struct {
		id, file, typed string
	}{
		{"I.1a", "node-ascii.wsbk", interopASCII},
		{"I.1b", "node-precomposed.wsbk", interopPre},
		{"I.1c", "node-precomposed.wsbk", interopDec},
		{"I.1d", "node-decomposed.wsbk", interopPre},
		{"I.1e", "node-decomposed.wsbk", interopDec},
	} {
		e := newE2E(t, "interop-n2g-"+v.id)
		r := e.tty(v.typed+"\n", "--verify-backup", golden(v.file))
		c.ok(v.id, r.status == 0 && has(r.stdout, msg.VerifyOK) && hasArgs(r.stdout, msg.VerifyCounts, "1", "2", "3"),
			"Go verifies Node bundle "+v.file+" (passphrase typed "+form(v.typed)+")", r)
		r = e.tty(v.typed+"\n", "--restore", golden(v.file))
		c.ok(v.id, r.status == 0 && hasArgs(r.stdout, msg.RestoreDone, "1", "2") && e.interopSame(),
			"Go restores Node bundle "+v.file+" (passphrase typed "+form(v.typed)+"); every value injects exactly", r)
	}
	for _, f := range []string{"node-precomposed.wsbk", "node-decomposed.wsbk"} {
		e := newE2E(t, "interop-n2g-wrong")
		r := e.tty(interopWrong+"\n", "--verify-backup", golden(f))
		c.ok("I.3", r.status == 1 && has(r.stdout, msg.BundleOpenFailed), "a passphrase whose NFC differs (e for é) does not open "+f, r)
	}
}

func form(s string) string {
	switch {
	case strings.Contains(s, "\u0301"):
		return "decomposed"
	case strings.Contains(s, "é"):
		return "precomposed"
	}
	return "ASCII"
}

// node runs VaneSecret on a fake store root.
type nodeStore struct {
	t         *testing.T
	src, root string
}

func (n nodeStore) env() []string {
	return with(baseEnv(n.t), "WITH_SECRETS_ROOT="+n.root)
}

func (n nodeStore) run(args ...string) res {
	c := exec.Command("node", append([]string{filepath.Join(n.src, "with-secrets.mjs")}, args...)...)
	c.Env = n.env()
	var o, er bytes.Buffer
	c.Stdout, c.Stderr = &o, &er
	return finish(c.Run(), &o, &er)
}

func (n nodeStore) tty(input string, args ...string) res {
	c := scriptCmd(append([]string{"node", filepath.Join(n.src, "with-secrets.mjs")}, args...))
	c.Env = n.env()
	c.Stdin = strings.NewReader(input)
	var o, er bytes.Buffer
	c.Stdout, c.Stderr = &o, &er
	r := finish(c.Run(), &o, &er)
	r.stdout = strings.ReplaceAll(r.stdout, "\r\n", "\n")
	return r
}

func (n nodeStore) same() bool {
	return n.run("interop.n1", "--", interopValues).stdout == "same\n" && n.run("interop.n2", "--", interopValues2).stdout == "same\n"
}

func newNodeStore(t *testing.T, src, name string) nodeStore {
	root := filepath.Join(scratch, name)
	os.RemoveAll(root)
	if err := os.MkdirAll(filepath.Join(root, "env"), 0o700); err != nil {
		t.Fatal(err)
	}
	return nodeStore{t, src, root}
}

func Test_Interop_GoToNode(t *testing.T) {
	src := os.Getenv("GSEAL_INTEROP_NODE_SRC")
	_, nodeErr := exec.LookPath("node")
	if src == "" || nodeErr != nil || runtime.GOOS != "linux" || !haveSystemdCreds() {
		if os.Getenv("GSEAL_REQUIRE_NODE") != "" {
			t.Fatal("Go -> Node interop is required (GSEAL_REQUIRE_NODE): set GSEAL_INTEROP_NODE_SRC to VaneSecret ca87d68 src; needs node and systemd-creds --user")
		}
		t.Skip("set GSEAL_INTEROP_NODE_SRC=<VaneSecret ca87d68 src>; needs node and systemd-creds --user")
	}
	if os.Getenv("GSEAL_TEST_BACKEND") == "testfile" {
		t.Skip("Go -> Node interop uses the systemd-creds backend (VaneSecret's)")
	}
	c := checker{t}

	// Go writes a store and two bundles (passphrase typed precomposed / decomposed).
	g := newE2E(t, "interop-g2n-go")
	g.run("--init")
	g.write(g.imp("interop.ini"), interopFixture)
	r := g.run("--import", "interop")
	c.ok("I.2.0", r.status == 0 && g.interopSame(), "(Go store with the fixture)", r)
	bkPre, bkDec := filepath.Join(g.root, "bk-pre"), filepath.Join(g.root, "bk-dec")
	g.tty(interopPre+"\n"+interopPre+"\n", "--backup", bkPre)
	g.tty(interopDec+"\n"+interopDec+"\n", "--backup", bkDec, "--new-password")
	goPre, goDec := newest(bkPre, "secrets-base-"), newest(bkDec, "secrets-base-")
	c.ok("I.2.0", goPre != "" && goDec != "", "(Go bundles written)")
	for _, v := range []struct{ id, bundle, typed string }{
		{"I.2a", goPre, interopPre}, {"I.2b", goPre, interopDec},
		{"I.2c", goDec, interopPre}, {"I.2d", goDec, interopDec},
	} {
		n := newNodeStore(t, src, "interop-g2n-node-"+v.id)
		r := n.tty(v.typed+"\n", "--verify-backup", v.bundle)
		c.ok(v.id, r.status == 0 && strings.Contains(r.stdout, "可用于恢复"), "Node verifies Go bundle "+filepath.Base(filepath.Dir(v.bundle))+" (passphrase typed "+form(v.typed)+")", r)
		r = n.tty(v.typed+"\n", "--restore", v.bundle)
		c.ok(v.id, r.status == 0 && n.same(), "Node restores Go bundle "+filepath.Base(filepath.Dir(v.bundle))+" (passphrase typed "+form(v.typed)+"); every value injects exactly", r)
	}

	// Store format: a store written by Node is used, exported and re-imported
	// by Go; unchanged values keep their ciphertext, so the file is byte-identical.
	n := newNodeStore(t, src, "interop-g2n-store")
	n.run("--init")
	write(t, filepath.Join(n.root, "env", "_import", "interop.ini"), interopFixture)
	r = n.run("--import", "interop")
	before := read(filepath.Join(n.root, "env", "interop.ini"))
	c.ok("I.4.0", r.status == 0 && strings.Count(before, "ENC:v1:") == 3, "(Node store with the fixture, 3 encrypted values)", r)
	gs := &e2e{t: t, c: c, root: n.root, envDir: filepath.Join(n.root, "env"), env: with(baseEnv(t), "GSEAL_STORE="+n.root), backend: "systemd-creds"}
	c.ok("I.4a", gs.interopSame(), "Go injects every value of the Node store exactly")
	r = gs.run("--export", "interop")
	r2 := gs.run("--import", "interop")
	after := read(filepath.Join(n.root, "env", "interop.ini"))
	c.ok("I.4b", r.status == 0 && r2.status == 0 && after == before, "Go export + re-import of the Node store leaves it byte-identical", r, r2)
	c.ok("I.4c", n.same(), "Node still injects every value after Go wrote the store")
}
