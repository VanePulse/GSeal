package test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/scrypt"

	"github.com/VanePulse/GSeal/internal/msg"
	"github.com/VanePulse/GSeal/internal/norm"
)

// e2e is one fake store driven through the test build (gsealtest).
type e2e struct {
	t       *testing.T
	c       checker
	root    string // store root
	envDir  string // <root>/env
	env     []string
	backend string // systemd-creds | testfile
	exe     string // executable under test ("" = the gsealtest build)
}

func (e *e2e) bin() string {
	if e.exe != "" {
		return e.exe
	}
	return binTest
}

// testBackend returns the key backend for the e2e suites (GSEAL_TEST_BACKEND,
// default systemd-creds) and skips when it is not usable here.
func testBackend(t *testing.T) string {
	b := os.Getenv("GSEAL_TEST_BACKEND")
	if b == "" {
		b = "systemd-creds"
	}
	switch b {
	case "testfile":
	case "systemd-creds":
		if !haveSystemdCreds() {
			t.Skip("systemd-creds --user is not available here (needs systemd >= 256); run with GSEAL_TEST_BACKEND=testfile")
		}
	default:
		t.Fatalf("unknown GSEAL_TEST_BACKEND %q", b)
	}
	return b
}

func newE2E(t *testing.T, name string) *e2e {
	backend := testBackend(t)
	root := filepath.Join(scratch, name)
	os.RemoveAll(root)
	if err := os.MkdirAll(filepath.Join(root, "env"), 0o700); err != nil {
		t.Fatal(err)
	}
	env := with(baseEnv(t), "GSEAL_STORE="+root)
	if backend == "testfile" {
		env = with(env, "GSEAL_TEST_BACKEND=testfile")
	}
	return &e2e{t: t, c: checker{t}, root: root, envDir: filepath.Join(root, "env"), env: env, backend: backend}
}

type res struct {
	status         int
	signal         string
	stdout, stderr string
	raw            string // terminal output as written (ttyE), before CRLF -> LF
}

func finish(err error, o, e *bytes.Buffer) res {
	r := res{stdout: o.String(), stderr: e.String()}
	if err != nil {
		r.status = -1
		if ee, ok := err.(*exec.ExitError); ok {
			r.status = ee.ExitCode()
			if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
				r.signal = ws.Signal().String()
				if ws.Signal() == syscall.SIGKILL {
					r.signal = "SIGKILL"
				}
			}
		}
	}
	return r
}

// command builds a run of the test binary in its own session (no controlling
// terminal, so nothing can ever prompt on the developer's terminal).
func (e *e2e) command(extra []string, args ...string) *exec.Cmd {
	c := exec.Command(e.bin(), args...)
	c.Env = with(e.env, extra...)
	c.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return c
}

func (e *e2e) runE(extra []string, args ...string) res {
	c := e.command(extra, args...)
	var o, er bytes.Buffer
	c.Stdout, c.Stderr = &o, &er
	return finish(c.Run(), &o, &er)
}

func (e *e2e) run(args ...string) res { return e.runE(nil, args...) }

// async starts a run and returns a channel with its result.
func (e *e2e) async(extra []string, args ...string) chan res {
	ch := make(chan res, 1)
	c := e.command(extra, args...)
	var o, er bytes.Buffer
	c.Stdout, c.Stderr = &o, &er
	if err := c.Start(); err != nil {
		e.t.Fatal(err)
	}
	go func() { ch <- finish(c.Wait(), &o, &er) }()
	return ch
}

func shq(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// scriptCmd runs argv under a pseudo-terminal (util-linux or BSD script).
func scriptCmd(argv []string) *exec.Cmd {
	if runtime.GOOS == "darwin" {
		return exec.Command("script", append([]string{"-q", "/dev/null"}, argv...)...)
	}
	q := make([]string, len(argv))
	for i, a := range argv {
		q[i] = shq(a)
	}
	return exec.Command("script", "-qec", strings.Join(q, " "), "/dev/null")
}

// ttyE runs with a pseudo-terminal so /dev/tty prompts work; input is typed
// into it. Output (stdout and stderr of the command) is in stdout, with CRLF
// turned into LF.
func (e *e2e) ttyE(extra []string, input string, args ...string) res {
	c := scriptCmd(append([]string{e.bin()}, args...))
	c.Env = with(e.env, extra...)
	var o, er bytes.Buffer
	c.Stdout, c.Stderr = &o, &er
	r := finish(runTyped(c, input), &o, &er)
	r.raw = r.stdout
	r.stdout = strings.ReplaceAll(r.stdout, "\r\n", "\n")
	return r
}

func (e *e2e) tty(input string, args ...string) res { return e.ttyE(nil, input, args...) }

// runTyped runs a script(1) command with input typed into its terminal.
// util-linux script reads the input from a closed-at-end stdin as usual. BSD
// script (macOS) sends ^D to the terminal as soon as its stdin ends, which
// would reach the program before the typed lines; there the input is written
// to a pipe that stays open until the command has finished (60 s limit).
func runTyped(c *exec.Cmd, input string) error {
	if runtime.GOOS != "darwin" {
		c.Stdin = strings.NewReader(input)
		return c.Run()
	}
	in, err := c.StdinPipe()
	if err != nil {
		return err
	}
	if err := c.Start(); err != nil {
		return err
	}
	io.WriteString(in, input)
	done := make(chan error, 1)
	go func() { done <- c.Wait() }()
	select {
	case err := <-done:
		return err
	case <-time.After(60 * time.Second):
		c.Process.Kill()
		return <-done
	}
}

// ttyInteractive starts a run under a pseudo-terminal and types answer (then
// CR) delay after the prompt (message id) appears, like a human. It returns
// the merged output, the exit status and whether the prompt was seen.
func (e *e2e) ttyInteractive(extra []string, prompt msg.ID, delay time.Duration, answer string, args ...string) chan res {
	ch := make(chan res, 1)
	c := scriptCmd(append([]string{e.bin()}, args...))
	c.Env = with(e.env, extra...)
	in, _ := c.StdinPipe()
	out, _ := c.StdoutPipe()
	if err := c.Start(); err != nil {
		e.t.Fatal(err)
	}
	re := msg.Pattern(prompt)
	go func() {
		var buf bytes.Buffer
		typed := false
		b := make([]byte, 4096)
		for {
			n, err := out.Read(b)
			buf.Write(b[:n])
			if !typed && re.Match(buf.Bytes()) {
				typed = true
				go func() { time.Sleep(delay); in.Write([]byte(answer + "\r")) }()
			}
			if err != nil {
				break
			}
		}
		var o, er bytes.Buffer
		r := finish(c.Wait(), &o, &er)
		r.stdout = strings.ReplaceAll(buf.String(), "\r\n", "\n")
		if typed {
			r.signal += "prompt-seen"
		}
		ch <- r
	}()
	return ch
}

func (e *e2e) file(rel string) string { return filepath.Join(e.envDir, rel) }
func (e *e2e) imp(f string) string    { return filepath.Join(e.envDir, "_import", f) }

func (e *e2e) store(f string) string {
	b, err := os.ReadFile(e.file(f))
	if err != nil {
		return ""
	}
	return string(b)
}

func read(p string) string {
	b, _ := os.ReadFile(p)
	return string(b)
}

func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

func (e *e2e) write(p, s string) {
	e.t.Helper()
	write(e.t, p, s)
}

func (e *e2e) inject(name, expr string) string {
	return e.run(name, "--", `printf '%s' "`+expr+`"`).stdout
}

func (e *e2e) sh(name, script string) string { return e.run(name, "--", script).stdout }

func names(dir string) []string {
	ents, _ := os.ReadDir(dir)
	var out []string
	for _, x := range ents {
		out = append(out, x.Name())
	}
	return out
}

func withPrefix(l []string, p string) []string {
	var out []string
	for _, x := range l {
		if strings.HasPrefix(x, p) {
			out = append(out, x)
		}
	}
	return out
}

func newest(dir, prefix string) string {
	l := withPrefix(names(dir), prefix)
	sort.Strings(l)
	if len(l) == 0 {
		return ""
	}
	return filepath.Join(dir, l[len(l)-1])
}

// replaceFirst replaces the first match of re in s (like JavaScript's
// String.prototype.replace with a non-global regex); repl may use $1.
func replaceFirst(s, re, repl string) string {
	r := regexp.MustCompile(re)
	loc := r.FindStringSubmatchIndex(s)
	if loc == nil {
		return s
	}
	var dst []byte
	dst = r.ExpandString(dst, repl, s, loc)
	return s[:loc[0]] + string(dst) + s[loc[1]:]
}

// has reports whether out contains message id (any arguments).
func has(out string, id msg.ID) bool { return msg.Pattern(id).MatchString(out) }

// count returns how often message id occurs in out.
func count(out string, id msg.ID) int { return len(msg.Pattern(id).FindAllStringIndex(out, -1)) }

var verbRe = regexp.MustCompile(`%(?:\[\d+\])?[-+# 0-9.]*[sdvq]`)

// hasArgs reports whether out contains message id with the given arguments;
// an argument "*" matches anything.
func hasArgs(out string, id msg.ID, args ...string) bool {
	f := msg.Text(id)
	var b strings.Builder
	last := 0
	for i, loc := range verbRe.FindAllStringIndex(f, -1) {
		b.WriteString(regexp.QuoteMeta(f[last:loc[0]]))
		if i < len(args) && args[i] != "*" {
			b.WriteString(regexp.QuoteMeta(args[i]))
		} else {
			b.WriteString(`(?s:.*?)`)
		}
		last = loc[1]
	}
	b.WriteString(regexp.QuoteMeta(f[last:]))
	return regexp.MustCompile(b.String()).MatchString(out)
}

// leaks returns the known fake secrets found in s.
func leaksOf(s string, secrets []string) []string {
	var out []string
	for _, x := range secrets {
		if strings.Contains(s, x) {
			out = append(out, x)
		}
	}
	return out
}

type snapshot map[string]string

// snapshotStore: every *.ini and *.cred in env/, by content.
func (e *e2e) snapshot() snapshot {
	s := snapshot{}
	for _, f := range names(e.envDir) {
		if strings.HasSuffix(f, ".ini") || strings.HasSuffix(f, ".cred") {
			s[f] = read(e.file(f))
		}
	}
	return s
}

func same(a, b snapshot) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func (e *e2e) noTemps() bool {
	for _, d := range []string{e.envDir, filepath.Join(e.envDir, "_import")} {
		for _, f := range names(d) {
			if strings.Contains(f, ".tmp-") {
				return false
			}
		}
	}
	return true
}

func isBundle(p string) bool { return strings.HasPrefix(read(p), "WSBK1\n") }

// ---- independent reader / writer of the bundle format (WSBK1 | header JSON
// \n | nonce | ct | tag; AAD = magic + header line), used to check bundles in
// the test without going through the program.

type bundleFile struct {
	Created string            `json:"created"`
	Files   map[string]string `json:"files"`
	DataKey *string           `json:"datakey"`
}

func kdfKey(pass string, h map[string]any) []byte {
	salt, _ := base64.StdEncoding.DecodeString(h["salt"].(string))
	k, err := scrypt.Key([]byte(norm.NFC(pass)), salt, int(h["N"].(float64)), int(h["r"].(float64)), int(h["p"].(float64)), 32)
	if err != nil {
		panic(err)
	}
	return k
}

func openBundleWith(path, pass string) (*bundleFile, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	end := bytes.IndexByte(buf[6:], '\n') + 6
	var h map[string]any
	if err := json.Unmarshal(buf[6:end], &h); err != nil {
		return nil, err
	}
	blk, _ := aes.NewCipher(kdfKey(pass, h))
	g, _ := cipher.NewGCM(blk)
	body := buf[end+1:]
	pt, err := g.Open(nil, body[:12], body[12:], buf[:end+1])
	if err != nil {
		return nil, err
	}
	var p bundleFile
	return &p, json.Unmarshal(pt, &p)
}

// sealWith writes a bundle with the kdf parameters of a reference bundle.
func sealWith(pass, ref, kind string, p *bundleFile) []byte {
	rb, _ := os.ReadFile(ref)
	end := bytes.IndexByte(rb[6:], '\n') + 6
	var h map[string]any
	json.Unmarshal(rb[6:end], &h)
	key := kdfKey(pass, h)
	pt, _ := json.Marshal(p)
	h["kind"], h["created"], h["len"] = kind, time.Now().UTC().Format(time.RFC3339), 12+len(pt)+16
	hj, _ := json.Marshal(h)
	hb := append([]byte("WSBK1\n"), append(hj, '\n')...)
	nonce := make([]byte, 12)
	rand.Read(nonce)
	blk, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(blk)
	return g.Seal(append(append([]byte{}, hb...), nonce...), nonce, pt, hb)
}

func flipLast(b []byte) []byte {
	c := append([]byte{}, b...)
	c[len(c)-1] ^= 1
	return c
}
