// Black-box tests: they build the with-secrets executable once and run it
// against FAKE stores under a temporary directory. They never touch a real
// store: every run sets the store explicitly, and the config, data and home
// directories point into the scratch area.
//
// Test names carry the baseline assertion they port (VaneSecret ca87d68),
// e.g. m1_L090 = test/m1.mjs line 90. See test/BASELINE.md.
package test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var (
	bin     string // built executable (release build)
	binTest string // built with -tags gsealtest (fault injection, testfile backend)
	scratch string // per-run scratch root
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "gseal-test-")
	if err != nil {
		panic(err)
	}
	scratch = dir
	bin = filepath.Join(dir, "with-secrets")
	binTest = filepath.Join(dir, "with-secrets-test")
	for _, b := range []*exec.Cmd{
		exec.Command("go", "build", "-trimpath", "-o", bin, "../cmd/with-secrets"),
		exec.Command("go", "build", "-trimpath", "-tags", "gsealtest", "-o", binTest, "../cmd/with-secrets"),
	} {
		b.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := b.CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "build failed: %v\n%s", err, out)
			os.Exit(2)
		}
	}
	code := m.Run()
	if os.Getenv("GSEAL_TEST_KEEP") == "" {
		os.RemoveAll(dir)
	}
	os.Exit(code)
}

// baseEnv is the parent environment without anything that could be mistaken
// for an injected value or that would point at a real store or config.
func baseEnv(t *testing.T) []string {
	var out []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		switch {
		case strings.HasPrefix(k, "WITH_SECRETS_"), strings.HasPrefix(k, "GSEAL_"), strings.HasPrefix(k, "DEPLOY_"),
			k == "HOST", k == "PSWD", k == "USER_X", k == "XDG_CONFIG_HOME", k == "XDG_DATA_HOME", k == "HOME":
			continue
		}
		out = append(out, kv)
	}
	home := filepath.Join(scratch, "home-"+sanitize(t.Name()))
	return append(out,
		"HOME="+home,
		"GSEAL_CONFIG="+filepath.Join(home, "no-config.ini"),
		"XDG_CONFIG_HOME="+filepath.Join(home, ".config"),
		"XDG_DATA_HOME="+filepath.Join(home, "xdg-data-not-used"))
}

func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '/' || r == ' ' {
			return '_'
		}
		return r
	}, s)
}

// result of one run.
type result struct {
	status         int
	stdout, stderr string
}

func runEnv(env []string, stdin string, args ...string) result {
	c := exec.Command(bin, args...)
	c.Env = env
	if stdin != "" {
		c.Stdin = strings.NewReader(stdin)
	}
	var o, e bytes.Buffer
	c.Stdout, c.Stderr = &o, &e
	err := c.Run()
	st := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			st = ee.ExitCode()
		} else {
			st = -1
		}
	}
	return result{st, o.String(), e.String()}
}

// with sets or replaces variables in env.
func with(env []string, kv ...string) []string {
	out := append([]string(nil), env...)
	for _, x := range kv {
		k, _, _ := strings.Cut(x, "=")
		found := false
		for i, y := range out {
			if strings.HasPrefix(y, k+"=") {
				out[i], found = x, true
			}
		}
		if !found {
			out = append(out, x)
		}
	}
	return out
}

func without(env []string, keys ...string) []string {
	var out []string
	for _, x := range env {
		k, _, _ := strings.Cut(x, "=")
		drop := false
		for _, d := range keys {
			if k == d {
				drop = true
			}
		}
		if !drop {
			out = append(out, x)
		}
	}
	return out
}

// checker records PASS/FAIL lines like the baseline tests, under a baseline id.
type checker struct{ t *testing.T }

func (c checker) ok(id string, cond bool, desc string, detail ...any) {
	c.t.Helper()
	if cond {
		c.t.Logf("PASS  %s  %s", id, desc)
		return
	}
	extra := ""
	if len(detail) > 0 {
		extra = "\n" + fmt.Sprint(detail...)
	}
	c.t.Errorf("FAIL  %s  %s%s", id, desc, extra)
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func haveSystemdCreds() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	if _, err := exec.LookPath("systemd-creds"); err != nil {
		return false
	}
	c := exec.Command("systemd-creds", "encrypt", "--user", "--name=gseal-probe", "-", "-")
	c.Stdin = strings.NewReader("x")
	return c.Run() == nil
}
