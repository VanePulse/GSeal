package test

// M4: install.sh / uninstall.sh on scratch prefixes and FAKE stores
// (replacements R1 (installed layout), R2 and R5 of the test matrix).

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/VanePulse/GSeal/internal/msg"
)

type inst struct {
	t       *testing.T
	c       checker
	dir     string // scratch root
	home    string
	prefix  string
	store   string
	bins    map[string]string // version -> executable
	baseEnv []string
}

func newInst(t *testing.T, name string) *inst {
	dir := filepath.Join(scratch, name)
	os.RemoveAll(dir)
	i := &inst{t: t, c: checker{t}, dir: dir, home: filepath.Join(dir, "home"), prefix: filepath.Join(dir, "pfx"),
		store: filepath.Join(dir, "store"), bins: map[string]string{}}
	for _, d := range []string{i.home, filepath.Join(i.store, "env"), filepath.Join(i.store, "bin")} {
		os.MkdirAll(d, 0o700)
	}
	write(t, filepath.Join(i.store, "env", "web.ini"), "[n]\nHOST = web.invalid\nPSWD = inst-secret-1\n")
	// An old-style entry (like VaneSecret's shims) plus another file in bin/.
	write(t, filepath.Join(i.store, "bin", "with-secrets"), "#!/bin/sh\necho old-entry \"$@\"\n")
	os.Chmod(filepath.Join(i.store, "bin", "with-secrets"), 0o755)
	write(t, filepath.Join(i.store, "bin", "README.txt"), "old entry\n")
	i.baseEnv = []string{"HOME=" + i.home, "PATH=" + os.Getenv("PATH"), "TMPDIR=" + os.TempDir()}
	for _, v := range []string{"1.0.0", "1.1.0"} {
		out := filepath.Join(dir, "with-secrets-"+v)
		b := exec.Command("go", "build", "-mod=vendor", "-trimpath", "-ldflags", "-X github.com/VanePulse/GSeal/internal/cli.Version="+v, "-o", out, "../cmd/with-secrets")
		b.Env = append(os.Environ(), "CGO_ENABLED=0")
		if o, err := b.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v\n%s", v, err, o)
		}
		i.bins[v] = out
	}
	return i
}

func (i *inst) script(name string, extra []string, args ...string) res {
	c := exec.Command("bash", append([]string{filepath.Join("..", name)}, args...)...)
	c.Env = append(append([]string{}, i.baseEnv...), extra...)
	return i.exec(c)
}

func (i *inst) exec(c *exec.Cmd) res {
	var o, e strings.Builder
	c.Stdout, c.Stderr = &o, &e
	err := c.Run()
	r := res{stdout: o.String(), stderr: e.String()}
	if err != nil {
		r.status = -1
		if ee, ok := err.(*exec.ExitError); ok {
			r.status = ee.ExitCode()
		}
	}
	return r
}

func (i *inst) install(extra []string, args ...string) res {
	return i.script("install.sh", extra, append([]string{"--prefix", i.prefix}, args...)...)
}

// run calls an entry with a clean environment (only HOME and PATH).
func (i *inst) run(entry string, args ...string) res {
	c := exec.Command(entry, args...)
	c.Env = append([]string{}, i.baseEnv...)
	return i.exec(c)
}

func (i *inst) link(p string) string { s, _ := os.Readlink(p); return s }

// tree lists every path under dir with its type, link target or content.
func tree(dir string) string {
	var out []string
	filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		switch {
		case fi.Mode()&os.ModeSymlink != 0:
			t, _ := os.Readlink(p)
			out = append(out, rel+" -> "+t)
		case fi.IsDir():
			out = append(out, rel+"/")
		default:
			b, _ := os.ReadFile(p)
			out = append(out, rel+" = "+string(b))
		}
		return nil
	})
	sort.Strings(out)
	return strings.Join(out, "\n")
}

func Test_Install_Layout(t *testing.T) {
	i := newInst(t, "inst-layout")
	c := i.c
	cfg := filepath.Join(i.home, ".config", "gseal", "config.ini")
	r := i.install(nil, "--binary", i.bins["1.0.0"], "--store", i.store)
	lib := filepath.Join(i.prefix, "lib", "gseal")
	c.ok("M4.I1", r.status == 0 && i.link(filepath.Join(lib, "current")) == "1.0.0" &&
		i.link(filepath.Join(i.prefix, "bin", "with-secrets")) == "../lib/gseal/current/with-secrets" &&
		i.link(filepath.Join(i.prefix, "bin", "gseal")) == "../lib/gseal/current/with-secrets",
		"first install: <prefix>/lib/gseal/1.0.0, current -> 1.0.0, bin/with-secrets and bin/gseal -> current (relative links)", r)
	x := i.run(filepath.Join(i.prefix, "bin", "gseal"), "--version")
	c.ok("M4.I1", x.status == 0 && strings.Contains(x.stdout, msg.Text(msg.VersionLine, "1.0.0")), "gseal entry runs the installed version", x)
	b, _ := os.ReadFile(cfg)
	st, _ := os.Stat(cfg)
	c.ok("M4.I2", strings.Contains(string(b), "path = "+i.store) && st != nil && st.Mode().Perm() == 0o600, "first install writes config.ini (mode 600) with [store] path", string(b))
	// R1 on the installed layout: two levels of links, store from the config, no internal variables in the child.
	ub := filepath.Join(i.home, ".local", "bin")
	os.MkdirAll(ub, 0o700)
	os.Symlink(filepath.Join(i.prefix, "bin", "with-secrets"), filepath.Join(ub, "with-secrets"))
	c2 := exec.Command(filepath.Join(ub, "with-secrets"), "web.n", "--", `printf '%s|' "$WEB_N_HOST"; env | grep -c -E '^(GSEAL_|WITH_SECRETS_)' || true`)
	c2.Env = append(append([]string{}, i.baseEnv...), "GSEAL_X=1", "WITH_SECRETS_Y=1")
	x = i.exec(c2)
	c.ok("M4.R1", x.status == 0 && x.stdout == "web.invalid|0\n", "R1: ~/.local/bin/with-secrets -> <prefix>/bin/with-secrets -> current works; store from config; no GSEAL_* / WITH_SECRETS_* in the child", x)

	// The config is never overwritten; differences are shown.
	os.WriteFile(cfg, []byte("[store]\npath = "+i.store+"\n\n[audit]\nenabled = false\n"), 0o600)
	before, _ := os.ReadFile(cfg)
	r = i.install(nil, "--binary", i.bins["1.1.0"])
	after, _ := os.ReadFile(cfg)
	c.ok("M4.I3", r.status == 0 && string(before) == string(after) && strings.Contains(r.stdout, "+enabled = true") && strings.Contains(r.stdout, "-enabled = false"),
		"upgrade with an existing config: not changed, differences shown", r)
	c.ok("M4.I4", i.link(filepath.Join(lib, "current")) == "1.1.0" && i.link(filepath.Join(lib, "previous")) == "1.0.0" &&
		exists(filepath.Join(lib, "1.0.0", "with-secrets")) && exists(filepath.Join(lib, "1.1.0", "with-secrets")),
		"upgrade: both versions side by side, current -> 1.1.0, previous -> 1.0.0")
	r = i.install(nil, "--check")
	c.ok("M4.I5", r.status == 0 && !strings.Contains(r.stdout, "FAIL"), "--check: installation complete", r)
	r = i.script("install.sh", nil, "--prefix", i.prefix, "--rollback")
	x = i.run(filepath.Join(i.prefix, "bin", "with-secrets"), "--version")
	c.ok("M4.I6", r.status == 0 && i.link(filepath.Join(lib, "current")) == "1.0.0" && i.link(filepath.Join(lib, "previous")) == "1.1.0" &&
		strings.Contains(x.stdout, msg.Text(msg.VersionLine, "1.0.0")), "--rollback: back to 1.0.0 (and 1.1.0 is now previous)", r, x)
	r = i.install(nil, "--binary", i.bins["1.1.0"], "--version", "1.0.0")
	c.ok("M4.I7", r.status == 1 && i.link(filepath.Join(lib, "current")) == "1.0.0", "a version already installed with a different executable is refused, nothing changed", r)

	// R2: current -> a missing version: --check FAILs, the entry gives 127 from the shell.
	os.Remove(filepath.Join(lib, "current"))
	os.Symlink("9.9.9", filepath.Join(lib, "current"))
	r = i.install(nil, "--check")
	sh := exec.Command("bash", "-c", `"$0" --version; echo "rc=$?"`, filepath.Join(i.prefix, "bin", "with-secrets"))
	sh.Env = i.baseEnv
	x = i.exec(sh)
	c.ok("M4.R2", r.status != 0 && strings.Contains(r.stdout, "FAIL") && strings.Contains(x.stdout, "rc=127"), "R2: current points to a missing version: --check FAILs (non-zero), calling the entry exits 127", r, x)
}

func Test_Install_LinkStoreBin(t *testing.T) {
	i := newInst(t, "inst-storebin")
	c := i.c
	oldBin := tree(filepath.Join(i.store, "bin"))
	r := i.install(nil, "--binary", i.bins["1.0.0"], "--store", i.store, "--link-store-bin")
	var baks []string
	for _, n := range names(i.store) {
		if strings.HasPrefix(n, "bin.bak-") {
			baks = append(baks, n)
		}
	}
	c.ok("M4.L1", r.status == 0 && len(baks) == 1 && tree(filepath.Join(i.store, baks[0])) == oldBin, "--link-store-bin backs up <store>/bin first (exact copy)", r)
	c.ok("M4.L2", i.link(filepath.Join(i.store, "bin", "with-secrets")) == filepath.Join(i.prefix, "bin", "with-secrets") && exists(filepath.Join(i.store, "bin", "README.txt")),
		"<store>/bin/with-secrets links to the new entry; other files in bin/ stay")
	x := i.run(filepath.Join(i.store, "bin", "with-secrets"), "web.n", "--", `[ "$WEB_N_PSWD" = inst-secret-1 ] && echo same`)
	y := i.run(filepath.Join(i.store, "bin", "with-secrets"), "--list")
	c.ok("M4.L3", x.status == 0 && x.stdout == "same\n" && y.status == 0 && strings.Contains(y.stdout, "web"), "the old path works (injection and --list) with nothing but HOME and PATH", x, y)
	r = i.install(nil, "--check", "--store", i.store)
	c.ok("M4.L4", r.status == 0 && strings.Contains(r.stdout, "OK    "+filepath.Join(i.store, "bin", "with-secrets")), "--check verifies the store entry too", r)

	// Uninstall keeps store, config and backups, and puts the old entry back.
	cfg := filepath.Join(i.home, ".config", "gseal", "config.ini")
	envBefore := tree(filepath.Join(i.store, "env"))
	r = i.script("uninstall.sh", nil, "--prefix", i.prefix)
	x = i.run(filepath.Join(i.store, "bin", "with-secrets"), "a", "b")
	c.ok("M4.U1", r.status == 0 && !exists(filepath.Join(i.prefix, "lib", "gseal")) && !exists(filepath.Join(i.prefix, "bin", "with-secrets")) && !exists(filepath.Join(i.prefix, "bin", "gseal")),
		"uninstall removes the program and its links", r)
	c.ok("M4.U2", tree(filepath.Join(i.store, "env")) == envBefore && exists(cfg) && exists(filepath.Join(i.store, baks[0])), "uninstall keeps the store, the config and the backup")
	c.ok("M4.U3", x.stdout == "old-entry a b\n" && tree(filepath.Join(i.store, "bin")) == oldBin, "uninstall puts the old <store>/bin back", x)
}

// Each step failing after it ran: everything is put back exactly (R5).
func Test_Install_Faults(t *testing.T) {
	i := newInst(t, "inst-faults")
	c := i.c
	// An existing installation of 1.0.0 with the store entry linked.
	if r := i.install(nil, "--binary", i.bins["1.0.0"], "--store", i.store, "--link-store-bin"); r.status != 0 {
		t.Fatal(r)
	}
	snap := func() string {
		return tree(i.prefix) + "\n--\n" + tree(i.store) + "\n--\n" + tree(i.home)
	}
	// A second store whose entry is still the old one, for the store-bin steps.
	s2 := filepath.Join(i.dir, "store2")
	os.MkdirAll(filepath.Join(s2, "env"), 0o700)
	os.MkdirAll(filepath.Join(s2, "bin"), 0o700)
	write(t, filepath.Join(s2, "bin", "with-secrets"), "#!/bin/sh\necho old\n")
	for _, step := range []string{"binary", "switch", "previous", "links", "config", "store-bin", "verify"} {
		args := []string{"--binary", i.bins["1.1.0"]}
		if step == "store-bin" || step == "verify" {
			args = append(args, "--store", s2, "--link-store-bin")
		}
		if step == "config" {
			os.Rename(filepath.Join(i.home, ".config"), filepath.Join(i.dir, "config.aside")) // so the config step writes
		}
		before := snap() + "\n--\n" + tree(s2)
		r := i.install([]string{"GSEAL_INSTALL_FAULT=" + step}, args...)
		after := snap() + "\n--\n" + tree(s2)
		c.ok("M4.F1", r.status == 1 && before == after, "failure at step "+step+": exit 1, prefix, stores and config exactly as before", r)
		if step == "config" {
			os.Rename(filepath.Join(i.dir, "config.aside"), filepath.Join(i.home, ".config"))
		}
	}
	before := snap()
	r := i.script("install.sh", []string{"GSEAL_INSTALL_FAULT=rollback"}, "--prefix", i.prefix, "--rollback")
	c.ok("M4.F2", r.status == 1 && snap() == before, "--rollback without a previous version, or failing: nothing changed", r)
	i.install(nil, "--binary", i.bins["1.1.0"])
	before = snap()
	r = i.script("install.sh", []string{"GSEAL_INSTALL_FAULT=rollback"}, "--prefix", i.prefix, "--rollback")
	c.ok("M4.F3", r.status == 1 && snap() == before, "a failing --rollback puts current and previous back", r)
	// The store entry is verified: a store the config does not name is not linked.
	s3 := filepath.Join(i.dir, "store3")
	os.MkdirAll(filepath.Join(s3, "env"), 0o700)
	os.MkdirAll(filepath.Join(s3, "bin"), 0o700)
	write(t, filepath.Join(s3, "bin", "with-secrets"), "#!/bin/sh\necho old3\n")
	b3 := tree(s3)
	r = i.install(nil, "--binary", i.bins["1.1.0"], "--store", s3, "--link-store-bin")
	c.ok("M4.F4", r.status == 1 && tree(s3) == b3, "--link-store-bin for a store the old path would not reach (config names another): refused, store bin/ untouched", r)
}

// Open-source cleanup: no internal host names, user or facility names, paths
// or e-mail addresses in the repository. The forbidden words are given as
// SHA-256 hashes so this file does not list them itself.
func Test_Install_Clean(t *testing.T) {
	c := checker{t}
	bad := checkClean(t, "..")
	c.ok("M4.C1", len(bad) == 0, "no internal names, paths, hosts or e-mail addresses in the repository", "\n"+strings.Join(bad, "\n"))
}

// Release files: four archives and SHA256SUMS; an extracted archive installs
// its own executable; a source tree builds with go.
func Test_Install_Release(t *testing.T) {
	i := newInst(t, "inst-release")
	c := i.c
	dist := filepath.Join(i.dir, "dist")
	r := i.script(filepath.Join("tools", "release.sh"), nil, dist, "9.8.7")
	var archives []string
	for _, n := range names(dist) {
		if strings.HasSuffix(n, ".tar.gz") {
			archives = append(archives, n)
		}
	}
	want := []string{"gseal-9.8.7-darwin-amd64.tar.gz", "gseal-9.8.7-darwin-arm64.tar.gz", "gseal-9.8.7-linux-amd64.tar.gz", "gseal-9.8.7-linux-arm64.tar.gz"}
	c.ok("M4.P1", r.status == 0 && strings.Join(archives, ",") == strings.Join(want, ","), "release.sh builds linux/darwin x amd64/arm64 archives", r, archives)
	sums := read(filepath.Join(dist, "SHA256SUMS"))
	ver := exec.Command("sha256sum", "-c", "SHA256SUMS")
	if _, err := exec.LookPath("sha256sum"); err != nil {
		ver = exec.Command("shasum", "-a", "256", "-c", "SHA256SUMS")
	}
	ver.Dir = dist
	x := i.exec(ver)
	c.ok("M4.P2", x.status == 0 && strings.Count(sums, "\n") == 4, "SHA256SUMS lists and verifies all four archives", x)
	// Extract this platform's archive and install from it (no go needed).
	plat := "linux-amd64"
	if out, err := exec.Command("go", "env", "GOOS").Output(); err == nil {
		goarch, _ := exec.Command("go", "env", "GOARCH").Output()
		plat = strings.TrimSpace(string(out)) + "-" + strings.TrimSpace(string(goarch))
	}
	ex := filepath.Join(i.dir, "x")
	os.MkdirAll(ex, 0o700)
	tar := exec.Command("tar", "-C", ex, "-xzf", filepath.Join(dist, "gseal-9.8.7-"+plat+".tar.gz"))
	x = i.exec(tar)
	top := filepath.Join(ex, "gseal-9.8.7-"+plat)
	var files []string
	for _, n := range names(top) {
		files = append(files, n)
	}
	c.ok("M4.P3", x.status == 0 && strings.Join(files, ",") == "CHANGELOG.md,LICENSE,README.md,SECURITY.md,install.sh,uninstall.sh,with-secrets", "archive holds the executable, the scripts and the docs", x, files)
	ic := exec.Command("bash", filepath.Join(top, "install.sh"), "--prefix", i.prefix)
	ic.Env = append(append([]string{}, i.baseEnv...), "PATH=/usr/bin:/bin") // no go on the PATH
	x = i.exec(ic)
	v := i.run(filepath.Join(i.prefix, "bin", "with-secrets"), "--version")
	c.ok("M4.P4", x.status == 0 && strings.Contains(v.stdout, msg.Text(msg.VersionLine, "9.8.7")), "an extracted archive installs its own executable (no go needed)", x, v)
	// From the source tree: built with go, version from VERSION.
	p2 := filepath.Join(i.dir, "pfx2")
	r = i.script("install.sh", nil, "--prefix", p2)
	vf := strings.TrimSpace(read(filepath.Join("..", "VERSION")))
	v = i.run(filepath.Join(p2, "bin", "with-secrets"), "--version")
	c.ok("M4.P5", r.status == 0 && strings.Contains(v.stdout, msg.Text(msg.VersionLine, vf)), "from the source tree: built with go, version "+vf, r, v)
}

// Without --prefix: /usr/local only when writable, else ~/.local.
func Test_Install_DefaultPrefix(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root (default prefix /usr/local)")
	}
	i := newInst(t, "inst-default")
	r := i.script("install.sh", nil, "--binary", i.bins["1.0.0"])
	i.c.ok("M4.I8", r.status == 0 && exists(filepath.Join(i.home, ".local", "lib", "gseal", "1.0.0", "with-secrets")) &&
		exists(filepath.Join(i.home, ".local", "bin", "with-secrets")), "no root (whether or not /usr/local is writable): installed under ~/.local", r)
}

func unixWritable(dir string) bool {
	f, err := os.CreateTemp(dir, ".gseal-probe-")
	if err != nil {
		return false
	}
	f.Close()
	os.Remove(f.Name())
	return true
}

// An entry link that pointed elsewhere before the install (e.g. to the old
// store entry) is put back by uninstall.sh.
func Test_Install_ReplacedLink(t *testing.T) {
	i := newInst(t, "inst-replaced")
	c := i.c
	bin := filepath.Join(i.prefix, "bin")
	os.MkdirAll(bin, 0o700)
	old := filepath.Join(i.store, "bin", "with-secrets")
	os.Symlink(old, filepath.Join(bin, "with-secrets"))
	r := i.install(nil, "--binary", i.bins["1.0.0"], "--store", i.store, "--link-store-bin")
	x := i.run(filepath.Join(i.store, "bin", "with-secrets"), "web.n", "--", `[ "$WEB_N_HOST" = web.invalid ] && echo same`)
	c.ok("M4.U4", r.status == 0 && i.link(filepath.Join(bin, "with-secrets")) == "../lib/gseal/current/with-secrets" && x.stdout == "same\n",
		"an existing <prefix>/bin/with-secrets link to the old entry is replaced; the old path (now -> new entry) works, no loop", r, x)
	r = i.script("uninstall.sh", nil, "--prefix", i.prefix)
	y := i.run(filepath.Join(bin, "with-secrets"), "a")
	c.ok("M4.U4", r.status == 0 && i.link(filepath.Join(bin, "with-secrets")) == old && y.stdout == "old-entry a\n",
		"uninstall puts the previous link back, and the old entry it reaches is restored", r, y)
}

// Review M4-001: installs of one prefix run one at a time, so overlapping
// upgrades record the version that was really active before each switch.
func Test_Install_Concurrent(t *testing.T) {
	i := newInst(t, "inst-concurrent")
	c := i.c
	v3 := filepath.Join(i.dir, "with-secrets-1.2.0")
	b := exec.Command("go", "build", "-mod=vendor", "-trimpath", "-ldflags", "-X github.com/VanePulse/GSeal/internal/cli.Version=1.2.0", "-o", v3, "../cmd/with-secrets")
	b.Env = append(os.Environ(), "CGO_ENABLED=0")
	if o, err := b.CombinedOutput(); err != nil {
		t.Fatal(err, string(o))
	}
	i.install(nil, "--binary", i.bins["1.0.0"])
	first := make(chan res, 1)
	go func() { first <- i.install([]string{"GSEAL_INSTALL_HOLD=3"}, "--binary", i.bins["1.1.0"]) }() // holds the lock after reading current
	time.Sleep(1 * time.Second)
	second := i.install(nil, "--binary", v3) // must wait for the first
	r1 := <-first
	lib := filepath.Join(i.prefix, "lib", "gseal")
	c.ok("M4.I9", r1.status == 0 && second.status == 0 && strings.Contains(second.stdout, "waiting for another install.sh") &&
		i.link(filepath.Join(lib, "current")) == "1.2.0" && i.link(filepath.Join(lib, "previous")) == "1.1.0",
		"two overlapping upgrades: the second waits; current -> 1.2.0, previous -> 1.1.0 (the version active before it)", r1, second)
	r := i.script("install.sh", nil, "--prefix", i.prefix, "--rollback")
	c.ok("M4.I9", r.status == 0 && i.link(filepath.Join(lib, "current")) == "1.1.0", "--rollback then goes to 1.1.0", r)
}

// Review M4-002: --check fails for a missing store entry, a broken rollback
// target and a config that does not load.
func Test_Install_CheckFailures(t *testing.T) {
	i := newInst(t, "inst-check")
	c := i.c
	i.install(nil, "--binary", i.bins["1.0.0"], "--store", i.store, "--link-store-bin")
	i.install(nil, "--binary", i.bins["1.1.0"])
	lib := filepath.Join(i.prefix, "lib", "gseal")
	r := i.install(nil, "--check")
	c.ok("M4.K1", r.status == 0 && !strings.Contains(r.stdout, "FAIL"), "(a good installation passes)", r)
	entry := filepath.Join(i.store, "bin", "with-secrets")
	os.Remove(entry)
	r = i.install(nil, "--check")
	c.ok("M4.K2", r.status != 0 && strings.Contains(r.stdout, "FAIL  "+entry), "store entry removed after the switch: FAIL, non-zero (recorded store, no --store needed)", r)
	os.Symlink(filepath.Join(i.prefix, "bin", "with-secrets"), entry)
	os.Rename(filepath.Join(lib, "1.0.0"), filepath.Join(i.dir, "v1.aside"))
	r = i.install(nil, "--check")
	c.ok("M4.K3", r.status != 0 && strings.Contains(r.stdout, "FAIL  previous points to 1.0.0"), "rollback target missing: FAIL, non-zero", r)
	os.Rename(filepath.Join(i.dir, "v1.aside"), filepath.Join(lib, "1.0.0"))
	cfg := filepath.Join(i.home, ".config", "gseal", "config.ini")
	good := read(cfg)
	os.WriteFile(cfg, []byte("[nope]\n"), 0o600)
	r = i.install(nil, "--check")
	c.ok("M4.K4", r.status != 0 && strings.Contains(r.stdout, "FAIL  config"), "config that does not load: FAIL, non-zero", r)
	os.WriteFile(cfg, []byte(good), 0o600)
	r = i.install(nil, "--check")
	c.ok("M4.K5", r.status == 0, "(all repaired: passes again)", r)
}

// Review M4-003: the config is created atomically with mode 600; a failure
// inside the step leaves nothing; a config created meanwhile is kept.
func Test_Install_ConfigFaults(t *testing.T) {
	i := newInst(t, "inst-config")
	c := i.c
	cfg := filepath.Join(i.home, ".config", "gseal", "config.ini")
	for _, step := range []string{"config-write", "config-chmod"} {
		before := tree(i.home) + tree(i.prefix)
		r := i.install([]string{"GSEAL_INSTALL_FAULT=" + step}, "--binary", i.bins["1.0.0"], "--store", i.store)
		c.ok("M4.G1", r.status == 1 && strings.Contains(r.stderr, "injected fault at "+step) && !exists(cfg) && tree(i.home)+tree(i.prefix) == before,
			"failure at "+step+": exit 1, no config file (and no directory) left, prefix unchanged", r)
	}
	r := i.install([]string{"GSEAL_INSTALL_FAULT=config-race"}, "--binary", i.bins["1.0.0"], "--store", i.store)
	c.ok("M4.G2", r.status == 0 && read(cfg) == "; created by someone else meanwhile\n" && strings.Contains(r.stdout, "exists; not changed"),
		"a config created between the check and the write is kept, not overwritten", r)
	os.Remove(cfg)
	r = i.install(nil, "--binary", i.bins["1.0.0"], "--store", i.store)
	st, _ := os.Stat(cfg)
	c.ok("M4.G3", r.status == 0 && st != nil && st.Mode().Perm() == 0o600, "written config is mode 600", r)
}

// Review M4-004: uninstall restores exactly the entry from the backup made
// by the switch, keeps everything else, and removes nothing if it cannot.
func Test_Install_UninstallSafety(t *testing.T) {
	i := newInst(t, "inst-uninstall")
	c := i.c
	i.install(nil, "--binary", i.bins["1.0.0"], "--store", i.store, "--link-store-bin")
	sbin := filepath.Join(i.store, "bin")
	write(t, filepath.Join(sbin, "added-later.txt"), "keep me\n")
	other := filepath.Join(i.store, "bin.bak-99991231T235959-1")
	os.MkdirAll(other, 0o700)
	write(t, filepath.Join(other, "with-secrets"), "#!/bin/sh\necho unrelated-backup\n")
	os.Chmod(filepath.Join(other, "with-secrets"), 0o755)
	r := i.script("uninstall.sh", nil, "--prefix", i.prefix)
	x := i.run(filepath.Join(sbin, "with-secrets"), "a")
	c.ok("M4.U5", r.status == 0 && x.stdout == "old-entry a\n" && read(filepath.Join(sbin, "added-later.txt")) == "keep me\n" &&
		read(filepath.Join(other, "with-secrets")) == "#!/bin/sh\necho unrelated-backup\n" && exists(filepath.Join(sbin, "README.txt")),
		"uninstall puts back the entry from the backup recorded by the switch (not the newest-named one); files added to bin/ later and other backups are kept", r, x)

	// Backup gone: nothing removed, the switched entry keeps working.
	i.install(nil, "--binary", i.bins["1.0.0"], "--store", i.store, "--link-store-bin")
	for _, n := range names(i.store) {
		if strings.HasPrefix(n, "bin.bak-") && filepath.Join(i.store, n) != other {
			os.RemoveAll(filepath.Join(i.store, n))
		}
	}
	r = i.script("uninstall.sh", nil, "--prefix", i.prefix)
	x = i.run(filepath.Join(sbin, "with-secrets"), "web.n", "--", `[ "$WEB_N_HOST" = web.invalid ] && echo same`)
	c.ok("M4.U6", r.status == 1 && exists(filepath.Join(i.prefix, "lib", "gseal", "current")) && x.stdout == "same\n",
		"backup missing: uninstall exits 1, removes nothing, the switched entry still works", r, x)

	// A store inside the prefix (or the other way round) is refused up front.
	i2 := newInst(t, "inst-overlap")
	inner := filepath.Join(i2.prefix, "lib", "gseal", "store")
	os.MkdirAll(filepath.Join(inner, "env"), 0o700)
	os.MkdirAll(filepath.Join(inner, "bin"), 0o700)
	r = i2.install(nil, "--binary", i2.bins["1.0.0"], "--store", inner, "--link-store-bin")
	c.ok("M4.U7", r.status == 2 && exists(filepath.Join(inner, "env")) && !exists(filepath.Join(i2.prefix, "lib", "gseal", "current")),
		"a store inside the prefix: refused before anything is changed", r)
}

// Review M4-005: the old path is checked the way a cron job calls it, on the
// first switch and on repeated installs; the verify step is really reached.
func Test_Install_StoreBinFaults(t *testing.T) {
	i := newInst(t, "inst-storebin-faults")
	c := i.c
	if r := i.install(nil, "--binary", i.bins["1.0.0"], "--store", i.store); r.status != 0 {
		t.Fatal(r)
	}
	snap := func() string { return tree(i.prefix) + "\n--\n" + tree(i.store) + "\n--\n" + tree(i.home) }
	for _, step := range []string{"store-bin", "verify"} {
		before := snap()
		r := i.install([]string{"GSEAL_INSTALL_FAULT=" + step}, "--binary", i.bins["1.1.0"], "--store", i.store, "--link-store-bin")
		c.ok("M4.V1", r.status == 1 && strings.Contains(r.stderr, "injected fault at "+step) && snap() == before,
			"failure at step "+step+" (reached: fault reported): exit 1, everything exactly as before, old entry in place", r)
	}
	// A config only the installing shell sees (GSEAL_CONFIG): jobs would not reach the store.
	j := newInst(t, "inst-custom-config")
	custom := filepath.Join(j.dir, "custom.ini")
	before := tree(j.store)
	r := j.install([]string{"GSEAL_CONFIG=" + custom}, "--binary", j.bins["1.0.0"], "--store", j.store, "--link-store-bin")
	x := j.run(filepath.Join(j.store, "bin", "with-secrets"), "a")
	c.ok("M4.V2", r.status == 1 && strings.Contains(r.stderr, "jobs would break") && tree(j.store) == before && x.stdout == "old-entry a\n",
		"config only in GSEAL_CONFIG (invisible to jobs): refused, old entry kept and working", r)
	// Already linked, but the config no longer names the store: a repeated install fails.
	i.install(nil, "--binary", i.bins["1.1.0"], "--store", i.store, "--link-store-bin")
	cfg := filepath.Join(i.home, ".config", "gseal", "config.ini")
	good := read(cfg)
	os.WriteFile(cfg, []byte(strings.Replace(good, "path = "+i.store, "path = "+j.store, 1)), 0o600)
	r = i.install(nil, "--binary", i.bins["1.1.0"], "--store", i.store, "--link-store-bin")
	c.ok("M4.V3", r.status == 1 && strings.Contains(r.stderr, "does not reach "+i.store), "repeated install with the entry already linked: checked again, fails when jobs would not reach the store", r)
	os.WriteFile(cfg, []byte(good), 0o600)
}

// Review M4-008: the quick start gives a first command for both kinds of
// machine (each is run on a fake store: M3.P1 for the passphrase backend,
// e2e_L059 for systemd-creds), and the threat model states that plain-text
// values are not protected at rest.
func Test_Install_Docs(t *testing.T) {
	c := checker{t}
	readme := read(filepath.Join("..", "README.md"))
	sec := read(filepath.Join("..", "SECURITY.md"))
	c.ok("M4.D1", strings.Contains(readme, "with-secrets --init                       # Linux with systemd 256") &&
		strings.Contains(readme, "with-secrets --init --backend passphrase  # macOS"), "README quick start: --init for systemd-creds and --init --backend passphrase for macOS / no systemd-creds")
	c.ok("M4.D2", strings.Contains(sec, "Values the policy leaves in plain text are **not** protected at rest") &&
		strings.Contains(sec, "Backup bundles are encrypted as a whole"), "SECURITY.md: at-rest protection covers encrypted values and whole bundles, not plain-text values")
}

// Review M4-001 (round 2): a holder that dies leaves no lock to take over
// (kernel flock); without flock a dead holder's lock is reported, never
// taken over, and the lock still serialises installs.
func Test_Install_LockRobust(t *testing.T) {
	// M4.I10 is about the kernel lock: flock(1) is a precondition here (CI
	// installs it on macOS); M4.I11 / I12 cover the no-flock lock explicitly.
	if _, err := exec.LookPath("flock"); err != nil {
		t.Fatal("M4.I10 needs flock(1) on the PATH (util-linux; on macOS: brew install flock)")
	}
	i := newInst(t, "inst-lock")
	c := i.c
	lib := filepath.Join(i.prefix, "lib", "gseal")
	i.install(nil, "--binary", i.bins["1.0.0"])
	// Holder killed while it holds the lock (after reading current).
	cmd := exec.Command("bash", filepath.Join("..", "install.sh"), "--prefix", i.prefix, "--binary", i.bins["1.1.0"])
	cmd.Env = append(append([]string{}, i.baseEnv...), "GSEAL_INSTALL_HOLD=30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1500 * time.Millisecond)
	cmd.Process.Kill()
	cmd.Wait()
	// Two installs right after: still one at a time.
	v3 := filepath.Join(i.dir, "with-secrets-1.2.0")
	b := exec.Command("go", "build", "-mod=vendor", "-trimpath", "-ldflags", "-X github.com/VanePulse/GSeal/internal/cli.Version=1.2.0", "-o", v3, "../cmd/with-secrets")
	b.Env = append(os.Environ(), "CGO_ENABLED=0")
	b.CombinedOutput()
	first := make(chan res, 1)
	go func() { first <- i.install([]string{"GSEAL_INSTALL_HOLD=2"}, "--binary", i.bins["1.1.0"]) }()
	time.Sleep(700 * time.Millisecond)
	second := i.install(nil, "--binary", v3)
	r1 := <-first
	c.ok("M4.I10", r1.status == 0 && second.status == 0 && i.link(filepath.Join(lib, "current")) == "1.2.0" && i.link(filepath.Join(lib, "previous")) == "1.1.0",
		"after a holder was killed (kernel released the lock) two competing installs still run one at a time: previous = the version active before the last switch", r1, second)

	// Without flock: a lock whose holder is gone is reported, nothing changes.
	j := newInst(t, "inst-lock-dir")
	j.install([]string{"GSEAL_INSTALL_NO_FLOCK=1"}, "--binary", j.bins["1.0.0"])
	jl := filepath.Join(j.prefix, "lib", "gseal")
	dead := exec.Command("true")
	dead.Run()
	os.MkdirAll(j.lockPath(), 0o700)
	write(t, filepath.Join(j.lockPath(), "pid"), itoa(dead.ProcessState.Pid())+"\n")
	before := tree(j.prefix)
	r := j.install([]string{"GSEAL_INSTALL_NO_FLOCK=1"}, "--binary", j.bins["1.1.0"])
	c.ok("M4.I11", r.status == 1 && strings.Contains(r.stderr, "no longer running") && tree(j.prefix) == before,
		"no flock: a lock left by a dead process is reported and not taken over; nothing changed", r)
	os.RemoveAll(j.lockPath())
	first = make(chan res, 1)
	go func() {
		first <- j.install([]string{"GSEAL_INSTALL_NO_FLOCK=1", "GSEAL_INSTALL_HOLD=2"}, "--binary", j.bins["1.1.0"])
	}()
	time.Sleep(700 * time.Millisecond)
	second = j.install([]string{"GSEAL_INSTALL_NO_FLOCK=1"}, "--binary", v3)
	r1 = <-first
	c.ok("M4.I12", r1.status == 0 && second.status == 0 && strings.Contains(second.stdout, "waiting for another") && i.link(filepath.Join(jl, "current")) == "1.2.0" &&
		i.link(filepath.Join(jl, "previous")) == "1.1.0", "no flock: overlapping installs are still serialised", r1, second)
}

// Review M4-002 (round 2): a recorded store whose bin/ did not exist before.
func Test_Install_CheckNoOldBin(t *testing.T) {
	i := newInst(t, "inst-check-nobin")
	c := i.c
	os.RemoveAll(filepath.Join(i.store, "bin"))
	r := i.install(nil, "--binary", i.bins["1.0.0"], "--store", i.store, "--link-store-bin")
	entry := filepath.Join(i.store, "bin", "with-secrets")
	c.ok("M4.K6", r.status == 0 && i.link(entry) == filepath.Join(i.prefix, "bin", "with-secrets"), "a store without bin/: the entry is created", r)
	os.Remove(entry)
	r = i.install(nil, "--check")
	c.ok("M4.K6", r.status != 0 && strings.Contains(r.stdout, "FAIL  "+entry), "its entry removed: --check FAILs", r)
}

// Review M4-003 (round 2): a directory at the config path.
func Test_Install_ConfigDirectory(t *testing.T) {
	i := newInst(t, "inst-config-dir")
	c := i.c
	cfg := filepath.Join(i.home, ".config", "gseal", "config.ini")
	os.MkdirAll(cfg, 0o700)
	before := tree(i.home) + tree(i.prefix)
	r := i.install(nil, "--binary", i.bins["1.0.0"], "--store", i.store)
	c.ok("M4.G4", r.status == 2 && tree(i.home)+tree(i.prefix) == before, "the config path is a directory: refused before any change", r)
	os.RemoveAll(cfg)
	before = tree(i.home) + tree(i.prefix)
	r = i.install([]string{"GSEAL_INSTALL_FAULT=config-race-dir"}, "--binary", i.bins["1.0.0"], "--store", i.store)
	inDir := names(cfg)
	os.RemoveAll(cfg)
	c.ok("M4.G5", r.status == 1 && strings.Contains(r.stderr, "is a directory") && len(inDir) == 0 && tree(i.home)+tree(i.prefix) == before,
		"a directory created at the config path meanwhile: exit 1 (not success), nothing written into it, everything else as before", r, inDir)
	inside := filepath.Join(i.prefix, "lib", "gseal", "state", "config.ini")
	r = i.install([]string{"GSEAL_CONFIG=" + inside}, "--binary", i.bins["1.0.0"])
	c.ok("M4.G6", r.status == 2 && !exists(inside), "a config path inside <prefix>/lib/gseal is refused", r)
}

// Review M4-004 (round 2): uninstall keeps foreign files in state/, and
// handles stores that had no entry (or no bin/) before the switch.
func Test_Install_UninstallNoOldEntry(t *testing.T) {
	i := newInst(t, "inst-uninst-noentry")
	c := i.c
	os.Remove(filepath.Join(i.store, "bin", "with-secrets")) // bin/ exists, no entry
	r := i.install(nil, "--binary", i.bins["1.0.0"], "--store", i.store, "--link-store-bin")
	// A file that install did not write, put into state/.
	foreign := filepath.Join(i.prefix, "lib", "gseal", "state", "notes.txt")
	write(t, foreign, "mine\n")
	u := i.script("uninstall.sh", nil, "--prefix", i.prefix)
	c.ok("M4.U8", r.status == 0 && u.status == 0 && !exists(filepath.Join(i.store, "bin", "with-secrets")) &&
		exists(filepath.Join(i.store, "bin", "README.txt")) && read(foreign) == "mine\n",
		"store whose bin/ had no entry: uninstall removes the link only; a file in state/ that install did not write is kept", r, u)
	// A store without bin/: install makes bin/, uninstall removes it again (empty).
	j := newInst(t, "inst-uninst-nobin")
	os.RemoveAll(filepath.Join(j.store, "bin"))
	j.install(nil, "--binary", j.bins["1.0.0"], "--store", j.store, "--link-store-bin")
	u = j.script("uninstall.sh", nil, "--prefix", j.prefix)
	c.ok("M4.U9", u.status == 0 && !exists(filepath.Join(j.store, "bin")) && exists(filepath.Join(j.store, "env", "web.ini")) && !exists(filepath.Join(j.prefix, "lib", "gseal")),
		"store without bin/: uninstall removes the link and the empty bin/ it made; the store is kept", u)
}

// Review M4-009: a failure after the replaced entry link was recorded puts
// the link back and leaves no state file.
func Test_Install_ReplacedLinkFault(t *testing.T) {
	i := newInst(t, "inst-replaced-fault")
	c := i.c
	bin := filepath.Join(i.prefix, "bin")
	os.MkdirAll(bin, 0o700)
	old := filepath.Join(i.store, "bin", "with-secrets")
	os.Symlink(old, filepath.Join(bin, "with-secrets"))
	before := tree(i.prefix) + tree(i.home)
	r := i.install([]string{"GSEAL_INSTALL_FAULT=links"}, "--binary", i.bins["1.0.0"])
	c.ok("M4.H1", r.status == 1 && i.link(filepath.Join(bin, "with-secrets")) == old && !exists(filepath.Join(i.prefix, "lib", "gseal", "state")) && tree(i.prefix)+tree(i.home) == before,
		"first install fails after recording the replaced link: exit 1, link and state exactly as before", r)
}

// Review M4-007: tools/check-history.sh (the M4.C1 checks for a ref's every
// commit) on plain directories: it finds what M4.C1 finds, never reports an
// unreadable input as clean, and its allow lists equal M4.C1's.
func Test_Install_HistoryScript(t *testing.T) {
	c := checker{t}
	scan := func(dir string) res {
		cmd := exec.Command("bash", filepath.Join("..", "tools", "check-history.sh"), "--tree", dir)
		var o, e strings.Builder
		cmd.Stdout, cmd.Stderr = &o, &e
		err := cmd.Run()
		r := res{stdout: o.String(), stderr: e.String()}
		if ee, ok := err.(*exec.ExitError); ok {
			r.status = ee.ExitCode()
		}
		return r
	}
	base := filepath.Join(scratch, "hist")
	os.RemoveAll(base)
	clean := filepath.Join(base, "clean")
	write(t, filepath.Join(clean, "a.go"), "package a // see example.invalid, 10.0.0.1, ops@example.invalid, x.localName\n")
	r := scan(clean)
	c.ok("M4.C2", r.status == 0, "a clean tree is clean (no false positive for x.localName)", r)
	for k, v := range map[string]string{
		"name":  "deploy on gan" + "try today\n",
		"email": "mail someone@" + "corp.example\n",
		"path":  "see /ho" + "me/someone/x\n",
		"host":  "db at " + strings.Join([]string{"db1", "intranet", "local"}, ".") + " now\n",
		"ip":    "addr 172.16" + ".5.4\n",
	} {
		d := filepath.Join(base, k)
		write(t, filepath.Join(d, "f.txt"), v)
		r = scan(d)
		c.ok("M4.C2", r.status == 1, "finds a planted "+k, r)
	}
	write(t, filepath.Join(base, "vend", "vendor", "x.txt"), "gan"+"try\n")
	write(t, filepath.Join(base, "vend", "testdata", "norm", "v.txt"), "gan"+"try\n")
	r = scan(filepath.Join(base, "vend"))
	c.ok("M4.C2", r.status == 0, "vendor/ and testdata/norm/ are left out, as in M4.C1", r)
	r = scan(filepath.Join(base, "missing"))
	c.ok("M4.C2", r.status == 2 && !strings.Contains(r.stdout, "clean"), "a directory that cannot be read: exit 2, never 'clean'", r)
	// The allow lists in the script equal those of M4.C1.
	src := read(filepath.Join("..", "tools", "check-history.sh"))
	field := func(name string) []string {
		for _, l := range strings.Split(src, "\n") {
			if strings.HasPrefix(l, name+"=\"") {
				f := strings.Fields(strings.Trim(strings.TrimPrefix(l, name+"="), "\""))
				sort.Strings(f)
				return f
			}
		}
		return nil
	}
	keys := func(m map[string]bool) []string {
		var out []string
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	c.ok("M4.C2", strings.Join(field("ALLOW_HOSTS"), " ") == strings.Join(keys(cleanAllowHost), " ") &&
		strings.Join(field("ALLOW_IPS"), " ") == strings.Join(keys(cleanAllowIP), " "), "the script's allow lists equal M4.C1's", field("ALLOW_HOSTS"), field("ALLOW_IPS"))
}

// Review M4-001 (round 3): uninstall.sh uses the same lock and never deletes
// it, so it cannot let two installs in at once.
func Test_Install_UninstallLock(t *testing.T) {
	i := newInst(t, "inst-uninst-lock")
	c := i.c
	lib := filepath.Join(i.prefix, "lib", "gseal")
	i.install(nil, "--binary", i.bins["1.0.0"])
	held := make(chan res, 1)
	go func() { held <- i.install([]string{"GSEAL_INSTALL_HOLD=2"}, "--binary", i.bins["1.1.0"]) }()
	time.Sleep(700 * time.Millisecond)
	u := i.script("uninstall.sh", nil, "--prefix", i.prefix)
	h := <-held
	c.ok("M4.I13", h.status == 0 && u.status == 0 && strings.Contains(u.stdout, "waiting for another") && !exists(lib) && exists(i.prefix),
		"an uninstall during an install waits for it, then removes everything; the prefix itself (the lock) stays", h, u)
	first := make(chan res, 1)
	go func() { first <- i.install([]string{"GSEAL_INSTALL_HOLD=2"}, "--binary", i.bins["1.0.0"]) }()
	time.Sleep(700 * time.Millisecond)
	second := i.install(nil, "--binary", i.bins["1.1.0"])
	r1 := <-first
	c.ok("M4.I14", r1.status == 0 && second.status == 0 && strings.Contains(second.stdout, "waiting for another") &&
		i.link(filepath.Join(lib, "current")) == "1.1.0" && i.link(filepath.Join(lib, "previous")) == "1.0.0",
		"after an uninstall, two overlapping installs are still serialised: current 1.1.0, previous 1.0.0", r1, second)
}

// Review M4-002 (round 3): a config path that became a directory fails --check.
func Test_Install_CheckConfigDir(t *testing.T) {
	i := newInst(t, "inst-check-cfgdir")
	c := i.c
	i.install(nil, "--binary", i.bins["1.0.0"], "--store", i.store)
	cfg := filepath.Join(i.home, ".config", "gseal", "config.ini")
	os.Remove(cfg)
	os.MkdirAll(cfg, 0o700)
	r := i.install(nil, "--check")
	c.ok("M4.K7", r.status != 0 && strings.Contains(r.stdout, "FAIL  config path"), "the config path is now a directory: --check FAILs", r)
}

// Review M4-004 (round 3): overlaps are found on canonical paths ("..",
// symlinks), and an entry link that cannot be removed stops the uninstall.
func Test_Install_CanonicalOverlap(t *testing.T) {
	i := newInst(t, "inst-canon")
	c := i.c
	lib := filepath.Join(i.prefix, "lib", "gseal")
	i.install(nil, "--binary", i.bins["1.0.0"])
	sneaky := filepath.Join(lib, "x", "..", "state", "config.ini")
	before := tree(i.prefix)
	r := i.install([]string{"GSEAL_CONFIG=" + sneaky}, "--binary", i.bins["1.1.0"])
	c.ok("M4.G7", r.status != 0 && !exists(filepath.Join(lib, "state", "config.ini")) && tree(i.prefix) == before,
		"a config path into <prefix>/lib/gseal written with '..' is refused", r)
	alias := filepath.Join(i.dir, "pfx-alias")
	os.Symlink(i.prefix, alias)
	inner := filepath.Join(alias, "lib", "gseal", "..", "gseal-store")
	os.MkdirAll(filepath.Join(i.prefix, "lib", "gseal-store", "env"), 0o700)
	r = i.install(nil, "--binary", i.bins["1.1.0"], "--store", inner, "--link-store-bin")
	c.ok("M4.U10", r.status == 2 && tree(i.prefix) != "" && !exists(filepath.Join(i.prefix, "lib", "gseal-store", "bin")),
		"a store inside the prefix reached through a symlink and '..' is refused", r)
	if os.Getuid() != 0 {
		bin := filepath.Join(i.prefix, "bin")
		os.Chmod(bin, 0o555)
		u := i.script("uninstall.sh", nil, "--prefix", i.prefix)
		x := i.run(filepath.Join(bin, "with-secrets"), "--version")
		os.Chmod(bin, 0o755)
		c.ok("M4.U11", u.status == 1 && exists(filepath.Join(lib, "current")) && x.status == 0,
			"an entry link that cannot be removed: uninstall exits 1 and keeps the program, the entry still works", u, x)
	}
}

// lockPath is the lock directory install.sh uses for this prefix.
func (i *inst) lockPath() string {
	r := i.install(nil, "--lock-path")
	return strings.TrimSpace(r.stdout)
}

// Review M4-001 (round 4): one lock for every process, with or without
// flock, and independent of the prefix existing.
func Test_Install_LockMixed(t *testing.T) {
	i := newInst(t, "inst-lock-mixed")
	c := i.c
	lib := filepath.Join(i.prefix, "lib", "gseal")
	i.install(nil, "--binary", i.bins["1.0.0"])
	for _, order := range [][2][]string{
		{{"GSEAL_INSTALL_HOLD=2"}, {"GSEAL_INSTALL_NO_FLOCK=1"}},
		{{"GSEAL_INSTALL_HOLD=2", "GSEAL_INSTALL_NO_FLOCK=1"}, nil},
	} {
		i.install(nil, "--binary", i.bins["1.0.0"]) // current 1.0.0
		first := make(chan res, 1)
		go func() { first <- i.install(order[0], "--binary", i.bins["1.1.0"]) }()
		time.Sleep(700 * time.Millisecond)
		second := i.install(order[1], "--binary", i.bins["1.0.0"])
		r1 := <-first
		c.ok("M4.I15", r1.status == 0 && second.status == 0 && strings.Contains(second.stdout, "waiting for another") &&
			i.link(filepath.Join(lib, "current")) == "1.0.0" && i.link(filepath.Join(lib, "previous")) == "1.1.0",
			"one process with flock, one without (both orders): the second waits; previous = the version active before its switch", order, r1, second)
	}
	// A first install that fails removes the prefix it made; installs
	// waiting meanwhile, and new ones, still run one at a time.
	j := newInst(t, "inst-lock-fresh")
	jl := filepath.Join(j.prefix, "lib", "gseal")
	a := make(chan res, 1)
	go func() {
		a <- j.install([]string{"GSEAL_INSTALL_HOLD=2", "GSEAL_INSTALL_FAULT=switch"}, "--binary", j.bins["1.0.0"])
	}()
	time.Sleep(700 * time.Millisecond)
	b := make(chan res, 1)
	go func() { b <- j.install([]string{"GSEAL_INSTALL_HOLD=3"}, "--binary", j.bins["1.0.0"]) }()
	ra := <-a
	time.Sleep(1 * time.Second) // b holds the lock now
	rc := j.install(nil, "--binary", j.bins["1.1.0"])
	rb := <-b
	c.ok("M4.I16", ra.status == 1 && rb.status == 0 && rc.status == 0 && strings.Contains(rc.stdout, "waiting for another") &&
		j.link(filepath.Join(jl, "current")) == "1.1.0" && j.link(filepath.Join(jl, "previous")) == "1.0.0",
		"a failing first install removes the prefix it made; the waiting install and a new one are still serialised (current 1.1.0, previous 1.0.0)", ra, rb, rc)
}

// Review M4-004 (round 4): a config file that is a symlink into
// <prefix>/lib/gseal is refused at install, and never removed by uninstall.
func Test_Install_ConfigSymlink(t *testing.T) {
	i := newInst(t, "inst-config-link")
	c := i.c
	lib := filepath.Join(i.prefix, "lib", "gseal")
	cfg := filepath.Join(i.home, ".config", "gseal", "config.ini")
	i.install(nil, "--binary", i.bins["1.0.0"], "--store", i.store, "--link-store-bin")
	target := filepath.Join(lib, "state", "store-bin")
	keep := read(cfg)
	os.Remove(cfg)
	os.Symlink(target, cfg)
	before := tree(i.prefix)
	r := i.install(nil, "--binary", i.bins["1.1.0"])
	c.ok("M4.U12", r.status == 2 && tree(i.prefix) == before, "a config that is a symlink into <prefix>/lib/gseal: install refused, nothing changed", r)
	u := i.script("uninstall.sh", nil, "--prefix", i.prefix)
	c.ok("M4.U13", u.status == 0 && exists(target) && strings.Contains(u.stdout, "kept "+target) && i.link(cfg) == target,
		"uninstall never removes the file the config links to (even inside state/); the config link stays", u)
	os.Remove(cfg)
	os.WriteFile(cfg, []byte(keep), 0o600)
}

// Review M4-001 (round 5): a failing install removes what it made before it
// releases the lock, so the next install cannot lose its directories.
func Test_Install_DieOrder(t *testing.T) {
	i := newInst(t, "inst-die-order")
	c := i.c
	lib := filepath.Join(i.prefix, "lib", "gseal")
	a := make(chan res, 1)
	go func() {
		a <- i.install([]string{"GSEAL_INSTALL_HOLD=2", "GSEAL_INSTALL_FAULT=switch", "GSEAL_INSTALL_DIE_HOLD=3"}, "--binary", i.bins["1.0.0"])
	}()
	time.Sleep(700 * time.Millisecond)
	rb := i.install(nil, "--binary", i.bins["1.1.0"]) // waits, then runs while a lingers after releasing
	ra := <-a
	c.ok("M4.I17", ra.status == 1 && rb.status == 0 && i.link(filepath.Join(lib, "current")) == "1.1.0" && exists(filepath.Join(lib, "1.1.0", "with-secrets")),
		"a failing first install removes its directories before releasing the lock: the next install (taking the lock while the first still runs) completes", ra, rb)
}

// Review M4-004 (round 5): the config an install used is protected by
// uninstall even from a session that does not set GSEAL_CONFIG.
func Test_Install_RecordedConfig(t *testing.T) {
	i := newInst(t, "inst-recorded-config")
	c := i.c
	lib := filepath.Join(i.prefix, "lib", "gseal")
	custom := filepath.Join(i.dir, "custom", "config.ini")
	i.install(nil, "--binary", i.bins["1.0.0"], "--store", i.store, "--link-store-bin") // state/store-bin exists
	r := i.install([]string{"GSEAL_CONFIG=" + custom}, "--binary", i.bins["1.1.0"])     // a later install with a custom config
	c.ok("M4.U14", r.status == 0 && strings.Contains(read(filepath.Join(lib, "state", "config-paths")), custom), "(the config path used is recorded)", r)
	target := filepath.Join(lib, "state", "store-bin")
	os.Remove(custom)
	os.Symlink(target, custom)
	u := i.script("uninstall.sh", nil, "--prefix", i.prefix) // no GSEAL_CONFIG here
	c.ok("M4.U14", u.status == 0 && exists(target) && i.link(custom) == target, "uninstall from a session without GSEAL_CONFIG keeps what the recorded config links to", u)
}

// Review M4-004 (round 6): uninstall removes only the exact files install
// writes in state/; a file added later, whatever its name (also one that
// looks like a temp file), and an unrecorded config linking to it are kept.
func Test_Install_StateExactNames(t *testing.T) {
	i := newInst(t, "inst-state-exact")
	c := i.c
	lib := filepath.Join(i.prefix, "lib", "gseal")
	i.install(nil, "--binary", i.bins["1.0.0"], "--store", i.store, "--link-store-bin")
	var added []string
	for _, n := range []string{".config.ini.new.12345", ".store-bin.new.999", "my.ini"} {
		f := filepath.Join(lib, "state", n)
		write(t, f, "[store]\npath = "+i.store+"\n")
		added = append(added, f)
	}
	unrecorded := filepath.Join(i.dir, "elsewhere", "config.ini")
	os.MkdirAll(filepath.Dir(unrecorded), 0o700)
	os.Symlink(added[0], unrecorded) // a config nobody told install about
	u := i.script("uninstall.sh", nil, "--prefix", i.prefix)
	kept := true
	for _, f := range added {
		kept = kept && read(f) == "[store]\npath = "+i.store+"\n"
	}
	c.ok("M4.U15", u.status == 0 && kept && read(unrecorded) != "" && !exists(filepath.Join(lib, "state", "store-bin")) && !exists(filepath.Join(lib, "current")),
		"uninstall removes only install's own files in state/ (exact names); files added later (also temp-file-like names) and an unrecorded config linking to one are kept", u)
}
