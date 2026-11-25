package cli

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"

	"github.com/VanePulse/GSeal/internal/audit"
	"github.com/VanePulse/GSeal/internal/msg"
	"github.com/VanePulse/GSeal/internal/redact"
)

var (
	envName      = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	logicalName  = regexp.MustCompile(`^([\w-]+)\.([\w-]+)$`)
	nonAlnumRuns = regexp.MustCompile(`[^A-Z0-9]+`)
)

// envPrefix: every injected variable is prefixed with its logical name, so
// several names combine:  pay-db.dev01 + HOST → PAY_DB_DEV01_HOST.
func envPrefix(name string) string {
	return nonAlnumRuns.ReplaceAllString(strings.ToUpper(name), "_") + "_"
}

// varName: variable names are fully upper case, whatever the key's case.
func varName(prefix, key string) string { return prefix + strings.ToUpper(key) }

// errorKind is the audit category of a failure (never the message itself,
// which may echo raw input).
func errorKind(err error) string {
	switch msg.IDOf(err) {
	case msg.Usage:
		return "usage"
	case msg.BadLogicalName:
		return "bad-name"
	case msg.UnknownName:
		return "unknown-name"
	case msg.BadKeyVar:
		return "bad-key"
	case msg.ReservedPrefix:
		return "reserved-prefix"
	case msg.KeysClash, msg.VarClash:
		return "name-collision"
	case msg.UnsupportedShell:
		return "bad-shell"
	case msg.DataKeyMissing, msg.DataKeyUnwrap, msg.DataKeyLength, msg.DecryptFailed, msg.CredsDecrypt:
		return "decrypt"
	}
	return "error"
}

// call is the audit context of one injection call.
type call struct {
	started  time.Time
	ts       string
	names    []string
	shell    string
	cmd      string
	cwd      string
	patterns []string
	known    bool // patterns are known: the command can be masked
}

// isKnownName: a logical name that names an existing section (not stray input).
func (a *app) isKnownName(n string) bool {
	m := logicalName.FindStringSubmatch(n)
	if m == nil {
		return false
	}
	f, err := a.st.Load(m[1])
	if err != nil || f == nil {
		return false
	}
	_, ok := f.Merged.Get(m[2])
	return ok
}

func (a *app) auditFailure(c *call, code int, err error) {
	if !a.cfg.AuditEnabled {
		return
	}
	known := []string{}
	for _, n := range c.names {
		if a.isKnownName(n) {
			known = append(known, n)
		}
	}
	rec := audit.Record{TS: c.ts, Names: known, Shell: c.shell, Cwd: c.cwd, Exit: code,
		Error: errorKind(err), MS: time.Since(c.started).Milliseconds(), UnknownNames: len(c.names) - len(known)}
	if c.known {
		cmd := c.cmd
		rec.Cmd = &cmd
	} else {
		n := len(utf16.Encode([]rune(c.cmd)))
		rec.CmdChars = &n
	}
	a.writeAudit(rec, c.patterns)
}

func (a *app) writeAudit(rec audit.Record, patterns []string) {
	if err := audit.Write(a.st.Logs, rec, patterns); err != nil {
		a.warn(msg.Text(msg.AuditWriteError, err.Error()))
	}
}

func bashQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func (a *app) allNames() []string {
	var out []string
	facs, _ := a.st.Facilities() // names for a hint only
	for _, fac := range facs {
		f, _ := a.st.Load(fac)
		if f == nil {
			continue
		}
		for _, sec := range f.Merged.Names() {
			out = append(out, fac+"."+sec)
		}
	}
	return out
}

func available(head string, names []string) string {
	l := strings.Join(names, "\n  ")
	if l == "" {
		l = msg.Text(msg.NoneAvailable)
	}
	return head + "\n" + msg.Text(msg.Available) + "\n  " + l
}

type resolved struct {
	env       [][2]string
	secret    []string // values to mask (incl. encrypted ones)
	encrypted []string // values stored encrypted: masked even inside plain values
	plain     []string
}

func (a *app) resolveNames(names []string) (*resolved, error) {
	r := &resolved{}
	type origin struct{ name, key string }
	seen := map[string]origin{}
	for _, name := range names {
		dot := strings.IndexByte(name, '.')
		if dot < 1 {
			return nil, msg.Errorf(msg.BadLogicalName, name)
		}
		fac, sec := name[:dot], name[dot+1:]
		f, err := a.st.Load(fac)
		if err != nil {
			return nil, err
		}
		if f == nil {
			return nil, unknownName(name, a.allNames())
		}
		if _, ok := f.Merged.Get(sec); !ok {
			return nil, unknownName(name, a.allNames())
		}
		kvs, err := a.st.Section(fac, f, sec)
		if err != nil {
			return nil, err
		}
		prefix := envPrefix(name)
		for _, kv := range kvs {
			vn := varName(prefix, kv.Key)
			if !envName.MatchString(vn) {
				return nil, msg.Errorf(msg.BadKeyVar, name, kv.Key, vn)
			}
			if m := internalEnv.FindString(vn); m != "" {
				return nil, msg.Errorf(msg.ReservedPrefix, name, vn, m)
			}
			if o, ok := seen[vn]; ok {
				if o.name == name {
					return nil, msg.Errorf(msg.KeysClash, name, o.key, kv.Key, vn)
				}
				return nil, msg.Errorf(msg.VarClash, vn, o.name, name)
			}
			seen[vn] = origin{name, kv.Key}
			r.env = append(r.env, [2]string{vn, kv.Plain})
			if a.plain.Redacted(kv.Key, kv.Encrypted) {
				r.secret = append(r.secret, kv.Plain)
				if kv.Encrypted {
					r.encrypted = append(r.encrypted, kv.Plain)
				}
			} else {
				r.plain = append(r.plain, kv.Plain)
			}
		}
	}
	return r, nil
}

func unknownName(name string, all []string) error {
	e := msg.Errorf(msg.UnknownName, name)
	e.Text = available(e.Text, all)
	return e
}

func (a *app) inject(argv []string) (int, error) {
	shell := os.Getenv("WITH_SECRETS_SHELL")
	if shell == "" {
		shell = "bash"
	}
	cwd, _ := os.Getwd()
	c := &call{started: now(), ts: now().UTC().Format("2006-01-02T15:04:05.000Z"), shell: shell, cwd: cwd}
	die := func(err error) (int, error) {
		a.auditFailure(c, ExitUsage, err)
		return ExitUsage, err
	}
	argv = append([]string(nil), argv...)
	sep := -1
	for i, x := range argv {
		if x == "--" {
			sep = i
			break
		}
	}
	if sep < 0 {
		// No `--`: treat the leading arguments that name an existing section
		// as the logical names.
		sep = 0
		for sep < len(argv) && a.isKnownName(argv[sep]) {
			sep++
		}
		// A leading name-shaped argument that does not exist: report it as unknown.
		if sep == 0 && len(argv) > 0 && logicalName.MatchString(argv[0]) {
			sep = 1
		}
		argv = append(argv[:sep], append([]string{"--"}, argv[sep:]...)...)
	}
	c.names = argv[:sep]
	c.cmd = strings.Join(argv[sep+1:], " ")
	if sep < 1 || sep == len(argv)-1 {
		return die(msg.Errorf(msg.Usage))
	}
	if shell != "bash" {
		return die(msg.Errorf(msg.UnsupportedShell, shell))
	}
	names, cmdArgs := argv[:sep], argv[sep+1:]
	script := cmdArgs[0]
	if len(cmdArgs) > 1 {
		q := make([]string, len(cmdArgs))
		for i, x := range cmdArgs {
			q[i] = bashQuote(x)
		}
		script = strings.Join(q, " ")
	}
	c.cmd = script
	res, err := a.resolveNames(names)
	if err != nil {
		return die(err)
	}
	patterns := redact.Patterns(res.secret)
	forced := redact.Patterns(res.encrypted)
	var plain []string
	for _, v := range res.plain {
		if v != "" {
			plain = append(plain, v)
		}
	}
	c.patterns, c.known = patterns, true

	bash := os.Getenv("WITH_SECRETS_BASH")
	if bash == "" {
		bash = "bash"
	}
	child := exec.Command(bash, "-c", script)
	child.Env = childEnv(os.Environ(), res.env)
	child.Stdin = os.Stdin
	code := a.runChild(child, patterns, forced, plain, bash)
	if a.cfg.AuditEnabled {
		cmd := script
		a.writeAudit(audit.Record{TS: c.ts, Names: names, Shell: shell, Cmd: &cmd, Cwd: cwd, Exit: code,
			MS: time.Since(c.started).Milliseconds()}, patterns)
	}
	return code, nil
}

// childEnv: parent environment plus injected variables, without the
// launcher's own WITH_SECRETS_* / GSEAL_* variables.
func childEnv(parent []string, inj [][2]string) []string {
	m := map[string]string{}
	var order []string
	set := func(k, v string) {
		if _, ok := m[k]; !ok {
			order = append(order, k)
		}
		m[k] = v
	}
	for _, kv := range parent {
		k, v, _ := strings.Cut(kv, "=")
		set(k, v)
	}
	for _, kv := range inj {
		set(kv[0], kv[1])
	}
	out := make([]string, 0, len(order))
	for _, k := range order {
		if !internalEnv.MatchString(k) {
			out = append(out, k+"="+m[k])
		}
	}
	return out
}

func (a *app) runChild(child *exec.Cmd, patterns, forced, plain []string, file string) int {
	stdout, err1 := child.StdoutPipe()
	stderr, err2 := child.StderrPipe()
	if err := errors.Join(err1, err2); err != nil {
		a.warn(msg.Text(msg.StartFailed, file, err.Error()))
		return 127
	}
	if err := child.Start(); err != nil {
		a.warn(msg.Text(msg.StartFailed, file, err.Error()))
		return 127
	}
	done := make(chan struct{}, 2)
	go func() { pipeRedacted(stdout, a.stdout, patterns, forced, plain); done <- struct{}{} }()
	go func() { pipeRedacted(stderr, a.stderr, patterns, forced, plain); done <- struct{}{} }()
	<-done
	<-done
	err := child.Wait()
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal())
		}
		return ee.ExitCode()
	}
	return 1
}

// pipeRedacted copies src to dst through a redactor. After a short idle the
// decided part of the held tail is flushed, so prompts without a newline show.
func pipeRedacted(src io.Reader, dst io.Writer, patterns, forced, plain []string) {
	r := redact.New(patterns, forced, plain)
	chunks := make(chan []byte)
	go func() {
		defer close(chunks)
		for {
			buf := make([]byte, 64*1024)
			n, err := src.Read(buf)
			if n > 0 {
				chunks <- buf[:n]
			}
			if err != nil {
				return
			}
		}
	}()
	write := func(s string) {
		if s != "" {
			io.WriteString(dst, s)
		}
	}
	idle := time.NewTimer(time.Hour)
	idle.Stop()
	for {
		select {
		case b, ok := <-chunks:
			if !ok {
				idle.Stop()
				write(r.Flush(true))
				return
			}
			write(r.Push(string(b)))
			idle.Reset(50 * time.Millisecond)
		case <-idle.C:
			write(r.Flush(false))
		}
	}
}
