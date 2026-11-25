// Package cli implements the with-secrets command line.
//
//	with-secrets [--store <dir>] <facility.section> [more...] -- <command...>
//	with-secrets [--store <dir>] --list [<facility>[.<section>]]
//	with-secrets [--store <dir>] --where
//	with-secrets [--store <dir>] --policy [<facility>]
//	with-secrets --init | --new | --export | --import | --backup | --restore | --undo-restore | --verify-backup
//
// Variables are named <LOGICAL_NAME>_<KEY>, e.g. redis.uat + PSWD → REDIS_UAT_PSWD.
// A single argument after `--` is run as a bash script (so $VAR references
// expand inside the child, after injection); several arguments are quoted
// and joined.
package cli

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/VanePulse/GSeal/internal/admin"
	"github.com/VanePulse/GSeal/internal/config"
	"github.com/VanePulse/GSeal/internal/keys"
	"github.com/VanePulse/GSeal/internal/msg"
	"github.com/VanePulse/GSeal/internal/policy"
	"github.com/VanePulse/GSeal/internal/store"
)

// Exit codes.
const (
	ExitOK    = 0
	ExitFail  = 1
	ExitUsage = 2
)

// internalEnv matches the launcher's own variables: never passed to the
// child, never produced by injection.
var internalEnv = regexp.MustCompile(`^(WITH_SECRETS_|GSEAL_)`)

// app holds what every command needs.
type app struct {
	stdout, stderr io.Writer
	cfg            *config.Config
	loc            config.Location
	st             *store.Store
	plain          policy.Plain
}

// Main runs with-secrets with args (without the program name).
func Main(args []string, stdout, stderr io.Writer) int {
	a := &app{stdout: stdout, stderr: stderr}
	code, err := a.run(args)
	if err != nil {
		a.warn(err.Error())
	}
	return code
}

// Version is set at build time: -ldflags "-X github.com/VanePulse/GSeal/internal/cli.Version=1.2.3".
var Version = "dev"

func (a *app) run(args []string) (int, error) {
	if len(args) == 1 && args[0] == "--version" {
		fmt.Fprintln(a.stdout, msg.Text(msg.VersionLine, Version))
		return ExitOK, nil
	}
	storeFlag := ""
	for len(args) > 0 {
		if args[0] == "--store" {
			if len(args) < 2 || args[1] == "" {
				return ExitUsage, msg.Errorf(msg.MissingArg, "--store")
			}
			storeFlag, args = args[1], args[2:]
			continue
		}
		if v, ok := strings.CutPrefix(args[0], "--store="); ok {
			if v == "" {
				return ExitUsage, msg.Errorf(msg.MissingArg, "--store")
			}
			storeFlag, args = v, args[1:]
			continue
		}
		break
	}
	cfg, err := config.Load()
	if err != nil {
		if len(args) > 0 && (args[0] == "doctor" || args[0] == "--doctor") {
			safe := msg.Text(msg.CfgSafeFile, config.File(), msg.Text(msg.CfgKindRead, ""))
			var ce *config.Error
			if errors.As(err, &ce) {
				safe = ce.Safe()
			}
			fmt.Fprintln(a.stdout, msg.Text(msg.DocFail, msg.Text(msg.DocConfigBad, safe)))
			fmt.Fprintln(a.stdout, msg.Text(msg.DocSummary, 0, 0, 1))
			return ExitFail, nil
		}
		return ExitUsage, err
	}
	a.cfg = cfg
	a.plain = policy.NewPlain(cfg.RedactPlain)
	cmd := ""
	if len(args) > 0 {
		cmd = args[0]
	}
	loc, err := config.Resolve(storeFlag, cfg, cmd == "--init")
	a.loc = loc
	if err != nil {
		if cmd == "--where" {
			a.where(false)
		}
		return ExitUsage, err
	}
	a.st = store.Open(loc.Root, keys.Default())
	switch {
	case cmd == "--where":
		a.where(true)
		return ExitOK, nil
	case cmd == "--list":
		target := ""
		if len(args) > 1 {
			target = args[1]
		}
		lines, err := a.listView(target)
		if err != nil {
			return ExitUsage, err
		}
		fmt.Fprintln(a.stdout, strings.Join(lines, "\n"))
		return ExitOK, nil
	case cmd == "--policy":
		target := ""
		if len(args) > 1 {
			target = args[1]
		}
		return a.policyView(target)
	case admin.Commands[cmd]:
		if !admin.ReadOnly[cmd] {
			if err := a.st.CheckWritable(); err != nil {
				return ExitFail, err
			}
		}
		ad := &admin.Admin{St: a.st, Cfg: a.cfg, Plain: a.plain, Stdout: a.stdout, Stderr: a.stderr, Where: a.loc.Describe(a.cfg)}
		return ad.Run(cmd, args[1:]), nil
	}
	return a.inject(args)
}

func (a *app) where(ok bool) {
	fmt.Fprintln(a.stdout, msg.Text(msg.WhereStore, a.loc.Root, a.loc.Describe(a.cfg)))
	if a.cfg.Present {
		fmt.Fprintln(a.stdout, msg.Text(msg.WhereConfig, a.cfg.Path))
	} else {
		fmt.Fprintln(a.stdout, msg.Text(msg.WhereConfigNone, a.cfg.Path))
	}
	if !ok {
		return
	}
	v, err := a.st.FormatVersion()
	switch {
	case err != nil:
		fmt.Fprintln(a.stdout, err.Error())
	case v > store.Version:
		fmt.Fprintln(a.stdout, msg.Text(msg.WhereVersionNew, v, store.Version))
	default:
		fmt.Fprintln(a.stdout, msg.Text(msg.WhereVersion, v))
	}
}

// warn prints a line to stderr with the program prefix.
func (a *app) warn(text string) { fmt.Fprintln(a.stderr, msg.Prefix+text) }

// now is replaceable in tests.
var now = time.Now
