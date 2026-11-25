// Package config reads the user configuration (INI) and resolves the store
// location. Nothing here hard-codes a store path: the store comes from, in
// order, --store, GSEAL_STORE, WITH_SECRETS_ROOT, [store] path in the config,
// or the default ~/.local/share/gseal (fixed: XDG_DATA_HOME is not consulted).
//
// "No guessing": the first source that is set decides. If it does not point
// to a store, that is an error; the next source is never tried.
package config

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/VanePulse/GSeal/internal/ini"
	"github.com/VanePulse/GSeal/internal/msg"
)

// Config is the parsed configuration. Unset fields keep their defaults.
type Config struct {
	Path    string // file it was read from
	Present bool   // the file exists

	StorePath string

	Encrypt    string // [encrypt] keys
	EncryptSet bool

	RedactPlain    []string // [redact] plain
	RedactPlainSet bool

	BackupDir string

	AuditEnabled bool
}

// Defaults.
var DefaultPlain = []string{"HOST", "PORT", "DB", "DATABASE", "USER", "USERNAME", "NAME", "SCHEMA", "ENDPOINT", "BUCKET", "BUCKETNAME"}

var schema = map[string][]string{
	"store":   {"path"},
	"encrypt": {"keys"},
	"redact":  {"plain"},
	"backup":  {"dir"},
	"audit":   {"enabled"},
}

// File returns the config file location: GSEAL_CONFIG, else
// $XDG_CONFIG_HOME/gseal/config.ini, else ~/.config/gseal/config.ini.
func File() string {
	if p := os.Getenv("GSEAL_CONFIG"); p != "" {
		return p
	}
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" || !filepath.IsAbs(base) {
		base = filepath.Join(home(), ".config")
	}
	return filepath.Join(base, "gseal", "config.ini")
}

// DefaultStore is the store used when no source is set: ~/.local/share/gseal.
func DefaultStore() string { return filepath.Join(home(), ".local", "share", "gseal") }

func home() string {
	if h, err := os.UserHomeDir(); err == nil {
		return h
	}
	return "/"
}

var (
	sectionRe = regexp.MustCompile(`^\[([^\]]+)\]$`)
	keyRe     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	wordRe    = regexp.MustCompile(`^[A-Za-z0-9_]+$`)
)

// Error is a config error. Error() is the full message (may quote the
// offending text); Safe() names only the file, the line, a known field name
// and the kind of problem, never text from the file (for doctor).
type Error struct {
	full  *msg.Error
	Path  string
	Line  int    // 0: the file as a whole
	Kind  msg.ID // one of the CfgKind* messages
	Field string // known schema name ("[backup]", "redact.plain"), or ""
}

func (e *Error) Error() string { return e.full.Error() }

// Unwrap gives the full message (and its ID) to msg.IDOf.
func (e *Error) Unwrap() error { return e.full }

// Safe is the message without any text taken from the file.
func (e *Error) Safe() string {
	if e.Line == 0 {
		return msg.Text(msg.CfgSafeFile, e.Path, msg.Text(e.Kind, e.Field))
	}
	return msg.Text(msg.CfgSafeLine, e.Path, e.Line, msg.Text(e.Kind, e.Field))
}

// Load reads the config file. A missing file is not an error (defaults).
func Load() (*Config, error) {
	c := &Config{Path: File(), AuditEnabled: true, RedactPlain: DefaultPlain}
	data, err := os.ReadFile(c.Path)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return nil, &Error{msg.Errorf(msg.ConfigRead, c.Path, err.Error()), c.Path, 0, msg.CfgKindRead, ""}
	}
	c.Present = true
	cur := ""
	seen := map[string]bool{}
	text := strings.TrimPrefix(string(data), "\uFEFF")
	for i, raw := range regexp.MustCompile(`\r?\n`).Split(text, -1) {
		n := i + 1
		line := ini.Trim(raw)
		if line == "" || line[0] == ';' || line[0] == '#' {
			continue
		}
		if s := sectionRe.FindStringSubmatch(line); s != nil {
			cur = strings.ToLower(ini.Trim(s[1]))
			if _, ok := schema[cur]; !ok {
				return nil, &Error{msg.Errorf(msg.ConfigUnknownSec, c.Path, n, ini.Trim(s[1])), c.Path, n, msg.CfgKindUnknownSec, ""}
			}
			continue
		}
		eq := strings.Index(line, "=")
		if eq < 0 || cur == "" {
			return nil, &Error{msg.Errorf(msg.ConfigSyntax, c.Path, n, line), c.Path, n, msg.CfgKindSyntax, ""}
		}
		key := strings.ToLower(ini.Trim(line[:eq]))
		if !keyRe.MatchString(key) || !contains(schema[cur], key) {
			return nil, &Error{msg.Errorf(msg.ConfigUnknownKey, c.Path, n, ini.Trim(line[:eq]), cur), c.Path, n, msg.CfgKindUnknownKey, "[" + cur + "]"}
		}
		if seen[cur+"."+key] {
			return nil, &Error{msg.Errorf(msg.ConfigDupKey, c.Path, n, key, cur), c.Path, n, msg.CfgKindDup, cur + "." + key}
		}
		seen[cur+"."+key] = true
		val := ini.ParseValue(ini.Trim(line[eq+1:]))
		bad := func(why msg.ID, args ...any) error {
			return &Error{msg.Errorf(msg.ConfigBadValue, c.Path, n, cur+"."+key, msg.Text(why, args...)), c.Path, n, msg.CfgKindBadValue, cur + "." + key}
		}
		switch cur + "." + key {
		case "store.path":
			if val == "" {
				return nil, bad(msg.ReasonEmpty)
			}
			c.StorePath = expandHome(val)
			if !filepath.IsAbs(c.StorePath) {
				return nil, bad(msg.ReasonNotAbs)
			}
		case "encrypt.keys":
			c.Encrypt, c.EncryptSet = val, true
		case "redact.plain":
			var words []string
			for _, w := range strings.Split(val, ",") {
				if w = ini.Trim(w); w == "" {
					continue
				}
				if !wordRe.MatchString(w) {
					return nil, bad(msg.ReasonNotWord, w)
				}
				words = append(words, strings.ToUpper(w))
			}
			c.RedactPlain, c.RedactPlainSet = words, true
		case "backup.dir":
			c.BackupDir = expandHome(val)
			if c.BackupDir != "" && !filepath.IsAbs(c.BackupDir) {
				return nil, bad(msg.ReasonNotAbs)
			}
		case "audit.enabled":
			switch strings.ToLower(val) {
			case "true", "yes", "on", "1":
				c.AuditEnabled = true
			case "false", "no", "off", "0":
				c.AuditEnabled = false
			default:
				return nil, bad(msg.ReasonNotBool)
			}
		}
	}
	return c, nil
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func expandHome(p string) string {
	if p == "~" {
		return home()
	}
	if strings.HasPrefix(p, "~/") {
		return filepath.Join(home(), p[2:])
	}
	return p
}

// Source names where the store location came from.
const (
	SrcFlag    = "--store"
	SrcEnv     = "GSEAL_STORE"
	SrcLegacy  = "WITH_SECRETS_ROOT"
	SrcConfig  = "config"
	SrcDefault = "default"
)

// Location is a resolved store location.
type Location struct {
	Root   string
	Source string // one of the Src* names; config carries the file
}

// Describe returns the source for messages ("config /path" for the config).
func (l Location) Describe(c *Config) string {
	if l.Source == SrcConfig {
		return SrcConfig + " " + c.Path
	}
	return l.Source
}

// Resolve picks the store location. flag is the --store value ("" if absent).
// With allowMissing (for --init), a missing store directory is accepted.
func Resolve(flag string, c *Config, allowMissing bool) (Location, error) {
	var loc Location
	switch {
	case flag != "":
		loc = Location{flag, SrcFlag}
	case os.Getenv("GSEAL_STORE") != "":
		loc = Location{os.Getenv("GSEAL_STORE"), SrcEnv}
	case os.Getenv("WITH_SECRETS_ROOT") != "":
		loc = Location{os.Getenv("WITH_SECRETS_ROOT"), SrcLegacy}
	case c.StorePath != "":
		loc = Location{c.StorePath, SrcConfig}
	default:
		loc = Location{DefaultStore(), SrcDefault}
	}
	if loc.Source == SrcConfig && !filepath.IsAbs(loc.Root) {
		return loc, msg.Errorf(msg.StoreNotAbs, loc.Root, loc.Describe(c))
	}
	if abs, err := filepath.Abs(loc.Root); err == nil {
		loc.Root = abs
	}
	st, err := os.Stat(loc.Root)
	if err != nil || !st.IsDir() {
		if allowMissing && errors.Is(err, os.ErrNotExist) {
			return loc, nil
		}
		if loc.Source == SrcDefault {
			return loc, msg.Errorf(msg.DefaultMissing, loc.Root, c.Path)
		}
		return loc, msg.Errorf(msg.StoreMissing, loc.Root, loc.Describe(c))
	}
	if st, err := os.Stat(filepath.Join(loc.Root, "env")); err != nil || !st.IsDir() {
		if allowMissing && errors.Is(err, os.ErrNotExist) {
			return loc, nil
		}
		return loc, msg.Errorf(msg.StoreNotStore, loc.Root, loc.Describe(c))
	}
	return loc, nil
}
