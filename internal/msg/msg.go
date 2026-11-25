// Package msg holds every user-visible text of with-secrets, keyed by a stable
// ID. Code never formats user-facing strings inline: it calls Text / Errorf
// with an ID. Tests match output by ID (Pattern), not by literal English, so
// wording can change without touching the tests.
package msg

import (
	"fmt"
	"regexp"
	"strings"
)

// Prefix starts every line written to stderr.
const Prefix = "with-secrets: "

// ID identifies one message.
type ID string

const (
	// usage and arguments
	Usage            ID = "usage"
	BadLogicalName   ID = "bad-logical-name"
	UnknownName      ID = "unknown-name"
	UnknownFile      ID = "unknown-file"
	Available        ID = "available"
	NoneAvailable    ID = "none-available"
	InvalidFacility  ID = "invalid-facility"
	BadKeyVar        ID = "bad-key-var"
	ReservedPrefix   ID = "reserved-prefix"
	KeysClash        ID = "keys-clash"
	VarClash         ID = "var-clash"
	UnsupportedShell ID = "unsupported-shell"
	StartFailed      ID = "start-failed"
	MissingArg       ID = "missing-arg"
	NotYet           ID = "not-yet"

	// store location and config
	StoreMissing     ID = "store-missing"
	StoreNotStore    ID = "store-not-store"
	StoreNotAbs      ID = "store-not-abs"
	DefaultMissing   ID = "default-missing"
	ConfigRead       ID = "config-read"
	ConfigSyntax     ID = "config-syntax"
	ConfigUnknownSec ID = "config-unknown-section"
	ConfigUnknownKey ID = "config-unknown-key"
	ConfigDupKey     ID = "config-dup-key"
	ConfigBadValue   ID = "config-bad-value"
	ConfigBadSpec    ID = "config-bad-spec"
	ReasonEmpty      ID = "reason-empty"
	ReasonNotAbs     ID = "reason-not-abs"
	ReasonNotWord    ID = "reason-not-word"
	ReasonNotBool    ID = "reason-not-bool"
	ReasonBadToken   ID = "reason-bad-token"
	StoreVersionNew  ID = "store-version-new"
	StoreVersionBad  ID = "store-version-bad"
	WhereStore       ID = "where-store"
	WhereConfig      ID = "where-config"
	WhereConfigNone  ID = "where-config-none"
	WhereVersion     ID = "where-version"
	WhereVersionNew  ID = "where-version-new"

	// data key and decryption
	DataKeyMissing  ID = "datakey-missing"
	DataKeyUnwrap   ID = "datakey-unwrap"
	DataKeyLength   ID = "datakey-length"
	DecryptFailed   ID = "decrypt-failed"
	CredsEncrypt    ID = "creds-encrypt"
	CredsDecrypt    ID = "creds-decrypt"
	AuditWriteError ID = "audit-write"
	AuditNotOwned   ID = "audit-not-owned"

	// --list
	ListNone       ID = "list-none"
	ListFileHint   ID = "list-file-hint"
	ListNodes      ID = "list-nodes"
	ListNodeHint   ID = "list-node-hint"
	ListVars       ID = "list-vars"
	ListHidden     ID = "list-hidden"
	ListHiddenNote ID = "list-hidden-note"

	// --policy
	PolicyHeader    ID = "policy-header"
	PolicySrcConfig ID = "policy-src-config"
	PolicySrcFile   ID = "policy-src-file"
	PolicyAll       ID = "policy-all"
	PolicyRow       ID = "policy-row"
	PolicyWant      ID = "policy-want"
	PolicyPlain     ID = "policy-plain"
	PolicyStoredEnc ID = "policy-stored-enc"
	PolicyStoredPln ID = "policy-stored-plain"
	PolicyMismatch  ID = "policy-mismatch"
	PolicySummary   ID = "policy-summary"
	PolicySecIgnore ID = "policy-section-ignored"
	PolicyBad       ID = "policy-bad"
)

var table = map[ID]string{
	Usage: "usage: with-secrets [--store <dir>] <facility.section> [...] -- <command...>\n" +
		"       with-secrets [--store <dir>] --list [<file>[.<node>]]\n" +
		"       with-secrets [--store <dir>] --where | --policy [<file>]\n" +
		"       with-secrets --init | --new <file> | --export <file> | --import <file>\n" +
		"       with-secrets --backup [<dir>] [--new-password] | --restore <bundle> | --undo-restore | --verify-backup <bundle>\n" +
		"       with-secrets --set <file>.<node> <KEY> [--create] | --apply-policy [--dry-run] [--allow-decrypt]\n" +
		"       with-secrets --rotate-datakey | doctor | --init [--backend systemd-creds|passphrase] | --version",
	BadLogicalName:   "logical name must be <facility>.<section>: %s",
	UnknownName:      "unknown logical name: %s",
	UnknownFile:      "unknown file: %s",
	Available:        "available:",
	NoneAvailable:    "(none)",
	InvalidFacility:  "invalid facility name: %s",
	BadKeyVar:        "%s: key %s does not form a valid variable name (%s)",
	ReservedPrefix:   "%s: variable %s uses the reserved %s prefix",
	KeysClash:        "%s: keys %s and %s both map to %s (names are upper-cased)",
	VarClash:         "variable %s produced by both %s and %s",
	UnsupportedShell: "unsupported WITH_SECRETS_SHELL: %s (only bash is supported)",
	StartFailed:      "failed to start %s: %s",
	MissingArg:       "%s needs an argument",
	NotYet:           "%s is not available in this build yet",

	StoreMissing:     "store not found: %s (from %s)",
	StoreNotStore:    "not a with-secrets store (no env/ directory): %s (from %s)",
	StoreNotAbs:      "store path must be absolute: %s (from %s)",
	DefaultMissing:   "no store configured and the default store does not exist: %s\nrun with-secrets --init to create it, or point to a store with --store <dir>, GSEAL_STORE or [store] path in %s",
	ConfigRead:       "cannot read config %s: %s",
	ConfigSyntax:     "config %s line %d: cannot parse: %s",
	ConfigUnknownSec: "config %s line %d: unknown section [%s]",
	ConfigUnknownKey: "config %s line %d: unknown key %s in [%s]",
	ConfigDupKey:     "config %s line %d: %s set twice in [%s]",
	ConfigBadValue:   "config %s line %d: invalid value for %s: %s",
	ConfigBadSpec:    "config %s: invalid [encrypt] keys: %s",
	ReasonEmpty:      "empty",
	ReasonNotAbs:     "must be an absolute path",
	ReasonNotWord:    "not a key name: %s",
	ReasonNotBool:    "expected true or false",
	ReasonBadToken:   "not a key name or pattern: %s",
	StoreVersionNew:  "store format version %d is newer than this build supports (%d); upgrade with-secrets before changing this store",
	StoreVersionBad:  "store format version file is unreadable: %s",
	WhereStore:       "store:          %s  (from %s)",
	WhereConfig:      "config:         %s",
	WhereConfigNone:  "config:         %s  (not present, defaults in use)",
	WhereVersion:     "store version:  %d",
	WhereVersionNew:  "store version:  %d  (newer than supported %d: read-only)",

	DataKeyMissing:  "data key not found: run with-secrets --init on first use, or with-secrets --restore <bundle> on a new machine",
	DataKeyUnwrap:   "cannot unwrap the data key (different machine or user? with-secrets --restore <bundle> recovers): %s",
	DataKeyLength:   "data key has the wrong length",
	DecryptFailed:   "cannot decrypt %s.ini [%s] %s (ciphertext damaged or moved to another key)",
	CredsEncrypt:    "systemd-creds encrypt failed: %s",
	CredsDecrypt:    "systemd-creds decrypt failed: %s",
	AuditWriteError: "audit log write failed: %s",
	AuditNotOwned:   "audit log is not owned by the current user",

	ListNone:       "(no credentials defined)",
	ListFileHint:   "Nodes of a file: with-secrets --list <file>",
	ListNodes:      "Nodes:",
	ListNodeHint:   "Node details: with-secrets --list %s.<node>",
	ListVars:       "Variables:",
	ListHidden:     "(description hidden)",
	ListHiddenNote: "Note: the store cannot be fully decrypted, so descriptions may contain secrets that cannot be reliably masked; all are hidden. Reason: %s",

	PolicyHeader:    "%s  encrypt: %s  (%s)",
	PolicySrcConfig: "from config",
	PolicySrcFile:   "@encrypt in the file",
	PolicyAll:       "all keys",
	PolicyRow:       "  %s  %s  %s  %s",
	PolicyWant:      "encrypt",
	PolicyPlain:     "plain",
	PolicyStoredEnc: "stored encrypted",
	PolicyStoredPln: "stored plain",
	PolicyMismatch:  "<- differs",
	PolicySummary:   "%d value(s) would be encrypted, %d would be decrypted (run with-secrets --apply-policy to change the store)",
	PolicySecIgnore: "  note: @encrypt inside [%s] is ignored (only file-level @encrypt applies)",
	PolicyBad:       "%s.ini: invalid @encrypt: %s",
}

// Text formats message id with args.
func Text(id ID, args ...any) string {
	f, ok := table[id]
	if !ok {
		panic("msg: unknown id " + string(id))
	}
	if len(args) == 0 {
		return f
	}
	return fmt.Sprintf(f, args...)
}

// Error is a user-facing error carrying its message ID, so callers (audit
// categories, tests) can tell errors apart without parsing text.
type Error struct {
	ID   ID
	Text string
}

func (e *Error) Error() string { return e.Text }

// Errorf builds an *Error for id.
func Errorf(id ID, args ...any) *Error { return &Error{ID: id, Text: Text(id, args...)} }

// IDOf returns the message ID of err if it is (or wraps) an *Error.
func IDOf(err error) ID {
	for err != nil {
		if e, ok := err.(*Error); ok {
			return e.ID
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return ""
		}
		err = u.Unwrap()
	}
	return ""
}

var verb = regexp.MustCompile(`%(?:\[\d+\])?[-+# 0-9.]*[sdvq]`)

// Pattern returns a regular expression matching message id with any
// arguments: literal text is quoted, each formatting verb matches anything
// (non-greedy, may span lines).
func Pattern(id ID) *regexp.Regexp {
	f := Text(id)
	var b strings.Builder
	last := 0
	for _, loc := range verb.FindAllStringIndex(f, -1) {
		b.WriteString(regexp.QuoteMeta(f[last:loc[0]]))
		b.WriteString(`(?s:.*?)`)
		last = loc[1]
	}
	b.WriteString(regexp.QuoteMeta(f[last:]))
	return regexp.MustCompile(b.String())
}

// IDs returns all message IDs (for tests that check the table).
func IDs() []ID {
	out := make([]ID, 0, len(table))
	for id := range table {
		out = append(out, id)
	}
	return out
}
