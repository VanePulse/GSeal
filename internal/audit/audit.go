// Package audit appends one JSON line per injection call to logs/audit.log.
//
// Every string in a record is masked (same rules as the output) before JSON
// escaping, so values containing " or \ still match. The log is opened with
// O_NOFOLLOW, refused when not owned by the current user, and forced to 0600
// before writing, also when it already existed with wider permissions.
package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"

	"github.com/VanePulse/GSeal/internal/msg"
	"github.com/VanePulse/GSeal/internal/redact"
)

// Record is one audit line. Cmd is nil when the command could not be masked
// (the call failed before the secrets were known); CmdChars then holds its
// length.
type Record struct {
	TS           string   `json:"ts"`
	Names        []string `json:"names"`
	Shell        string   `json:"shell"`
	Cmd          *string  `json:"cmd"`
	Cwd          string   `json:"cwd"`
	Exit         int      `json:"exit"`
	Error        string   `json:"error,omitempty"`
	MS           int64    `json:"ms"`
	UnknownNames int      `json:"unknownNames,omitempty"`
	CmdChars     *int     `json:"cmdChars,omitempty"`
}

// Write appends rec to <logs>/audit.log. Problems are returned, not fatal.
func Write(logs string, rec Record, patterns []string) error {
	mask := func(s string) string { return redact.All(s, patterns, nil) }
	rec.TS, rec.Shell, rec.Cwd, rec.Error = mask(rec.TS), mask(rec.Shell), mask(rec.Cwd), mask(rec.Error)
	names := make([]string, len(rec.Names))
	for i, n := range rec.Names {
		names[i] = mask(n)
	}
	rec.Names = names
	if rec.Cmd != nil {
		c := mask(*rec.Cmd)
		rec.Cmd = &c
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(rec); err != nil {
		return err
	}
	if err := os.MkdirAll(logs, 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(logs, "audit.log"), os.O_WRONLY|os.O_APPEND|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && int(sys.Uid) != os.Getuid() {
		return msg.Errorf(msg.AuditNotOwned)
	}
	if st.Mode().Perm() != 0o600 {
		if err := f.Chmod(0o600); err != nil {
			return err
		}
	}
	_, err = f.Write(buf.Bytes())
	return err
}
