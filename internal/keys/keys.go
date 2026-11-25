// Package keys wraps and unwraps the store's keys. A Backend binds a secret
// to something outside the store (this machine and user, a passphrase, ...),
// so a copy of the store directory alone does not reveal it.
package keys

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/VanePulse/GSeal/internal/msg"
)

// Credential names (part of the store format; shared with VaneSecret).
const (
	DataKeyName   = "with-secrets-data"
	BackupKeyName = "with-secrets-backup"
)

// Backend wraps secrets into files and unwraps them.
type Backend interface {
	Name() string
	// Wrap writes the wrapped secret to outFile (callers publish atomically).
	Wrap(name string, secret []byte, outFile string) error
	// Unwrap returns the secret stored in file.
	Unwrap(name, file string) ([]byte, error)
}

// Detect returns the backend that wrote file, judged by its content:
// a passphrase credential, a testfile credential (test builds only), or
// otherwise systemd-creds (also every file written by VaneSecret). A missing
// file gives fallback.
func Detect(file string, fallback Backend) Backend {
	if _, err := os.Stat(file); err != nil {
		return fallback
	}
	if IsPassphraseFile(file) {
		return Passphrase{Ref: file}
	}
	if b, ok := detectTest(file); ok {
		return b
	}
	return SystemdCreds{}
}

// ByName returns the backend called name (systemd-creds, passphrase); ref is
// the store's data key file (see Passphrase.Ref).
func ByName(name, ref string) (Backend, error) {
	switch name {
	case "systemd-creds":
		return SystemdCreds{}, nil
	case "passphrase":
		return Passphrase{Ref: ref}, nil
	}
	if b, ok := byNameTest(name); ok {
		return b, nil
	}
	return nil, msg.Errorf(msg.UnknownBackend, name)
}

// SystemdCreds uses `systemd-creds --user`: bound to this machine's host key
// and this user's uid (like DPAPI on Windows). Any process of the same user
// can unwrap without a prompt.
type SystemdCreds struct {
	// Command is the systemd-creds executable (default "systemd-creds").
	Command string
}

func (s SystemdCreds) cmd() string {
	if s.Command != "" {
		return s.Command
	}
	return "systemd-creds"
}

// Name implements Backend.
func (SystemdCreds) Name() string { return "systemd-creds" }

// Wrap implements Backend.
func (s SystemdCreds) Wrap(name string, secret []byte, outFile string) error {
	c := exec.Command(s.cmd(), "encrypt", "--user", "--name="+name, "-", outFile)
	c.Stdin = bytes.NewReader(secret)
	var stderr bytes.Buffer
	c.Stderr = &stderr
	if err := c.Run(); err != nil {
		return msg.Errorf(msg.CredsEncrypt, detail(err, stderr.String()))
	}
	return nil
}

// Unwrap implements Backend.
func (s SystemdCreds) Unwrap(name, file string) ([]byte, error) {
	c := exec.Command(s.cmd(), "decrypt", "--user", "--name="+name, file, "-")
	var stdout, stderr bytes.Buffer
	c.Stdout, c.Stderr = &stdout, &stderr
	if err := c.Run(); err != nil {
		return nil, msg.Errorf(msg.CredsDecrypt, detail(err, stderr.String()))
	}
	return stdout.Bytes(), nil
}

func detail(err error, stderr string) string {
	if s := strings.TrimSpace(stderr); s != "" {
		return s
	}
	return fmt.Sprint(err)
}
