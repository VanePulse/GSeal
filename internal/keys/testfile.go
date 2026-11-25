//go:build gsealtest

package keys

import (
	"encoding/base64"
	"encoding/json"
	"os"

	"github.com/VanePulse/GSeal/internal/msg"
)

// Default returns the key backend of a test build: systemd-creds, or the
// testfile backend when GSEAL_TEST_BACKEND=testfile.
func Default() Backend {
	if os.Getenv("GSEAL_TEST_BACKEND") == "testfile" {
		return TestFile{}
	}
	return SystemdCreds{}
}

// TestFile keeps the secret in a plain mode-600 JSON file, bound only to its
// credential name. It exists only in gsealtest builds, so the store logic can
// be tested where systemd-creds --user is not available. Never secure.
type TestFile struct{}

type testFileCred struct {
	Backend string `json:"backend"`
	Name    string `json:"name"`
	Secret  string `json:"secret"`
}

func detectTest(file string) (Backend, bool) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, false
	}
	var c testFileCred
	if json.Unmarshal(b, &c) == nil && c.Backend == "testfile" {
		return TestFile{}, true
	}
	return nil, false
}

func byNameTest(name string) (Backend, bool) {
	if name == "testfile" {
		return TestFile{}, true
	}
	return nil, false
}

// Name implements Backend.
func (TestFile) Name() string { return "testfile" }

// Wrap implements Backend.
func (TestFile) Wrap(name string, secret []byte, outFile string) error {
	b, _ := json.Marshal(testFileCred{"testfile", name, base64.StdEncoding.EncodeToString(secret)})
	f, err := os.OpenFile(outFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return msg.Errorf(msg.CredsEncrypt, err.Error())
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return msg.Errorf(msg.CredsEncrypt, err.Error())
	}
	return f.Close()
}

// Unwrap implements Backend.
func (TestFile) Unwrap(name, file string) ([]byte, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, msg.Errorf(msg.CredsDecrypt, err.Error())
	}
	var c testFileCred
	if err := json.Unmarshal(b, &c); err != nil || c.Backend != "testfile" {
		return nil, msg.Errorf(msg.CredsDecrypt, msg.Text(msg.TestCredBad))
	}
	if c.Name != name {
		return nil, msg.Errorf(msg.CredsDecrypt, msg.Text(msg.TestCredName))
	}
	return base64.StdEncoding.DecodeString(c.Secret)
}
