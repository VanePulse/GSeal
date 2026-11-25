package keys

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"

	"golang.org/x/crypto/scrypt"

	"github.com/VanePulse/GSeal/internal/msg"
	"github.com/VanePulse/GSeal/internal/norm"
	"github.com/VanePulse/GSeal/internal/tty"
)

// Passphrase wraps secrets with a key derived from a store passphrase
// (scrypt(NFC(passphrase)), AES-256-GCM), for machines without
// systemd-creds. The passphrase is asked on /dev/tty whenever a secret is
// unwrapped (once per process).
//
// File format:  "GSPW1\n" | header JSON "\n" | nonce(12) | ciphertext | tag(16)
// with AAD = magic + header line; the header holds the kdf parameters and the
// credential name, so a file cannot be used under another name.
type Passphrase struct {
	// Ref is a passphrase credential of this store (the data key file). A
	// new credential is wrapped with the passphrase that opens Ref; if Ref
	// does not exist, a new store passphrase is asked for (twice).
	Ref string
}

var pwMagic = []byte("GSPW1\n")

type pwHeader struct {
	V    int    `json:"v"`
	KDF  string `json:"kdf"`
	Salt string `json:"salt"`
	N    int    `json:"N"`
	R    int    `json:"r"`
	P    int    `json:"p"`
	Name string `json:"name"`
}

// kdf parameters (same as backup bundles).
const pwN, pwR, pwP = 1 << 17, 8, 1

// The store passphrase of this process, once known: salt -> derived key, and
// the salt used for new credentials.
var (
	pwKeys = map[string][]byte{}
	pwSalt string
)

// Name implements Backend.
func (Passphrase) Name() string { return "passphrase" }

// IsPassphraseFile reports whether file is a passphrase credential.
func IsPassphraseFile(file string) bool {
	f, err := os.Open(file)
	if err != nil {
		return false
	}
	defer f.Close()
	b := make([]byte, len(pwMagic))
	n, _ := f.Read(b)
	return bytes.Equal(b[:n], pwMagic)
}

func pwDerive(pass, salt string, n, r, p int) ([]byte, error) {
	if n < 2 || n&(n-1) != 0 || r < 1 || p < 1 || p > 16 || 128*int64(n)*int64(r) > 512<<20 {
		return nil, msg.Errorf(msg.PassCredBad)
	}
	s, err := base64.StdEncoding.DecodeString(salt)
	if err != nil {
		return nil, msg.Errorf(msg.PassCredBad)
	}
	return scrypt.Key([]byte(norm.NFC(pass)), s, n, r, p, 32)
}

func pwRead(file string) (*pwHeader, []byte, []byte, error) {
	buf, err := os.ReadFile(file)
	if err != nil {
		return nil, nil, nil, err
	}
	if !bytes.HasPrefix(buf, pwMagic) {
		return nil, nil, nil, msg.Errorf(msg.PassCredBad)
	}
	end := bytes.IndexByte(buf[len(pwMagic):], '\n')
	if end < 0 {
		return nil, nil, nil, msg.Errorf(msg.PassCredBad)
	}
	end += len(pwMagic)
	var h pwHeader
	if json.Unmarshal(buf[len(pwMagic):end], &h) != nil || len(buf)-end-1 < 28 {
		return nil, nil, nil, msg.Errorf(msg.PassCredBad)
	}
	return &h, buf[:end+1], buf[end+1:], nil
}

func pwOpen(key, aad, body []byte) ([]byte, error) {
	g, err := gcmOf(key)
	if err != nil {
		return nil, err
	}
	return g.Open(nil, body[:12], body[12:], aad)
}

func gcmOf(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

// keyFor returns the derived key for a credential file, asking for the
// store passphrase if this process does not know it yet.
func keyFor(h *pwHeader, aad, body []byte) ([]byte, error) {
	if k, ok := pwKeys[h.Salt]; ok {
		return k, nil
	}
	ans, err := tty.Secrets(msg.Text(msg.PromptStorePass))
	if err != nil {
		return nil, err
	}
	k, err := pwDerive(ans[0], h.Salt, h.N, h.R, h.P)
	if err != nil {
		return nil, err
	}
	if _, err := pwOpen(k, aad, body); err != nil {
		return nil, msg.Errorf(msg.StorePassWrong)
	}
	pwKeys[h.Salt] = k
	if pwSalt == "" {
		pwSalt = h.Salt
	}
	return k, nil
}

// Unwrap implements Backend.
func (Passphrase) Unwrap(name, file string) ([]byte, error) {
	h, aad, body, err := pwRead(file)
	if err != nil {
		return nil, err
	}
	if h.Name != name {
		return nil, msg.Errorf(msg.PassCredName, name)
	}
	k, err := keyFor(h, aad, body)
	if err != nil {
		return nil, err
	}
	pt, err := pwOpen(k, aad, body)
	if err != nil {
		return nil, msg.Errorf(msg.StorePassWrong)
	}
	return pt, nil
}

// Wrap implements Backend.
func (p Passphrase) Wrap(name string, secret []byte, outFile string) error {
	if pwSalt == "" {
		if p.Ref != "" && IsPassphraseFile(p.Ref) {
			h, aad, body, err := pwRead(p.Ref)
			if err != nil {
				return err
			}
			if _, err := keyFor(h, aad, body); err != nil {
				return err
			}
			pwSalt = h.Salt
		} else {
			pass, err := tty.NewPassphrase(msg.PromptNewStorePass, msg.PromptAgain)
			if err != nil {
				return err
			}
			s := make([]byte, 16)
			if _, err := rand.Read(s); err != nil {
				return err
			}
			salt := base64.StdEncoding.EncodeToString(s)
			k, err := pwDerive(pass, salt, pwN, pwR, pwP)
			if err != nil {
				return err
			}
			pwKeys[salt], pwSalt = k, salt
		}
	}
	h, _ := json.Marshal(pwHeader{1, "scrypt", pwSalt, pwN, pwR, pwP, name})
	aad := append(append(append([]byte{}, pwMagic...), h...), '\n')
	g, err := gcmOf(pwKeys[pwSalt])
	if err != nil {
		return err
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	out := g.Seal(append(append([]byte{}, aad...), nonce...), nonce, secret, aad)
	f, err := os.OpenFile(outFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(out); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
