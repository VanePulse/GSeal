// Package store gives access to a credential store: env/<facility>.ini files
// (the single source of truth), the wrapped data key, and decryption of
// ENC:v1: values.
//
// Layout (unchanged from VaneSecret):
//
//	<root>/env/<facility>.ini   credentials and their docs
//	<root>/env/.datakey.cred    data key wrapped by the key backend
//	<root>/env/.store-version   store format version (absent = 1)
//	<root>/logs/audit.log       audit records
package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/VanePulse/GSeal/internal/ini"
	"github.com/VanePulse/GSeal/internal/keys"
	"github.com/VanePulse/GSeal/internal/msg"
)

// Version is the store format version this build writes and understands.
const Version = 1

// NameRe is a legal facility or section name.
var NameRe = regexp.MustCompile(`^[\w-]+$`)

// Store is an opened store.
type Store struct {
	Root    string
	Env     string
	Logs    string
	Backend keys.Backend // for new keys (see KeyBackend)

	dataKey []byte
}

// Open returns the store at root (not checked; config.Resolve checks).
func Open(root string, b keys.Backend) *Store {
	return &Store{Root: root, Env: filepath.Join(root, "env"), Logs: filepath.Join(root, "logs"), Backend: b}
}

// DataKeyFile is the wrapped data key.
func (s *Store) DataKeyFile() string { return filepath.Join(s.Env, ".datakey.cred") }

// KeyBackend is the backend of the store's keys: the one that wrote the data
// key, or Backend (the default for new keys) when there is none yet.
func (s *Store) KeyBackend() keys.Backend { return keys.Detect(s.DataKeyFile(), s.Backend) }

// FormatVersion reads env/.store-version (absent = 1).
func (s *Store) FormatVersion() (int, error) {
	b, err := os.ReadFile(filepath.Join(s.Env, ".store-version"))
	if errors.Is(err, os.ErrNotExist) {
		return 1, nil
	}
	if err != nil {
		return 0, msg.Errorf(msg.StoreVersionBad, err.Error())
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || v < 1 {
		return 0, msg.Errorf(msg.StoreVersionBad, strings.TrimSpace(string(b)))
	}
	return v, nil
}

// CheckWritable fails when the store format is newer than this build.
func (s *Store) CheckWritable() error {
	v, err := s.FormatVersion()
	if err != nil {
		return err
	}
	if v > Version {
		return msg.Errorf(msg.StoreVersionNew, v, Version)
	}
	return nil
}

// Facilities lists the facility names (env/*.ini), sorted. A missing env/
// is an empty store; any other failure to list it is an error (never "no
// files": callers rewrite or snapshot every file they are given).
func (s *Store) Facilities() ([]string, error) {
	ents, err := os.ReadDir(s.Env)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, msg.Errorf(msg.ListEnvFailed, s.Env, ReadReason(err))
	}
	var out []string
	for _, e := range ents {
		n := e.Name()
		if strings.HasSuffix(n, ".ini") && !e.IsDir() {
			out = append(out, strings.TrimSuffix(n, ".ini"))
		}
	}
	sort.Strings(out)
	return out, nil
}

// ReadReason is the category of a file system error (no paths, no content).
func ReadReason(err error) string {
	switch {
	case errors.Is(err, os.ErrNotExist):
		return msg.Text(msg.ReasonMissing)
	case errors.Is(err, os.ErrPermission):
		return msg.Text(msg.ReasonPerm)
	}
	return msg.Text(msg.ReasonReadErr)
}

// Load parses env/<facility>.ini. A missing file returns (nil, nil).
func (s *Store) Load(facility string) (*ini.File, error) {
	if !NameRe.MatchString(facility) {
		return nil, msg.Errorf(msg.InvalidFacility, facility)
	}
	b, err := os.ReadFile(filepath.Join(s.Env, facility+".ini"))
	if err != nil {
		return nil, nil
	}
	return ini.Parse(string(b)), nil
}

// ---------------------------------------------------------------- crypto ----

// EncPrefix marks an encrypted value.
const EncPrefix = "ENC:v1:"

// IsEnc reports whether a stored value is encrypted.
func IsEnc(v string) bool { return strings.HasPrefix(v, EncPrefix) }

func aad(fac, sec, key string) []byte {
	return []byte("with-secrets\x00" + fac + "\x00" + sec + "\x00" + key)
}

// Encrypt seals plain for facility/section/key: AES-256-GCM, random nonce,
// AAD bound to the location, so a ciphertext cannot be moved to another key.
func Encrypt(dataKey []byte, fac, sec, key, plain string) (string, error) {
	gcm, err := newGCM(dataKey)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nil, nonce, []byte(plain), aad(fac, sec, key))
	return EncPrefix + base64.RawURLEncoding.EncodeToString(append(nonce, ct...)), nil
}

// ErrDecrypt is returned when a ciphertext does not open.
var ErrDecrypt = errors.New("decrypt failed")

// Decrypt opens a stored ENC:v1: value.
func Decrypt(dataKey []byte, fac, sec, key, stored string) (string, error) {
	b64 := strings.TrimRight(strings.TrimPrefix(stored, EncPrefix), "=")
	buf, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil || len(buf) < 28 {
		return "", ErrDecrypt
	}
	gcm, err := newGCM(dataKey)
	if err != nil {
		return "", err
	}
	pt, err := gcm.Open(nil, buf[:12], buf[12:], aad(fac, sec, key))
	if err != nil {
		return "", ErrDecrypt
	}
	return string(pt), nil
}

func newGCM(k []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// DataKey returns the data key, unwrapped once per process.
func (s *Store) DataKey() ([]byte, error) {
	if s.dataKey != nil {
		return s.dataKey, nil
	}
	if _, err := os.Stat(s.DataKeyFile()); err != nil {
		return nil, msg.Errorf(msg.DataKeyMissing)
	}
	k, err := s.KeyBackend().Unwrap(keys.DataKeyName, s.DataKeyFile())
	if err != nil {
		return nil, msg.Errorf(msg.DataKeyUnwrap, err.Error())
	}
	if len(k) != 32 {
		return nil, msg.Errorf(msg.DataKeyLength)
	}
	s.dataKey = k
	return k, nil
}

// ForgetDataKey drops the cached data key (after it was replaced).
func (s *Store) ForgetDataKey() { s.dataKey = nil }

// Value is a stored value after decryption.
type Value struct {
	Plain     string
	Encrypted bool // stored as ENC:v1:
}

// Values holds decrypted values per section, in file order.
type Values struct {
	Names []string
	Sec   map[string][]KV
}

// KV is one key and its value.
type KV struct {
	Key string
	Value
}

// DecryptRaw decrypts every section as written (incl. DEFAULT, not merged).
func (s *Store) DecryptRaw(fac string, f *ini.File) (*Values, error) {
	out := &Values{Sec: map[string][]KV{}}
	for _, sec := range f.Raw.Names() {
		m, _ := f.Raw.Get(sec)
		out.Names = append(out.Names, sec)
		for _, k := range m.Keys() {
			v, _ := m.Get(k)
			if !IsEnc(v) {
				out.Sec[sec] = append(out.Sec[sec], KV{k, Value{v, false}})
				continue
			}
			dk, err := s.DataKey()
			if err != nil {
				return nil, err
			}
			p, err := Decrypt(dk, fac, sec, k, v)
			if err != nil {
				return nil, msg.Errorf(msg.DecryptFailed, fac, sec, k)
			}
			out.Sec[sec] = append(out.Sec[sec], KV{k, Value{p, true}})
		}
		if out.Sec[sec] == nil {
			out.Sec[sec] = []KV{}
		}
	}
	return out, nil
}

// Section returns the decrypted, DEFAULT-merged keys of one section.
func (s *Store) Section(fac string, f *ini.File, sec string) ([]KV, error) {
	raw, err := s.DecryptRaw(fac, f)
	if err != nil {
		return nil, err
	}
	var out []KV
	idx := map[string]int{}
	add := func(kvs []KV) {
		for _, kv := range kvs {
			if i, ok := idx[kv.Key]; ok {
				out[i] = kv
				continue
			}
			idx[kv.Key] = len(out)
			out = append(out, kv)
		}
	}
	add(raw.Sec["DEFAULT"])
	add(raw.Sec[sec])
	return out, nil
}

// HasEnc reports whether a parsed file holds any encrypted value.
func HasEnc(f *ini.File) bool {
	for _, sec := range f.Raw.Names() {
		m, _ := f.Raw.Get(sec)
		for _, k := range m.Keys() {
			if v, _ := m.Get(k); IsEnc(v) {
				return true
			}
		}
	}
	return false
}
