package admin

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/crypto/scrypt"

	"github.com/VanePulse/GSeal/internal/fault"
	"github.com/VanePulse/GSeal/internal/ini"
	"github.com/VanePulse/GSeal/internal/keys"
	"github.com/VanePulse/GSeal/internal/msg"
	"github.com/VanePulse/GSeal/internal/norm"
	"github.com/VanePulse/GSeal/internal/store"
)

// Backup bundle (WSBK1, same as VaneSecret):
//
//	"WSBK1\n" | header JSON "\n" | nonce(12) | ciphertext | tag(16)
//
// AES-256-GCM with AAD = magic + header line, so the header (kdf params,
// kind, body length) is authenticated. The key is scrypt(NFC(passphrase)).

var magic = []byte("WSBK1\n")

const (
	keepAuto   = 19 // rotating auto backups; the base backup is kept forever
	minPass    = 12
	scryptN    = 1 << 17
	scryptR    = 8
	scryptP    = 1
	scryptMem  = 512 << 20 // same limit as VaneSecret's maxmem
	kindBase   = "base"
	kindAuto   = "auto"
	kindManual = "manual"
)

var bundleName = regexp.MustCompile(`^secrets-(base|auto|manual)-\d{8}T\d+(-\d+)?\.wsbk$`)
var bundleTmp = regexp.MustCompile(`^\.secrets-.*\.wsbk\.tmp-`)

type header struct {
	V       int    `json:"v"`
	KDF     string `json:"kdf"`
	Salt    string `json:"salt"`
	N       int    `json:"N"`
	R       int    `json:"r"`
	P       int    `json:"p"`
	Kind    string `json:"kind"`
	Created string `json:"created"`
	Len     *int   `json:"len,omitempty"`
}

type payload struct {
	Created string            `json:"created"`
	Files   map[string]string `json:"files"`
	DataKey *string           `json:"datakey"`
}

// backupKey is the derived bundle key with its kdf parameters, stored wrapped
// in env/.backupkey.cred.
type backupKey struct {
	Salt string `json:"salt"`
	N    int    `json:"N"`
	R    int    `json:"r"`
	P    int    `json:"p"`
	Key  string `json:"key"`
}

func (k *backupKey) sameKDF(h *header) bool {
	return h.Salt == k.Salt && h.N == k.N && h.R == k.R && h.P == k.P
}

func decodeB64(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(strings.TrimRight(s, "="))
}

// derive returns scrypt(NFC(pass), salt, N, r, p, 32).
func derive(pass, salt string, n, r, p int) ([]byte, error) {
	if n < 2 || n&(n-1) != 0 || r < 1 || p < 1 || p > 16 || 128*int64(n)*int64(r) > scryptMem {
		return nil, msg.Errorf(msg.BundleKDFBad)
	}
	s, err := decodeB64(salt)
	if err != nil {
		return nil, msg.Errorf(msg.BundleHeaderBad)
	}
	return scrypt.Key([]byte(norm.NFC(pass)), s, n, r, p, 32)
}

func makeBackupKey(pass, salt string, n, r, p int) (*backupKey, error) {
	if salt == "" {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		salt = base64.StdEncoding.EncodeToString(b)
	}
	k, err := derive(pass, salt, n, r, p)
	if err != nil {
		return nil, err
	}
	return &backupKey{salt, n, r, p, base64.StdEncoding.EncodeToString(k)}, nil
}

func marshal(v any) []byte {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	e.Encode(v)
	return bytes.TrimSuffix(b.Bytes(), []byte("\n"))
}

func gcm(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

func sealBundle(bk *backupKey, kind string, p *payload) ([]byte, error) {
	pt := marshal(p)
	n := 12 + len(pt) + 16
	h := marshal(header{1, "scrypt", bk.Salt, bk.N, bk.R, bk.P, kind, isoNow(), &n})
	hb := append(append(append([]byte{}, magic...), h...), '\n')
	key, err := decodeB64(bk.Key)
	if err != nil {
		return nil, err
	}
	g, err := gcm(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(hb)+12+len(pt)+16)
	out = append(append(out, hb...), nonce...)
	return g.Seal(out, nonce, pt, hb), nil
}

// readHeader parses the header; bodyStart is where the nonce begins.
func readHeader(buf []byte) (*header, int, error) {
	if !bytes.HasPrefix(buf, magic) {
		return nil, 0, msg.Errorf(msg.BundleNotBundle)
	}
	end := bytes.IndexByte(buf[len(magic):], '\n')
	if end < 0 {
		return nil, 0, msg.Errorf(msg.BundleHeaderBad)
	}
	end += len(magic)
	var h header
	if err := json.Unmarshal(buf[len(magic):end], &h); err != nil {
		return nil, 0, msg.Errorf(msg.BundleHeaderBad)
	}
	return &h, end + 1, nil
}

func openBundle(buf, key []byte) (*header, *payload, error) {
	h, start, err := readHeader(buf)
	if err != nil {
		return nil, nil, err
	}
	body := buf[start:]
	fail := msg.Errorf(msg.BundleOpenFailed)
	if len(body) < 12+16 {
		return nil, nil, fail
	}
	g, err := gcm(key)
	if err != nil {
		return nil, nil, fail
	}
	pt, err := g.Open(nil, body[:12], body[12:], buf[:start])
	if err != nil {
		return nil, nil, fail
	}
	var p payload
	if err := json.Unmarshal(pt, &p); err != nil {
		return nil, nil, fail
	}
	return h, &p, nil
}

type check struct {
	facs, secs, encs int
	problems         []string
}

// verifyPayload checks every file parses and every ENC value decrypts with
// the bundled data key.
func verifyPayload(p *payload) check {
	var c check
	var key []byte
	if p.DataKey != nil {
		key, _ = decodeB64(*p.DataKey)
	}
	names := make([]string, 0, len(p.Files))
	for n := range p.Files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		fac := strings.TrimSuffix(name, ".ini")
		if !strings.HasSuffix(name, ".ini") || !store.NameRe.MatchString(fac) {
			c.problems = append(c.problems, msg.Text(msg.PayloadBadName, name))
			continue
		}
		f := ini.Parse(p.Files[name])
		c.facs++
		c.secs += len(f.Merged.Names())
		for _, sec := range f.Raw.Names() {
			m, _ := f.Raw.Get(sec)
			for _, k := range m.Keys() {
				v, _ := m.Get(k)
				if !store.IsEnc(v) {
					continue
				}
				c.encs++
				if key == nil {
					c.problems = append(c.problems, msg.Text(msg.PayloadNoKey, name, sec, k))
					continue
				}
				if _, err := store.Decrypt(key, fac, sec, k, v); err != nil {
					c.problems = append(c.problems, msg.Text(msg.PayloadNoDecr, name, sec, k))
				}
			}
		}
	}
	return c
}

func (a *Admin) currentPayload() (*payload, error) {
	p := &payload{Created: isoNow(), Files: map[string]string{}}
	facs, err := a.St.Facilities()
	if err != nil {
		return nil, err
	}
	for _, fac := range facs {
		b, err := os.ReadFile(a.facFile(fac))
		if err != nil {
			return nil, err
		}
		p.Files[fac+".ini"] = string(b)
	}
	if exists(a.St.DataKeyFile()) {
		k, err := a.St.DataKey()
		if err != nil {
			return nil, err
		}
		s := base64.StdEncoding.EncodeToString(k)
		p.DataKey = &s
	}
	return p, nil
}

func (a *Admin) loadBackupKey(file string) (*backupKey, error) {
	if !exists(file) {
		return nil, nil
	}
	b, err := keys.Detect(file, a.St.KeyBackend()).Unwrap(keys.BackupKeyName, file)
	if err != nil {
		return nil, err
	}
	var k backupKey
	if err := json.Unmarshal(b, &k); err != nil {
		return nil, err
	}
	return &k, nil
}

func (a *Admin) saveBackupKey(b keys.Backend, bk *backupKey, file string) error {
	if err := fault.At("save-backupkey"); err != nil {
		return err
	}
	return a.wrapTo(b, keys.BackupKeyName, marshal(bk), file, false)
}

// readConf reads env/.backup.json (the remembered backup dir).
func (a *Admin) readConf() (map[string]any, error) {
	b, err := os.ReadFile(a.confFile())
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]any{}, nil
	}
	var c map[string]any
	if err != nil || json.Unmarshal(b, &c) != nil || c == nil {
		return nil, msg.Errorf(msg.BackupConfBad, a.confFile())
	}
	return c, nil
}

func confDir(c map[string]any) string {
	s, _ := c["dir"].(string)
	return s
}

// autoDir is where automatic backups go: the remembered dir, else config
// [backup] dir, else the default ($TMPDIR/with-secrets-backup).
func (a *Admin) autoDir(conf map[string]any) string {
	if d := confDir(conf); d != "" {
		return d
	}
	if a.Cfg.BackupDir != "" {
		return a.Cfg.BackupDir
	}
	return defaultBackupDir()
}

func defaultBackupDir() string { return filepath.Join(os.TempDir(), "with-secrets-backup") }

func under(dir, base string) bool {
	d, b := filepath.Clean(dir), filepath.Clean(base)
	return d == b || strings.HasPrefix(d, b+string(filepath.Separator))
}

func isTempDir(dir string) bool { return under(dir, "/tmp") || under(dir, os.TempDir()) }

// Bundle status for base / rotation decisions:
//
//	ok       made with the current passphrase and restorable (only these count)
//	other    sound, but made with another passphrase: cannot be verified here,
//	         so it neither counts nor gets deleted
//	damaged  not a regular file, bad header, kind != name, wrong length, does
//	         not open, or not restorable
const (
	stOK = iota
	stOther
	stDamaged
)

func bundleStatus(path string, bk *backupKey) int {
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() {
		return stDamaged
	}
	buf, err := os.ReadFile(path)
	if err != nil {
		return stDamaged
	}
	h, start, err := readHeader(buf)
	if err != nil {
		return stDamaged
	}
	m := bundleName.FindStringSubmatch(filepath.Base(path))
	if m == nil || h.Kind != m[1] {
		return stDamaged
	}
	bodyLen := len(buf) - start
	if h.Len != nil && bodyLen != *h.Len || h.Len == nil && bodyLen < 12+16+2 {
		return stDamaged
	}
	if !bk.sameKDF(h) {
		return stOther
	}
	key, err := decodeB64(bk.Key)
	if err != nil {
		return stDamaged
	}
	_, p, err := openBundle(buf, key)
	if err != nil || len(verifyPayload(p).problems) > 0 {
		return stDamaged
	}
	return stOK
}

func listNames(dir string) []string {
	ents, _ := os.ReadDir(dir)
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

// writeBundle writes one bundle into dir and publishes it only once complete
// (temp file, full write, fsync, re-open with the key, rename). Only final
// names count, so an interrupted write never becomes the base or an auto
// copy. The first bundle verified with the current key is the permanent
// base; auto backups rotate (newest keepAuto kept); manual ones are kept.
func (a *Admin) writeBundle(dir, kind string, bk *backupKey) (string, string, error) {
	if err := ensureDir(dir); err != nil {
		return "", "", err
	}
	// A directory that cannot be listed would look empty (a new base, no
	// rotation): refuse instead.
	if _, err := os.ReadDir(dir); err != nil {
		return "", "", msg.Errorf(msg.ListEnvFailed, dir, store.ReadReason(err))
	}
	for _, f := range listNames(dir) {
		if bundleTmp.MatchString(f) {
			os.Remove(filepath.Join(dir, f))
		}
	}
	var named []string
	for _, f := range listNames(dir) {
		if bundleName.MatchString(f) {
			named = append(named, f)
		}
	}
	ok := map[string]bool{}
	others := 0
	for _, f := range named {
		switch bundleStatus(filepath.Join(dir, f), bk) {
		case stOK:
			ok[f] = true
		case stOther:
			others++
		default:
			a.warn(msg.Text(msg.BundleDamaged, filepath.Join(dir, f)))
		}
	}
	if others > 0 {
		a.warn(msg.Text(msg.BundleOthers, dir, others))
	}
	hasBase := false
	for f := range ok {
		if strings.HasPrefix(f, "secrets-base-") {
			hasBase = true
		}
	}
	if !hasBase {
		kind = kindBase
	}
	ts := stamp()
	name := "secrets-" + kind + "-" + ts + ".wsbk"
	for i := 1; exists(filepath.Join(dir, name)); i++ {
		name = "secrets-" + kind + "-" + ts + "-" + itoa(i) + ".wsbk"
	}
	file := filepath.Join(dir, name)
	tmp := filepath.Join(dir, "."+name+".tmp-"+itoa(os.Getpid()))
	// Refuse to publish a bundle that could not be restored (e.g. ENC values
	// but no data key): it would become a useless base.
	p, err := a.currentPayload()
	if err != nil {
		return "", "", err
	}
	if c := verifyPayload(p); len(c.problems) > 0 {
		list := strings.Join(c.problems[:min(3, len(c.problems))], "; ")
		if len(c.problems) > 3 {
			list += " ..."
		}
		return "", "", msg.Errorf(msg.BackupRefused, list)
	}
	data, err := sealBundle(bk, kind, p)
	if err != nil {
		return "", "", err
	}
	err = func() error {
		f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		err = writeAll(f, data, true)
		if err == nil {
			err = f.Sync()
		}
		f.Close()
		if err != nil {
			return err
		}
		if err := fault.At("bundle-written"); err != nil {
			return err
		}
		back, err := os.ReadFile(tmp)
		if err != nil {
			return err
		}
		key, _ := decodeB64(bk.Key)
		if _, _, err := openBundle(back, key); err != nil { // what is on disk opens
			return err
		}
		if err := os.Rename(tmp, file); err != nil {
			return err
		}
		fsyncDir(dir)
		return nil
	}()
	if err != nil {
		os.Remove(tmp)
		return "", "", err
	}
	if kind == kindAuto {
		// Rotate among intact auto bundles only; damaged files neither count
		// nor get deleted.
		autos := []string{name}
		for f := range ok {
			if strings.HasPrefix(f, "secrets-auto-") {
				autos = append(autos, f)
			}
		}
		sort.Strings(autos)
		for _, old := range autos[:max(0, len(autos)-keepAuto)] {
			os.Remove(filepath.Join(dir, old))
		}
	}
	if isTempDir(dir) {
		a.warn(msg.Text(msg.BackupInTemp, dir))
	}
	return file, kind, nil
}

func kindText(kind string) string {
	switch kind {
	case kindBase:
		return msg.Text(msg.KindBase)
	case kindAuto:
		return msg.Text(msg.KindAuto)
	}
	return msg.Text(msg.KindManual)
}

// autoBackup returns "" when done (or not set up), else what failed.
func (a *Admin) autoBackup() string {
	if !exists(a.backupKeyFile()) {
		a.warn(msg.Text(msg.AutoNotSetUp))
		return ""
	}
	conf, err := a.readConf()
	if err != nil {
		return msg.Text(msg.AutoFailed, err.Error())
	}
	bk, err := a.loadBackupKey(a.backupKeyFile())
	if err == nil && bk == nil {
		err = os.ErrNotExist
	}
	if err != nil {
		return msg.Text(msg.AutoFailed, err.Error())
	}
	file, kind, err := a.writeBundle(a.autoDir(conf), kindAuto, bk)
	if err != nil {
		return msg.Text(msg.AutoFailed, err.Error())
	}
	a.say(msg.Text(msg.AutoDone, kindText(kind), file))
	return ""
}
