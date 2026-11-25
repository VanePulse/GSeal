package test

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// forbiddenWords: SHA-256 of words that must not appear in the repository
// (internal user, host, project and facility names). Hashed so the list
// itself does not disclose them.
var forbiddenWords = map[string]bool{
	"67b6a6b3785f0ce05f692e11e84c4c6196872760cd247c3ce2e66dd008381d19": true,
	"80348a765e5b2971cc36f5f653cac9afc65e39aee6d38b81ad415f34ead2b4de": true,
	"3014637776d42a85266a46eecaa689d23eed6e49a3cea1f282afce1001b796c7": true,
	"f2c5d725911cd60cb075b39085deb8cbd0f79c765f5cf9e3a56a48dc3ed57c52": true,
	"227c4aa4f3c008a44e1e0f634698f8a5f8542af492a79ad39734d07cc3baaaec": true,
	"f4096758dc10e8bc14ceb9d925e38a1428fe977e71a269329c6ec5ed39914012": true,
	"00945b62888be9fa253f5ee210b958c82cf365ece532955d03f632af4be3aedd": true,
	"dfc48d33af398cb16cec49170422d0e51d27102230d4afc5495cc87f13fe06b8": true,
}

var (
	cleanToken = regexp.MustCompile(`[a-z0-9-]+`)
	cleanEmail = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+`)
	cleanIP    = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	cleanPath  = regexp.MustCompile(`/(?:data|home|Users)/[A-Za-z0-9._-]+`)
	// Host names: only .invalid (examples) and the project's public homes.
	cleanHost = regexp.MustCompile(`\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|net|org|cn|io|local|lan|corp|internal|intra)\b`)
)

var cleanAllowHost = map[string]bool{"github.com": true, "golang.org": true, "go.dev": true, "pkg.go.dev": true, "opensource.org": true, "semver.org": true, "keepachangelog.com": true}

// IPs from the baseline fixtures (private / documentation ranges only).
var cleanAllowIP = map[string]bool{"10.0.0.1": true, "10.0.0.2": true, "10.0.0.3": true, "10.9.9.9": true, "127.0.0.1": true}

func checkClean(t *testing.T, root string) []string {
	var bad []string
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		if d.IsDir() {
			switch rel {
			case ".git", "vendor", "dist", filepath.Join("testdata", "norm"):
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(p, ".wsbk") || strings.HasSuffix(rel, "go.sum") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		for n, line := range strings.Split(string(b), "\n") {
			at := rel + ":" + itoa(n+1)
			for _, w := range cleanToken.FindAllString(strings.ToLower(line), -1) {
				h := sha256.Sum256([]byte(w))
				if forbiddenWords[hex.EncodeToString(h[:])] {
					bad = append(bad, at+": internal name")
				}
			}
			for _, m := range cleanEmail.FindAllString(line, -1) {
				if !strings.HasSuffix(m, ".invalid") && !strings.HasPrefix(m, "noreply@") {
					bad = append(bad, at+": e-mail address")
				}
			}
			for _, m := range cleanIP.FindAllString(line, -1) {
				if !cleanAllowIP[m] && !strings.HasPrefix(m, "192.0.2.") {
					bad = append(bad, at+": IP address "+m)
				}
			}
			if m := cleanPath.FindString(line); m != "" {
				bad = append(bad, at+": absolute personal path")
			}
			for _, m := range cleanHost.FindAllString(line, -1) {
				if !cleanAllowHost[m] {
					bad = append(bad, at+": host name "+m)
				}
			}
		}
		return nil
	})
	return bad
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
