package norm

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func parseSeq(t *testing.T, s string) string {
	var b strings.Builder
	for _, h := range strings.Fields(s) {
		v, err := strconv.ParseUint(h, 16, 32)
		if err != nil {
			t.Fatalf("bad hex %q", h)
		}
		b.WriteRune(rune(v))
	}
	return b.String()
}

func hexOf(s string) string {
	var p []string
	for _, r := range s {
		p = append(p, strings.ToUpper(strconv.FormatInt(int64(r), 16)))
	}
	return strings.Join(p, " ")
}

// vectors reads testdata/norm/vectors.txt; assigned receives every assigned
// code point listed (I ranges and S lines).
func vectors(t *testing.T) (cases [][3]string, assigned []rune) {
	f, err := os.Open(filepath.Join("..", "..", "testdata", "norm", "vectors.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	header := ""
	for sc.Scan() {
		line := sc.Text()
		if header == "" {
			header = line
		}
		if line == "" || line[0] == '#' {
			continue
		}
		kind, rest, _ := strings.Cut(line, " ")
		switch kind {
		case "I":
			a, b, _ := strings.Cut(rest, " ")
			lo, _ := strconv.ParseUint(a, 16, 32)
			hi, _ := strconv.ParseUint(b, 16, 32)
			for cp := lo; cp <= hi; cp++ {
				s := string(rune(cp))
				cases = append(cases, [3]string{"I", s, s})
				assigned = append(assigned, rune(cp))
			}
		case "S", "P", "X":
			src, want, ok := strings.Cut(rest, ";")
			if !ok {
				t.Fatalf("bad line %q", line)
			}
			s := parseSeq(t, src)
			cases = append(cases, [3]string{kind, s, parseSeq(t, want)})
			if kind == "S" {
				assigned = append(assigned, []rune(s)[0])
			}
		default:
			t.Fatalf("bad line %q", line)
		}
	}
	if !strings.Contains(header, "Unicode "+UnicodeVersion+",") {
		t.Fatalf("vectors are for another Unicode version than the tables (%s): %s", UnicodeVersion, header)
	}
	return cases, assigned
}

// TestVectors: every generated vector (all assigned single code points, all
// composition pairs, 10000 random mark sequences) matches unicodedata.
func TestVectors(t *testing.T) {
	cases, assigned := vectors(t)
	if len(assigned) < 150000 {
		t.Fatalf("only %d assigned code points in the vectors", len(assigned))
	}
	n := map[string]int{}
	bad := 0
	for _, c := range cases {
		n[c[0]]++
		if got := NFC(c[1]); got != c[2] {
			if bad++; bad <= 20 {
				t.Errorf("%s NFC(%s) = %s, want %s", c[0], hexOf(c[1]), hexOf(got), hexOf(c[2]))
			}
		}
	}
	if bad > 0 {
		t.Fatalf("%d of %d vectors differ", bad, len(cases))
	}
	if n["P"] < 900 || n["X"] != 10000 {
		t.Fatalf("unexpected vector counts: %v", n)
	}
	t.Logf("Unicode %s: %v", UnicodeVersion, n)
}

func TestExamples(t *testing.T) {
	for _, c := range [][2]string{
		{"", ""},
		{"plain ascii", "plain ascii"},
		{"e\u0301", "é"},
		{"é", "é"},
		{"ậ", "ậ"},  // reordered then composed
		{"ậ", "ậ"},  // same, other order
		{"각", "각"},  // Hangul LVT
		{"Å", "Å"},    // singleton (Angstrom sign)
		{"क़", "क़"},   // composition exclusion
		{"\xff", "�"}, // invalid UTF-8
	} {
		if got := NFC(c[0]); got != c[1] {
			t.Errorf("NFC(%s) = %s, want %s", hexOf(c[0]), hexOf(got), hexOf(c[1]))
		}
	}
}

// TestAgainstNode compares every code point assigned in UnicodeVersion with
// Node's String.prototype.normalize('NFC') (VaneSecret's implementation).
// Normalization stability guarantees the result for assigned characters does
// not change in later Unicode versions, so a newer Node must agree exactly.
// Characters assigned only in Node's newer version are not in the list.
// Runs on Linux when node is installed (required on the reviewer's machine:
// set GSEAL_REQUIRE_NODE=1 to fail instead of skip).
func TestAgainstNode(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil || runtime.GOOS != "linux" {
		if os.Getenv("GSEAL_REQUIRE_NODE") != "" {
			t.Fatal("node is required (GSEAL_REQUIRE_NODE is set)")
		}
		t.Skip("node not available")
	}
	_, assigned := vectors(t)
	var in strings.Builder
	for _, r := range assigned {
		in.WriteString(strconv.FormatInt(int64(r), 16))
		in.WriteByte('\n')
	}
	script := `const out = [];
for (const h of require('fs').readFileSync(0, 'utf8').split('\n')) {
  if (!h) continue;
  out.push([...String.fromCodePoint(parseInt(h, 16)).normalize('NFC')].map(c => c.codePointAt(0).toString(16)).join(' '));
}
process.stdout.write(process.versions.unicode + '\n' + out.join('\n') + '\n');`
	cmd := exec.Command(node, "-e", script)
	cmd.Stdin = strings.NewReader(in.String())
	b, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	nodeVer, lines := lines[0], lines[1:]
	if len(lines) != len(assigned) {
		t.Fatalf("node returned %d results for %d code points", len(lines), len(assigned))
	}
	bad := 0
	for i, r := range assigned {
		want := strings.ToLower(hexOf(NFC(string(r))))
		if lines[i] != want {
			if bad++; bad <= 20 {
				t.Errorf("U+%04X: Go %s, Node %s", r, want, lines[i])
			}
		}
	}
	if bad > 0 {
		t.Fatalf("%d code points differ from Node", bad)
	}
	t.Logf("%d code points (Unicode %s) identical to Node (Unicode %s)", len(assigned), UnicodeVersion, nodeVer)
}
