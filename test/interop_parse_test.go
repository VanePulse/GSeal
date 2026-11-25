package test

// Parser interop: the Go INI parser must read every file exactly as
// VaneSecret (ca87d68) does — sections, keys, values, docs. Runs when
// GSEAL_INTEROP_NODE_SRC points at VaneSecret's src/ and node is installed
// (Linux acceptance machine); skipped otherwise.

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/VanePulse/GSeal/internal/ini"
)

var parseCorpus = map[string]string{
	"docs.ini":   "\uFEFF; @desc First\n;\n; second para\n; KEY = hidden\n; @remark skipped\n# @desc hash tag\n; plain comment\n\n[DEFAULT]\n; @desc default doc goes to the file\nA = 1\n\n[s]\n; @desc Sec doc\n;   indented\nB = 2\nA = 3\n\n[s]\nC = 4\n",
	"values.ini": "[v]\nP1 = plain ; comment\nP2 = pa;ss\nP3 = \"quoted ; kept\" ; c\nP4 = 'single'\nP5 = \"a\" b\nP6 =   spaced   \nP7 = x\t# tab comment\nP8 = \"unterminated\nP9 = a = b = c\nP10 =\nP11 = \u00A0nbsp\u00A0;x\nP12 = \"x\" ; c \"y\" ; d\n",
	"names.ini":  "[constructor]\n__proto__ = 1\nvalueOf = 2\n[ spaced ]\n key with space = v\n[x]\nnoequals\n=empty key\n",
	"crlf.ini":   "; @desc CRLF file\r\n\r\n[a]\r\nK = v\r\n; @desc late doc\r\nL = w\r\n",
	"assign.ini": "; @desc doc\n; BAD KEY WITH FIVE WORDS = x\n; URL https://a.invalid/?q=1 shown\n; 中文 = 说明\n; a.b-c = hidden\n\n[n]\nK = v\n",
	"before.ini": "K = before any section\n[a]\nK = v\n",
}

type parsed struct {
	Raw     [][]any  `json:"raw"`
	Desc    []string `json:"desc"`
	SecDesc [][]any  `json:"secDesc"`
}

func goParse(text string) parsed {
	f := ini.Parse(text)
	p := parsed{Raw: [][]any{}, Desc: f.Desc, SecDesc: [][]any{}}
	if p.Desc == nil {
		p.Desc = []string{}
	}
	for _, s := range f.Raw.Names() {
		m, _ := f.Raw.Get(s)
		kv := []any{}
		for _, k := range m.Keys() {
			v, _ := m.Get(k)
			kv = append(kv, []any{k, v})
		}
		p.Raw = append(p.Raw, []any{s, kv})
	}
	for _, s := range f.Merged.Names() {
		d := f.SecDesc[s]
		l := []any{}
		for _, x := range d {
			l = append(l, x)
		}
		p.SecDesc = append(p.SecDesc, []any{s, l})
	}
	return p
}

func TestInteropParse(t *testing.T) {
	src := os.Getenv("GSEAL_INTEROP_NODE_SRC")
	if src == "" {
		t.Skip("GSEAL_INTEROP_NODE_SRC not set (VaneSecret ca87d68 src/); run on the Linux acceptance machine")
	}
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not installed")
	}
	dir := filepath.Join(scratch, "interop-parse")
	os.MkdirAll(dir, 0o700)
	args := []string{"testdata/interop/parse.mjs", src}
	for name, text := range parseCorpus {
		p := filepath.Join(dir, name)
		write(t, p, text)
		args = append(args, p)
	}
	out, err := exec.Command("node", args...).Output()
	if err != nil {
		t.Fatalf("node: %v", err)
	}
	var node map[string]json.RawMessage
	if err := json.Unmarshal(out, &node); err != nil {
		t.Fatal(err)
	}
	c := checker{t}
	for name, text := range parseCorpus {
		var want parsed
		json.Unmarshal(node[filepath.Join(dir, name)], &want)
		g, _ := json.Marshal(goParse(text))
		var got parsed
		json.Unmarshal(g, &got)
		c.ok("I.parse."+name, reflect.DeepEqual(got, want), "Go parse equals VaneSecret parse: "+name, "\n go:   ", string(g), "\n node: ", string(node[filepath.Join(dir, name)]))
	}
}
