package ini

import "testing"

func TestParseValue(t *testing.T) {
	cases := map[string]string{
		`plain`:                 "plain",
		`plain ; comment`:       "plain",
		`pa;ss`:                 "pa;ss",
		`pa ;ss`:                "pa",
		`"quoted ; kept" ; c`:   "quoted ; kept",
		`"quoted ; kept"`:       "quoted ; kept",
		`'single' # c`:          "single",
		`"a" b`:                 `"a" b`,
		`x  # tail`:             "x",
		`a b c`:                 "a b c",
		`"unterminated`:         `"unterminated`,
		"v\u00A0;nbsp-is-space": "v",
		`"x" ; c "y" ; d`:       "x",
	}
	for in, want := range cases {
		if got := ParseValue(in); got != want {
			t.Errorf("ParseValue(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFormatValueRoundTrip(t *testing.T) {
	for _, v := range []string{"plain", " lead", "trail ", "a ;b", `"q`, "it's", `say "hi"`} {
		f, ok := FormatValue(v)
		if !ok || ParseValue(f) != v {
			t.Errorf("FormatValue(%q) = %q (%v), reads back %q", v, f, ok, ParseValue(f))
		}
	}
	if _, ok := FormatValue(` "both' `); ok {
		t.Error("value with both quote characters must be refused")
	}
}

func TestParseDocsAndDefault(t *testing.T) {
	f := Parse("\uFEFF; @desc File doc\n;\n; second\n; KEY = hidden\n; @remark no\n\n[DEFAULT]\nA = 1\n\n[s]\n; @desc Sec\nB = 2\nA = 3\n[s]\nC = 4\n")
	if len(f.Desc) != 3 || f.Desc[0] != "File doc" || f.Desc[1] != "" || f.Desc[2] != "second" {
		t.Errorf("file desc = %q", f.Desc)
	}
	m, _ := f.Merged.Get("s")
	if k := m.Keys(); len(k) != 3 || k[0] != "A" || k[1] != "B" || k[2] != "C" {
		t.Errorf("merged keys = %q", k)
	}
	if v, _ := m.Get("A"); v != "3" {
		t.Errorf("A = %q", v)
	}
	if d := f.SecDesc["s"]; len(d) != 1 || d[0] != "Sec" {
		t.Errorf("sec desc = %q", d)
	}
}

func TestEncryptTag(t *testing.T) {
	f := Parse("; @encrypt @mask, HOST\n\n[a]\n; @encrypt all\nK = v\n")
	if !f.HasEncrypt || f.Encrypt != "@mask, HOST" {
		t.Errorf("encrypt = %q %v", f.Encrypt, f.HasEncrypt)
	}
	if len(f.EncryptIgnored) != 1 || f.EncryptIgnored[0] != "a" {
		t.Errorf("ignored = %q", f.EncryptIgnored)
	}
}
