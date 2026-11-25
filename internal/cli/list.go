package cli

import (
	"fmt"
	"sort"
	"strings"

	"github.com/VanePulse/GSeal/internal/ini"
	"github.com/VanePulse/GSeal/internal/msg"
	"github.com/VanePulse/GSeal/internal/policy"
	"github.com/VanePulse/GSeal/internal/redact"
	"github.com/VanePulse/GSeal/internal/store"
)

// descMasker masks secrets in @desc text, as whole tokens only (values
// stored encrypted wherever they occur). Facility,
// section and variable names are never masked. It uses the secrets of every
// file, since a value could be pasted into another file's @desc.
//
// If any value cannot be decrypted the masking set is incomplete: problem is
// set and no doc text may be shown at all.
func (a *app) descMasker(all map[string]*ini.File, order []string) (mask func(string) string, problem string) {
	var secret, encrypted []string
	for _, fac := range order {
		f := all[fac]
		vals, err := a.st.DecryptRaw(fac, f)
		if err != nil {
			if problem == "" {
				problem = err.Error()
			}
			continue
		}
		for _, sec := range vals.Names {
			for _, kv := range vals.Sec[sec] {
				if a.plain.Redacted(kv.Key, kv.Encrypted) {
					secret = append(secret, kv.Plain)
					if kv.Encrypted {
						encrypted = append(encrypted, kv.Plain)
					}
				}
			}
		}
	}
	patterns, forced := redact.Patterns(secret), redact.Patterns(encrypted)
	return func(s string) string { return redact.Words(s, patterns, forced) }, problem
}

// keyMeaning looks up a key's meaning in the file-level doc (a `KEY  text`
// line). Returns "" when not documented.
func keyMeaning(desc []string, key string) string {
	for _, l := range desc {
		s := strings.TrimLeftFunc(l, ini.IsSpace)
		rest, ok := strings.CutPrefix(s, key)
		if !ok || rest == "" {
			continue
		}
		r := []rune(rest)
		if !ini.IsSpace(r[0]) {
			continue
		}
		if t := ini.Trim(rest); t != "" {
			return t
		}
	}
	return ""
}

func table(pairs [][2]string, indent string) []string {
	w := 0
	for _, p := range pairs {
		if n := len([]rune(p[0])); n > w {
			w = n
		}
	}
	out := make([]string, len(pairs))
	for i, p := range pairs {
		if p[1] == "" {
			out[i] = indent + p[0]
			continue
		}
		out[i] = indent + p[0] + strings.Repeat(" ", w-len([]rune(p[0]))) + "  " + p[1]
	}
	return out
}

// listView: three levels.
//
//	--list                 files (facilities), one line each
//	--list <facility>      file doc + its nodes, one line each
//	--list <facility.node> node doc + injected variables with key meanings
func (a *app) listView(target string) ([]string, error) {
	all := map[string]*ini.File{}
	var order []string
	facs, err := a.st.Facilities()
	if err != nil {
		return nil, err
	}
	for _, fac := range facs {
		f, err := a.st.Load(fac)
		if err != nil || f == nil {
			continue
		}
		all[fac] = f
		order = append(order, fac)
	}
	mask, problem := a.descMasker(all, order)
	hidden := msg.Text(msg.ListHidden)
	first := func(lines []string) string {
		if len(lines) == 0 {
			return ""
		}
		if problem != "" {
			return hidden
		}
		return mask(lines[0])
	}
	block := func(lines []string, indent string) []string {
		if problem != "" {
			if len(lines) == 0 {
				return nil
			}
			return []string{indent + hidden}
		}
		out := make([]string, len(lines))
		for i, l := range lines {
			if l != "" {
				out[i] = indent + mask(l)
			}
		}
		return out
	}
	meaning := func(t string) string {
		if problem != "" {
			return ""
		}
		return mask(t)
	}
	var notice []string
	if problem != "" {
		notice = []string{"", msg.Text(msg.ListHiddenNote, problem)}
	}
	if target == "" {
		if len(order) == 0 {
			return []string{msg.Text(msg.ListNone)}, nil
		}
		var pairs [][2]string
		for _, fac := range order {
			pairs = append(pairs, [2]string{fac, first(all[fac].Desc)})
		}
		out := append(table(pairs, ""), "", msg.Text(msg.ListFileHint))
		return append(out, notice...), nil
	}
	dot := strings.IndexByte(target, '.')
	fac := target
	if dot >= 0 {
		fac = target[:dot]
	}
	f := all[fac]
	if f == nil {
		e := msg.Errorf(msg.UnknownFile, fac)
		e.Text = available(e.Text, order)
		return nil, e
	}
	if dot < 0 {
		var pairs [][2]string
		for _, s := range f.Merged.Names() {
			pairs = append(pairs, [2]string{fac + "." + s, first(f.SecDesc[s])})
		}
		out := append([]string{fac}, block(f.Desc, "  ")...)
		out = append(out, "", msg.Text(msg.ListNodes))
		out = append(out, table(pairs, "  ")...)
		out = append(out, "", msg.Text(msg.ListNodeHint, fac))
		return append(out, notice...), nil
	}
	sec := target[dot+1:]
	kv, ok := f.Merged.Get(sec)
	if !ok {
		var names []string
		for _, s := range f.Merged.Names() {
			names = append(names, fac+"."+s)
		}
		e := msg.Errorf(msg.UnknownName, target)
		e.Text = available(e.Text, names)
		return nil, e
	}
	prefix := envPrefix(target)
	var pairs [][2]string
	for _, k := range kv.Keys() {
		pairs = append(pairs, [2]string{varName(prefix, k), meaning(keyMeaning(f.Desc, k))})
	}
	out := append([]string{target}, block(f.SecDesc[sec], "  ")...)
	out = append(out, "", msg.Text(msg.ListVars))
	out = append(out, table(pairs, "  ")...)
	return append(out, notice...), nil
}

// effectiveSpec returns the encryption spec for a file and where it came from.
func (a *app) effectiveSpec(fac string, f *ini.File) (policy.Spec, string, error) {
	if f.HasEncrypt {
		s, err := policy.Parse(f.Encrypt)
		if err != nil {
			return s, "", msg.Errorf(msg.PolicyBad, fac, err.Error())
		}
		return s, msg.Text(msg.PolicySrcFile), nil
	}
	text := "@mask"
	if a.cfg.EncryptSet {
		text = a.cfg.Encrypt
	}
	s, err := policy.Parse(text)
	if err != nil {
		return s, "", msg.Errorf(msg.ConfigBadSpec, a.cfg.Path, err.Error())
	}
	return s, msg.Text(msg.PolicySrcConfig), nil
}

// policyView shows, per file, which values the policy encrypts and how each is
// stored now. It never decrypts and never shows values.
func (a *app) policyView(target string) (int, error) {
	facs, err := a.st.Facilities()
	if err != nil {
		return ExitUsage, err
	}
	if target != "" {
		f, err := a.st.Load(target)
		if err != nil {
			return ExitUsage, err
		}
		if f == nil {
			e := msg.Errorf(msg.UnknownFile, target)
			e.Text = available(e.Text, facs)
			return ExitUsage, e
		}
		facs = []string{target}
	}
	toEnc, toDec := 0, 0
	for i, fac := range facs {
		f, err := a.st.Load(fac)
		if err != nil || f == nil {
			continue
		}
		spec, src, err := a.effectiveSpec(fac, f)
		if err != nil {
			return ExitUsage, err
		}
		if i > 0 {
			fmt.Fprintln(a.stdout)
		}
		fmt.Fprintln(a.stdout, msg.Text(msg.PolicyHeader, fac, spec.Describe(msg.Text(msg.PolicyAll)), src))
		var rows [][4]string
		for _, sec := range f.Raw.Names() {
			m, _ := f.Raw.Get(sec)
			for _, k := range m.Keys() {
				v, _ := m.Get(k)
				want, enc := spec.Encrypt(k, a.plain), store.IsEnc(v)
				r := [4]string{"[" + sec + "] " + k, msg.Text(msg.PolicyPlain), msg.Text(msg.PolicyStoredPln), ""}
				if want {
					r[1] = msg.Text(msg.PolicyWant)
				}
				if enc {
					r[2] = msg.Text(msg.PolicyStoredEnc)
				}
				if want != enc {
					r[3] = msg.Text(msg.PolicyMismatch)
					if want {
						toEnc++
					} else {
						toDec++
					}
				}
				rows = append(rows, r)
			}
		}
		w := [3]int{}
		for _, r := range rows {
			for j := 0; j < 3; j++ {
				if n := len([]rune(r[j])); n > w[j] {
					w[j] = n
				}
			}
		}
		for _, r := range rows {
			pad := func(j int) string { return r[j] + strings.Repeat(" ", w[j]-len([]rune(r[j]))) }
			fmt.Fprintln(a.stdout, strings.TrimRight(msg.Text(msg.PolicyRow, pad(0), pad(1), pad(2), r[3]), " "))
		}
		ign := append([]string(nil), f.EncryptIgnored...)
		sort.Strings(ign)
		for _, s := range ign {
			fmt.Fprintln(a.stdout, msg.Text(msg.PolicySecIgnore, s))
		}
	}
	fmt.Fprintln(a.stdout)
	fmt.Fprintln(a.stdout, msg.Text(msg.PolicySummary, toEnc, toDec))
	return ExitOK, nil
}
