package test

// Every user-visible text lives in internal/msg. This scans all string
// literals of the production code (outside internal/msg) and fails on any
// that reads like prose: a letter-word followed by a space and another word,
// or a capitalised word. Literals that are not prose (command names, flags,
// file names, regular expressions, JSON keys, ...) are listed in
// allowedLiterals with the reason; anything new must either go to the
// message table or be added there explicitly.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// allowedLiterals: non-prose literals that contain a space or a capital.
var allowedLiterals = map[string]string{
	"decrypt failed": "store.ErrDecrypt sentinel; callers always report msg.DecryptFailed instead",
}

var prose = regexp.MustCompile(`[A-Za-z]{2,}[,:;!?]? +[A-Za-z]{2,}|^[A-Z][a-z]{2,}`)

var outputFunc = map[string]bool{
	"errors.New": true, "fmt.Errorf": true, "fmt.Sprint": true, "fmt.Sprintf": true, "fmt.Sprintln": true,
	"fmt.Print": true, "fmt.Printf": true, "fmt.Println": true, "fmt.Fprint": true, "fmt.Fprintf": true, "fmt.Fprintln": true,
	"io.WriteString": true,
}

// direct collects literals passed straight to output / error functions.
var direct []string

func productionLiterals(t *testing.T) map[string][]string {
	found := map[string][]string{}
	direct = nil
	fset := token.NewFileSet()
	filepath.WalkDir("..", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor", "testdata", "test", "tools", "msg":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.ImportSpec:
				return false
			case *ast.Field: // struct tags
				if x.Tag != nil {
					x.Tag = nil
				}
			case *ast.CallExpr:
				// A literal handed straight to an error or print function is
				// user text, even if it is a single word.
				if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
					if pkg, ok := sel.X.(*ast.Ident); ok && outputFunc[pkg.Name+"."+sel.Sel.Name] {
						for _, a := range x.Args {
							if lit, ok := a.(*ast.BasicLit); ok && lit.Kind == token.STRING {
								v, _ := strconv.Unquote(lit.Value)
								if strings.Trim(v, "%sdvq\n \t:") != "" {
									direct = append(direct, strconv.Quote(v)+" at "+fset.Position(lit.Pos()).String())
								}
							}
						}
					}
				}
			case *ast.BasicLit:
				if x.Kind == token.STRING {
					v, err := strconv.Unquote(x.Value)
					if err == nil {
						found[v] = append(found[v], fset.Position(x.Pos()).String())
					}
				}
			}
			return true
		})
		return nil
	})
	return found
}

func TestM1NoProseOutsideMsg(t *testing.T) {
	c := checker{t}
	var bad []string
	for lit, where := range productionLiterals(t) {
		if _, ok := allowedLiterals[lit]; ok {
			continue
		}
		if prose.MatchString(lit) {
			bad = append(bad, strconv.Quote(lit)+" at "+where[0])
		}
	}
	c.ok("L.3", len(bad) == 0, "no prose string literals outside internal/msg", "\n"+strings.Join(bad, "\n"))
	var d []string
	for _, x := range direct {
		lit, _ := strconv.Unquote(strings.SplitN(x, " at ", 2)[0])
		if _, ok := allowedLiterals[lit]; !ok {
			d = append(d, x)
		}
	}
	c.ok("L.4", len(d) == 0, "no literal passed straight to error / print functions outside internal/msg", "\n"+strings.Join(d, "\n"))
}
