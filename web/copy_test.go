package web

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Product strings are generic. Comments and historical docs retain their sources.
func TestNoPersonalNamesInProductCopy(t *testing.T) {
	personal := regexp.MustCompile(`(?i)\b(hamza|okabe|deepa|daru)\b`)
	for _, dir := range []string{"../cmd", "../internal", "app", "../cloud/public", "../cloud/src"} {
		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			ext := filepath.Ext(path)
			if ext == ".go" {
				f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
				if err != nil {
					return err
				}
				ast.Inspect(f, func(n ast.Node) bool {
					if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
						s, _ := strconv.Unquote(lit.Value)
						if personal.MatchString(s) {
							t.Errorf("personal name in %s: %s", path, s)
						}
					}
					return true
				})
			} else if ext == ".js" || ext == ".ts" || ext == ".html" || ext == ".yaml" {
				b, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				for _, line := range strings.Split(string(b), "\n") {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(line, "//") || strings.HasPrefix(line, "#") {
						continue
					}
					// Exact legacy actor keys remain readable as "You" for existing vaults.
					if path == filepath.Join("app", "app.js") && (strings.Contains(line, `n === "hamza"`) || strings.Contains(line, `e.actor === "hamza"`)) {
						continue
					}
					if personal.MatchString(line) && !strings.Contains(line, "Made by Hamza at Ralveto") {
						t.Errorf("personal name in %s: %s", path, line)
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
