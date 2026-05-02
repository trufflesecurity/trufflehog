// extract-keywords parses a detector package directory and prints the
// strings returned by its `Keywords() []string` method as a JSON array.
//
// Used by scripts/build_keyword_corpus.py to fan out per-detector GitHub
// Code Search queries during the corpora bench. Static parsing is preferred
// over compile-and-import because each detector lives in its own package
// and importing them dynamically requires either codegen or `plugin`.
//
// Resolution order:
//  1. Walk all non-test *.go files via go/parser.
//  2. Find a method named Keywords with no parameters and a single
//     []string return; take its first ReturnStmt.
//  3. If the return expr is a []string composite literal, collect string
//     literal elements.
//  4. If it's an identifier, look up a package-level var with that name and
//     extract from its initializer composite literal.
//  5. If AST extraction yields nothing, fall back to a regex over the body
//     of the same Keywords function — handles oddities like build-tag-gated
//     bodies that the parser may have skipped.
//
// Exit codes:
//
//	0 — keywords printed (possibly empty array).
//	1 — directory unreadable or no Keywords method found anywhere.
//
// An empty array on exit 0 is a deliberate signal to the caller that this
// detector should be marked thin-L1 and skipped, distinct from a hard
// failure (exit 1).
package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: extract-keywords <detector-package-dir>")
		os.Exit(1)
	}
	dir := os.Args[1]
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		fmt.Fprintf(os.Stderr, "extract-keywords: %s is not a readable directory\n", dir)
		os.Exit(1)
	}

	keywords, found, err := extractFromDir(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "extract-keywords: %v\n", err)
		os.Exit(1)
	}
	if !found {
		fmt.Fprintf(os.Stderr, "extract-keywords: no Keywords() method found in %s\n", dir)
		os.Exit(1)
	}

	out, _ := json.Marshal(keywords)
	fmt.Println(string(out))
}

// extractFromDir parses all non-test Go files in dir and returns the
// keyword list. The found return distinguishes "Keywords method exists but
// returns nothing extractable" (found=true, empty slice) from "no Keywords
// method at all" (found=false).
func extractFromDir(dir string) (keywords []string, found bool, err error) {
	fset := token.NewFileSet()
	// parser.ParseDir is deprecated in favour of go/packages, but we
	// deliberately want a build-tag-agnostic union of every file in the
	// directory rather than the type-checked, build-tag-respecting view that
	// go/packages produces. Switching would force a new direct module
	// dependency for marginal gain on a CI helper.
	//nolint:staticcheck
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		return nil, false, fmt.Errorf("parse %s: %w", dir, err)
	}

	// Most detector dirs have one package; versioned dirs (e.g. github/v2)
	// also have one. Iterating handles both without a special case.
	for _, pkg := range pkgs {
		fnDecl, fnFile := findKeywordsFunc(pkg)
		if fnDecl == nil {
			continue
		}
		found = true
		kws := extractFromFunc(fnDecl, pkg)
		if len(kws) > 0 {
			return kws, true, nil
		}
		// AST resolution failed — fall back to regex over the source range
		// of the Keywords function body. Handles cases the AST walker
		// can't statically resolve (helper calls, build-tagged variants).
		if grepped := grepFallback(fset, fnFile, fnDecl); len(grepped) > 0 {
			return grepped, true, nil
		}
	}

	if !found {
		// Last-ditch: pure-grep across all source files in the dir. Catches
		// cases where parser.ParseDir filtered the file out (rare; e.g.
		// build-tag exclusion with the default ParseDir filter).
		grepped, ok := grepDirFallback(dir)
		if ok {
			return grepped, true, nil
		}
	}

	return nil, found, nil
}

// findKeywordsFunc returns the Keywords method decl (if any) and the file
// containing it.
func findKeywordsFunc(pkg *ast.Package) (*ast.FuncDecl, *ast.File) {
	for _, file := range pkg.Files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if fn.Name == nil || fn.Name.Name != "Keywords" {
				continue
			}
			if fn.Recv == nil || len(fn.Recv.List) != 1 {
				continue
			}
			// Must look like `Keywords() []string`. Don't be picky about the
			// receiver — both Scanner and scanner are seen in the codebase.
			if fn.Type.Params != nil && len(fn.Type.Params.List) > 0 {
				continue
			}
			if fn.Type.Results == nil || len(fn.Type.Results.List) != 1 {
				continue
			}
			return fn, file
		}
	}
	return nil, nil
}

// extractFromFunc walks the function body for a return statement whose
// expression is either a []string composite literal or an identifier
// referring to a package-level var initialised with one.
func extractFromFunc(fn *ast.FuncDecl, pkg *ast.Package) []string {
	if fn.Body == nil {
		return nil
	}
	var out []string
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		ret, ok := n.(*ast.ReturnStmt)
		if !ok || len(ret.Results) == 0 {
			return true
		}
		switch expr := ret.Results[0].(type) {
		case *ast.CompositeLit:
			out = append(out, stringLitsFromComposite(expr)...)
		case *ast.Ident:
			if vals := lookupPackageStringSlice(pkg, expr.Name); len(vals) > 0 {
				out = append(out, vals...)
			}
		}
		return false
	})
	return dedupNonEmpty(out)
}

// stringLitsFromComposite extracts string literal elements from a
// `[]string{"a", "b", ...}` composite literal. Non-literal elements (e.g.
// helper calls) are silently dropped — the caller falls back to regex.
func stringLitsFromComposite(c *ast.CompositeLit) []string {
	if c == nil {
		return nil
	}
	if !isStringSliceType(c.Type) {
		return nil
	}
	var out []string
	for _, el := range c.Elts {
		if lit, ok := el.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			if s, err := strconv.Unquote(lit.Value); err == nil {
				out = append(out, s)
			}
		}
	}
	return out
}

func isStringSliceType(expr ast.Expr) bool {
	at, ok := expr.(*ast.ArrayType)
	if !ok {
		return false
	}
	id, ok := at.Elt.(*ast.Ident)
	return ok && id.Name == "string"
}

// lookupPackageStringSlice resolves a package-level
// `var <name> = []string{...}` declaration into its string literals.
func lookupPackageStringSlice(pkg *ast.Package, name string) []string {
	for _, file := range pkg.Files {
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.VAR {
				continue
			}
			for _, spec := range gen.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, n := range vs.Names {
					if n.Name != name || i >= len(vs.Values) {
						continue
					}
					if c, ok := vs.Values[i].(*ast.CompositeLit); ok {
						if vals := stringLitsFromComposite(c); len(vals) > 0 {
							return vals
						}
					}
				}
			}
		}
	}
	return nil
}

// stringLitRE matches Go double-quoted string literals (including escapes
// and \u sequences). Backtick raw strings are uncommon in keyword lists
// and are intentionally not handled.
var stringLitRE = regexp.MustCompile(`"((?:\\.|[^"\\])*)"`)

// grepFallback extracts string literals from the source span of the
// Keywords function body using a regex. Used when AST resolution fails.
func grepFallback(fset *token.FileSet, file *ast.File, fn *ast.FuncDecl) []string {
	if fn.Body == nil {
		return nil
	}
	tokFile := fset.File(file.Pos())
	if tokFile == nil {
		return nil
	}
	src, err := os.ReadFile(tokFile.Name())
	if err != nil {
		return nil
	}
	start := tokFile.Offset(fn.Body.Lbrace)
	end := tokFile.Offset(fn.Body.Rbrace)
	if start < 0 || end <= start || end > len(src) {
		return nil
	}
	return matchStringLits(string(src[start:end]))
}

// grepDirFallback scans every .go file in dir for a `Keywords() []string`
// signature and extracts string literals from its body. Used when
// parser.ParseDir didn't surface any package (build-tag filtering, etc.).
func grepDirFallback(dir string) ([]string, bool) {
	matches, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		return nil, false
	}
	bodyRE := regexp.MustCompile(`(?ms)Keywords\(\)\s*\[\]string\s*\{(.*?)^\}`)
	var out []string
	found := false
	for _, m := range matches {
		if strings.HasSuffix(m, "_test.go") {
			continue
		}
		src, err := os.ReadFile(m)
		if err != nil {
			continue
		}
		for _, body := range bodyRE.FindAllStringSubmatch(string(src), -1) {
			found = true
			out = append(out, matchStringLits(body[1])...)
		}
	}
	return dedupNonEmpty(out), found
}

func matchStringLits(s string) []string {
	var out []string
	for _, m := range stringLitRE.FindAllStringSubmatch(s, -1) {
		// m[0] is `"..."`, suitable for strconv.Unquote.
		if v, err := strconv.Unquote(m[0]); err == nil {
			out = append(out, v)
		}
	}
	return dedupNonEmpty(out)
}

func dedupNonEmpty(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
