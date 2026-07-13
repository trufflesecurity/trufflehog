package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Finding describes a single detectors.Result{} construction in a package that
// never references the SecretParts field.
type Finding struct {
	// Position is the source location of the offending composite literal.
	Position token.Position
	// Package is the directory containing the finding.
	Package string
}

// CheckPackageDir runs the SecretParts check on a single directory. It returns
// one Finding per detectors.Result{} construction site in the directory.
func CheckPackageDir(dir string) ([]Finding, error) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var files []*ast.File
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(dir, name)
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		return nil, nil
	}

	return checkFiles(fset, dir, files), nil
}

// checkFiles inspects a set of parsed, non-test files from a single directory
// and returns findings. It is separated from CheckPackageDir so that tests can
// drive it with synthetic ASTs.
func checkFiles(fset *token.FileSet, dir string, files []*ast.File) []Finding {
	var constructions []token.Position

	for _, f := range files {
		constructions = append(constructions, findResultConstructions(fset, f)...)
	}

	sort.Slice(constructions, func(i, j int) bool {
		if constructions[i].Filename != constructions[j].Filename {
			return constructions[i].Filename < constructions[j].Filename
		}
		return constructions[i].Offset < constructions[j].Offset
	})

	out := make([]Finding, len(constructions))
	for i, pos := range constructions {
		out[i] = Finding{Position: pos, Package: dir}
	}
	return out
}

// findResultConstructions returns positions of composite literals with the
// type detectors.Result (selector expression with identifier "detectors" and
// selector "Result"). It covers both bare literals and pointer literals
// (&detectors.Result{}).
func findResultConstructions(fset *token.FileSet, f *ast.File) []token.Position {
	var positions []token.Position
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		if !isDetectorsResultType(lit.Type) {
			return true
		}
		if hasSecretPartsKey(lit) {
			return true
		}
		positions = append(positions, fset.Position(lit.Lbrace))
		return true
	})
	return positions
}

func isDetectorsResultType(expr ast.Expr) bool {
	// Unwrap *detectors.Result which won't appear for composite literal Type,
	// but handle parenthesized forms defensively.
	for {
		switch e := expr.(type) {
		case *ast.ParenExpr:
			expr = e.X
			continue
		case *ast.StarExpr:
			expr = e.X
			continue
		}
		break
	}
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	return pkg.Name == "detectors" && sel.Sel.Name == "Result"
}

func hasSecretPartsKey(lit *ast.CompositeLit) bool {
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		if key.Name == "SecretParts" {
			return true
		}
	}
	return false
}
