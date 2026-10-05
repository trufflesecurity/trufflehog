package detectors

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The engine can give verifier auth to any detector that embeds
// EndpointSetter, because EndpointSetter satisfies VerifierAuthCustomizer.
// The token is only attached if the detector builds its verification client
// with VerificationClient. A detector that skips the wrap still accepts auth
// and sends unauthenticated requests, which an auth proxy answers as if every
// secret were invalid. No runtime check can see which client a detector uses,
// so this test reads detector source instead.
func TestEndpointSetterDetectorsUseVerificationClient(t *testing.T) {
	var checked int
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		if d.Name() == "testdata" {
			return filepath.SkipDir
		}

		embeds, calls, err := scanForVerificationClient(path)
		if err != nil {
			return err
		}
		if embeds {
			checked++
			assert.True(t, calls,
				"%s embeds detectors.EndpointSetter but never calls VerificationClient; build the verification client with s.VerificationClient(...)", path)
		}
		return nil
	})
	require.NoError(t, err)
	assert.NotZero(t, checked, "found no detectors embedding EndpointSetter; the source scan is broken")
}

// scanForVerificationClient reports whether the non-test Go files in dir
// embed detectors.EndpointSetter in a struct, and whether any of them call a
// VerificationClient method. The embed and the call may sit in different
// files of the same package.
func scanForVerificationClient(dir string) (embeds, calls bool, err error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, false, err
	}

	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return false, false, err
		}
		// Most of the ~1000 detector packages never mention either name, so
		// skip parsing them.
		if !bytes.Contains(src, []byte("EndpointSetter")) && !bytes.Contains(src, []byte("VerificationClient")) {
			continue
		}
		file, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			return false, false, err
		}

		ast.Inspect(file, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.StructType:
				for _, field := range n.Fields.List {
					if len(field.Names) == 0 && isDetectorsEndpointSetter(field.Type) {
						embeds = true
					}
				}
			case *ast.CallExpr:
				if sel, ok := n.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "VerificationClient" {
					calls = true
				}
			}
			return true
		})
	}
	return embeds, calls, nil
}

// isDetectorsEndpointSetter matches an embedded field of type
// detectors.EndpointSetter or *detectors.EndpointSetter.
func isDetectorsEndpointSetter(expr ast.Expr) bool {
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "EndpointSetter" {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "detectors"
}
