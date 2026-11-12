package detectors_test

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/defaults"
)

// modulePrefix is stripped from a detector's package path to find its source
// directory relative to the repository root.
const modulePrefix = "github.com/trufflesecurity/trufflehog/v3/"

// The engine can give verifier auth to any default detector that satisfies
// VerifierAuthCustomizer, whether it embeds EndpointSetter directly or
// inherits it by embedding another detector's Scanner (as GitHub v2 embeds
// v1). The token is only attached if the detector builds its verification
// client with VerificationClient. A detector that skips the wrap still accepts
// auth and sends unauthenticated requests, which an auth proxy answers as if
// every secret were invalid. No runtime check can see which client a detector
// uses, so this test reads the source of the package that defines each
// detector's concrete type, which is where its FromData lives.
func TestVerifierAuthDetectorsUseVerificationClient(t *testing.T) {
	scanned := make(map[string]bool)
	for _, d := range defaults.DefaultDetectors() {
		if _, ok := d.(detectors.VerifierAuthCustomizer); !ok {
			continue
		}

		typ := reflect.TypeOf(d)
		if typ.Kind() == reflect.Pointer {
			typ = typ.Elem()
		}
		pkgPath := typ.PkgPath()
		if _, done := scanned[pkgPath]; done {
			continue
		}

		rel, ok := strings.CutPrefix(pkgPath, modulePrefix)
		require.True(t, ok, "detector %s is defined outside this module", pkgPath)
		// The test runs in pkg/detectors, two levels below the repository root.
		calls, err := callsVerificationClient(filepath.Join("..", "..", rel))
		require.NoError(t, err)
		scanned[pkgPath] = calls

		assert.True(t, calls,
			"%s accepts verifier auth but never calls VerificationClient; build the verification client with s.VerificationClient(...)", pkgPath)
	}
	assert.NotEmpty(t, scanned, "found no default detectors that accept verifier auth; the check is broken")
}

// callsVerificationClient reports whether any non-test Go file in dir calls a
// method named VerificationClient.
func callsVerificationClient(dir string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, err
	}

	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return false, err
		}
		if !bytes.Contains(src, []byte("VerificationClient")) {
			continue
		}
		file, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			return false, err
		}

		var calls bool
		ast.Inspect(file, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "VerificationClient" {
					calls = true
				}
			}
			return !calls
		})
		if calls {
			return true, nil
		}
	}
	return false, nil
}
