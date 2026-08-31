package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckPackageDir(t *testing.T) {
	tests := []struct {
		name    string
		files   map[string]string
		wantLen int
	}{
		{
			name: "missing SecretParts is reported",
			files: map[string]string{
				"det.go": `package det

import "github.com/trufflesecurity/trufflehog/v3/pkg/detectors"

func FromData() detectors.Result {
	return detectors.Result{
		DetectorType: 1,
		Raw:          []byte("x"),
	}
}
`,
			},
			wantLen: 1,
		},
		{
			name: "SecretParts set in composite literal is accepted",
			files: map[string]string{
				"det.go": `package det

import "github.com/trufflesecurity/trufflehog/v3/pkg/detectors"

func FromData() detectors.Result {
	return detectors.Result{
		DetectorType: 1,
		Raw:          []byte("x"),
		SecretParts:  map[string]string{"key": "v"},
	}
}
`,
			},
			wantLen: 0,
		},
		{
			name: "SecretParts assigned later is not accepted",
			files: map[string]string{
				"det.go": `package det

import "github.com/trufflesecurity/trufflehog/v3/pkg/detectors"

func FromData() detectors.Result {
	r := detectors.Result{
		DetectorType: 1,
		Raw:          []byte("x"),
	}
	r.SecretParts = map[string]string{"key": "v"}
	return r
}
`,
			},
			wantLen: 1,
		},
		{
			name: "no detectors.Result construction is a no-op",
			files: map[string]string{
				"util.go": `package det

func Helper() string { return "" }
`,
			},
			wantLen: 0,
		},
		{
			name: "SecretParts only mentioned in test file does NOT suppress warning",
			files: map[string]string{
				"det.go": `package det

import "github.com/trufflesecurity/trufflehog/v3/pkg/detectors"

func FromData() detectors.Result {
	return detectors.Result{
		DetectorType: 1,
		Raw:          []byte("x"),
	}
}
`,
				"det_test.go": `package det

import (
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
)

func TestZeroSecretParts(t *testing.T) {
	r := detectors.Result{}
	r.SecretParts = nil
	_ = r
}
`,
			},
			wantLen: 1,
		},
		{
			name: "pointer composite literal is detected",
			files: map[string]string{
				"det.go": `package det

import "github.com/trufflesecurity/trufflehog/v3/pkg/detectors"

func FromData() *detectors.Result {
	return &detectors.Result{
		DetectorType: 1,
		Raw:          []byte("x"),
	}
}
`,
			},
			wantLen: 1,
		},
		{
			name: "multiple construction sites reported individually",
			files: map[string]string{
				"det.go": `package det

import "github.com/trufflesecurity/trufflehog/v3/pkg/detectors"

func One() detectors.Result { return detectors.Result{Raw: []byte("a")} }
func Two() detectors.Result { return detectors.Result{Raw: []byte("b")} }
`,
			},
			wantLen: 2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, contents := range tc.files {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			got, err := CheckPackageDir(dir)
			if err != nil {
				t.Fatalf("CheckPackageDir: %v", err)
			}
			if len(got) != tc.wantLen {
				t.Fatalf("got %d findings, want %d: %+v", len(got), tc.wantLen, got)
			}
			for _, f := range got {
				if !strings.HasSuffix(f.Position.Filename, ".go") {
					t.Errorf("finding has non-Go filename: %s", f.Position.Filename)
				}
				if f.Position.Line == 0 {
					t.Errorf("finding has zero line number: %+v", f)
				}
			}
		})
	}
}

func TestCollectPackageDirs(t *testing.T) {
	root := t.TempDir()
	mustWrite := func(rel, contents string) {
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite("a/a.go", "package a\n")
	mustWrite("a/b/b.go", "package b\n")
	mustWrite("a/b/b_test.go", "package b\n") // must not cause b to be seen twice
	mustWrite("a/testdata/skipme.go", "package skipme\n")
	mustWrite("a/vendor/v.go", "package v\n")
	mustWrite("a/empty/.keep", "")

	dirs, err := collectPackageDirs([]string{root + "/..."})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, d := range dirs {
		// Trim to relative for stable comparison.
		rel, err := filepath.Rel(root, d)
		if err != nil {
			t.Fatal(err)
		}
		got[rel] = true
	}
	wantIn := []string{"a", filepath.Join("a", "b")}
	for _, w := range wantIn {
		if !got[w] {
			t.Errorf("missing expected dir %q; got %v", w, got)
		}
	}
	skip := []string{filepath.Join("a", "testdata"), filepath.Join("a", "vendor"), filepath.Join("a", "empty")}
	for _, s := range skip {
		if got[s] {
			t.Errorf("unexpected dir %q in results", s)
		}
	}
}
