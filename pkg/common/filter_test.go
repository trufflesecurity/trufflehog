package common

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestFilterBasic(t *testing.T) {
	type filterTest struct {
		filter  Filter
		pattern string
		pass    bool
	}
	tests := map[string]filterTest{
		"IncludePassed": {
			filter: Filter{
				include: &FilterRuleSet{*regexp.MustCompile("test")},
			},
			pattern: "teststring",
			pass:    true,
		},
		"IncludeFiltered": {
			filter: Filter{
				include: &FilterRuleSet{*regexp.MustCompile("nomatch")},
			},
			pattern: "teststring",
			pass:    false,
		},
		"ExcludePassed": {
			filter: Filter{
				include: &FilterRuleSet{*regexp.MustCompile("")},
				exclude: &FilterRuleSet{*regexp.MustCompile("nomatch")},
			},
			pattern: "teststring",
			pass:    true,
		},
		"ExcludeFiltered": {
			filter: Filter{
				include: &FilterRuleSet{*regexp.MustCompile("")},
				exclude: &FilterRuleSet{*regexp.MustCompile("test")},
			},
			pattern: "teststring",
			pass:    false,
		},
		"IncludeExcludeDifferentPass": {
			filter: Filter{
				include: &FilterRuleSet{*regexp.MustCompile("test")},
				exclude: &FilterRuleSet{*regexp.MustCompile("nomatch")},
			},
			pattern: "teststring",
			pass:    true,
		},
		"IncludeExcludeDifferentFiltered": {
			filter: Filter{
				include: &FilterRuleSet{*regexp.MustCompile("nomatch")},
				exclude: &FilterRuleSet{*regexp.MustCompile("test")},
			},
			pattern: "teststring",
			pass:    false,
		},
		"IncludeExcludeSameFiltered": {
			filter: Filter{
				include: &FilterRuleSet{*regexp.MustCompile("test")},
				exclude: &FilterRuleSet{*regexp.MustCompile("test")},
			},
			pattern: "teststring",
			pass:    false,
		},
	}

	for name, test := range tests {
		if test.filter.Pass(test.pattern) != test.pass {
			t.Errorf("%s: unexpected filter result. pattern: %q, pass: %t", name, test.pattern, !test.pass)
		}
	}
}

func TestFilterFromFile(t *testing.T) {
	type filterTest struct {
		includeFile         bool
		excludeFile         bool
		includeFileContents string
		excludeFileContents string
		pattern             string
		pass                bool
	}
	tests := map[string]filterTest{
		"includeFileOnlyPass": {
			includeFile:         true,
			excludeFile:         false,
			includeFileContents: "test",
			pattern:             "test",
			pass:                true,
		},
		"includeFileOnlyFiltered": {
			includeFile:         true,
			excludeFile:         false,
			includeFileContents: "nomatch",
			pattern:             "test",
			pass:                false,
		},
		"includeFileEmptyFiltered": {
			includeFile:         true,
			excludeFile:         false,
			includeFileContents: "",
			pattern:             "test",
			pass:                false,
		},
		"excludeFileOnlyPass": {
			includeFile:         false,
			excludeFile:         true,
			excludeFileContents: "nomatch",
			pattern:             "test",
			pass:                true,
		},
		"excludeFileOnlyFiltered": {
			includeFile:         false,
			excludeFile:         true,
			excludeFileContents: "test",
			pattern:             "test",
			pass:                false,
		},
		"BothFilesEmptyExcludeFiltered": {
			includeFile:         true,
			excludeFile:         true,
			excludeFileContents: "",
			includeFileContents: "",
			pattern:             "test",
			pass:                false,
		},
		"EmptyLinesAreIgnored": {
			includeFile:         false,
			excludeFile:         true,
			excludeFileContents: " \ntest.txt",
			pattern:             "hello world.txt",
			pass:                true,
		},
	}
	for name, test := range tests {
		var includeTestFile, excludeTestFile string
		if test.includeFile {
			includeTestFile = "/tmp/trufflehog_test_ifilter.txt"
			if err := testFilterWriteFile(includeTestFile, []byte(test.includeFileContents)); err != nil {
				t.Fatalf("failed to create include rules file: %s", err)
			}
			defer os.Remove(includeTestFile)
		}
		if test.excludeFile {
			excludeTestFile = "/tmp/trufflehog_test_xfilter.txt"
			if err := testFilterWriteFile(excludeTestFile, []byte(test.excludeFileContents)); err != nil {
				t.Fatalf("failed to create include rules file: %s", err)
			}
			defer os.Remove(excludeTestFile)
		}

		filter, err := FilterFromFiles(includeTestFile, excludeTestFile)
		if err != nil {
			t.Errorf("failed to create filter from files: %s", err)
		}

		if filter.Pass(test.pattern) != test.pass {
			t.Errorf("%s: unexpected filter result. pattern: %q, pass: %t", name, test.pattern, !test.pass)
		}
	}
}

func testFilterWriteFile(filename string, content []byte) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	_, err = f.Write(content)
	if err != nil {
		return err
	}
	return f.Close()
}

// TestAddTrufflehogIgnoreFiles guards the .trufflehogignore auto-discovery
// added in https://github.com/trufflesecurity/trufflehog/issues/2687.
func TestAddTrufflehogIgnoreFiles(t *testing.T) {
	root := t.TempDir()
	ignorePath := filepath.Join(root, IgnoreFileName)
	contents := strings.Join([]string{
		"# .gitignore-style ignore file",
		"",
		"vendor/",
		"*.lock",
		"/secrets/known.json",
		"src/**/*.test.go",
	}, "\n")
	if err := os.WriteFile(ignorePath, []byte(contents), 0o644); err != nil {
		t.Fatalf("write ignore file: %v", err)
	}

	filter := FilterEmpty()
	loaded, err := filter.AddTrufflehogIgnoreFiles(root)
	if err != nil {
		t.Fatalf("AddTrufflehogIgnoreFiles: %v", err)
	}
	if len(loaded) != 1 || loaded[0] != ignorePath {
		t.Fatalf("expected loaded=[%q], got %v", ignorePath, loaded)
	}

	cases := []struct {
		path     string
		excluded bool
	}{
		{"vendor/foo.go", true},
		{"src/vendor/foo.go", true},
		{"main.go", false},
		{"yarn.lock", true},
		{"deeply/nested/yarn.lock", true},
		{"secrets/known.json", true},
		{"other/secrets/known.json", false},
		{"src/foo/bar/baz.test.go", true},
		{"src/baz.test.go", true},
	}
	for _, tc := range cases {
		if got := filter.ShouldExclude(tc.path); got != tc.excluded {
			t.Errorf("path=%q: expected excluded=%v, got %v", tc.path, tc.excluded, got)
		}
	}
}

// TestAddTrufflehogIgnoreFiles_NoFile is a no-op when the ignore file is missing.
func TestAddTrufflehogIgnoreFiles_NoFile(t *testing.T) {
	filter := FilterEmpty()
	loaded, err := filter.AddTrufflehogIgnoreFiles(t.TempDir())
	if err != nil {
		t.Fatalf("expected no error for missing ignore file, got %v", err)
	}
	if len(loaded) != 0 {
		t.Errorf("expected no files loaded, got %v", loaded)
	}
}

// TestAddTrufflehogIgnoreFiles_DedupeRoots ensures the same root is processed once.
func TestAddTrufflehogIgnoreFiles_DedupeRoots(t *testing.T) {
	root := t.TempDir()
	ignorePath := filepath.Join(root, IgnoreFileName)
	if err := os.WriteFile(ignorePath, []byte("vendor/\n"), 0o644); err != nil {
		t.Fatalf("write ignore: %v", err)
	}
	filter := FilterEmpty()
	loaded, err := filter.AddTrufflehogIgnoreFiles(root, root, root)
	if err != nil {
		t.Fatalf("AddTrufflehogIgnoreFiles: %v", err)
	}
	if len(loaded) != 1 {
		t.Errorf("expected 1 loaded file (deduped), got %d", len(loaded))
	}
}

// TestAddTrufflehogIgnoreFiles_RejectsNegation surfaces a clear error for unsupported "!".
func TestAddTrufflehogIgnoreFiles_RejectsNegation(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, IgnoreFileName), []byte("!keep_me.go\n"), 0o644); err != nil {
		t.Fatalf("write ignore: %v", err)
	}
	filter := FilterEmpty()
	_, err := filter.AddTrufflehogIgnoreFiles(root)
	if err == nil || !strings.Contains(err.Error(), "re-include") {
		t.Errorf("expected re-include error, got %v", err)
	}
}

// TestGlobToRegex pins the supported gitignore-style syntax.
func TestGlobToRegex(t *testing.T) {
	cases := []struct {
		glob  string
		match []string
		miss  []string
	}{
		{"*.lock", []string{"yarn.lock", "deep/yarn.lock"}, []string{"yarnlock"}},
		{"vendor/", []string{"vendor/foo.go", "src/vendor/foo.go"}, []string{"vendorish.go"}},
		{"/secrets/key.txt", []string{"secrets/key.txt"}, []string{"src/secrets/key.txt"}},
		{"src/**/*.go", []string{"src/main.go", "src/a/b/c.go"}, []string{"main.go"}},
		{"foo?bar", []string{"foo1bar", "fooXbar"}, []string{"foo/bar", "foobar"}},
	}
	for _, tc := range cases {
		t.Run(tc.glob, func(t *testing.T) {
			rx, err := globToRegex(tc.glob)
			if err != nil {
				t.Fatalf("globToRegex(%q): %v", tc.glob, err)
			}
			for _, m := range tc.match {
				if !rx.MatchString(m) {
					t.Errorf("glob %q expected match for %q (regex=%s)", tc.glob, m, rx.String())
				}
			}
			for _, m := range tc.miss {
				if rx.MatchString(m) {
					t.Errorf("glob %q expected NO match for %q (regex=%s)", tc.glob, m, rx.String())
				}
			}
		})
	}
}
