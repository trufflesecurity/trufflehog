package common

import (
	"os"
	"regexp"
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
