package common

import (
	"io"
	"reflect"
	"strings"
	"testing"
	"unicode"
)

func TestAddItem(t *testing.T) {
	type Case struct {
		Slice    []string
		Modifier []string
		Expected []string
	}
	tests := map[string]Case{
		"newItem": {
			Slice:    []string{"a", "b", "c"},
			Modifier: []string{"d"},
			Expected: []string{"a", "b", "c", "d"},
		},
		"newDuplicate": {
			Slice:    []string{"a", "b", "c"},
			Modifier: []string{"c"},
			Expected: []string{"a", "b", "c"},
		},
	}

	for name, test := range tests {
		for _, item := range test.Modifier {
			AddStringSliceItem(item, &test.Slice)
		}

		if !reflect.DeepEqual(test.Slice, test.Expected) {
			t.Errorf("%s: expected:%v, got:%v", name, test.Expected, test.Slice)
		}
	}
}

func TestRemoveItem(t *testing.T) {
	type Case struct {
		Slice    []string
		Modifier []string
		Expected []string
	}
	tests := map[string]Case{
		"existingItemEnd": {
			Slice:    []string{"a", "b", "c"},
			Modifier: []string{"c"},
			Expected: []string{"a", "b"},
		},
		"existingItemMiddle": {
			Slice:    []string{"a", "b", "c"},
			Modifier: []string{"b"},
			Expected: []string{"a", "c"},
		},
		"existingItemBeginning": {
			Slice:    []string{"a", "b", "c"},
			Modifier: []string{"a"},
			Expected: []string{"c", "b"},
		},
		"nonExistingItem": {
			Slice:    []string{"a", "b", "c"},
			Modifier: []string{"d"},
			Expected: []string{"a", "b", "c"},
		},
	}

	for name, test := range tests {
		for _, item := range test.Modifier {
			RemoveStringSliceItem(item, &test.Slice)
		}

		if !reflect.DeepEqual(test.Slice, test.Expected) {
			t.Errorf("%s: expected:%v, got:%v", name, test.Expected, test.Slice)
		}
	}
}

// Test ParseResponseForKeywords with a reader that contains the keyword and a reader that doesn't.
func TestParseResponseForKeywords(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		keyword  string
		expected bool
	}{
		{
			name:     "Should find keyword",
			input:    "ey: abc",
			keyword:  "ey",
			expected: true,
		},
		{
			name:     "Should not find keyword",
			input:    "fake response",
			keyword:  "ey",
			expected: false,
		},
		{
			name:     "Empty string",
			input:    "",
			keyword:  "ey",
			expected: false,
		},
		{
			name:     "Keyword at end",
			input:    "abc ey",
			keyword:  "ey",
			expected: true,
		},
		{
			name:     "Keyword at start",
			input:    "ey abc",
			keyword:  "ey",
			expected: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testReader := strings.NewReader(tc.input)
			testReadCloser := io.NopCloser(testReader)
			found, err := ResponseContainsSubstring(testReadCloser, tc.keyword)

			if err != nil {
				t.Errorf("Error: %v", err)
			}

			if found != tc.expected {
				t.Errorf("Expected %v, got %v", tc.expected, found)
			}
		})
	}
}

func TestSliceContainsString(t *testing.T) {
	testCases := []struct {
		name           string
		slice          []string
		target         string
		expectedBool   bool
		expectedString string
		expectedIndex  int
		ignoreCase     bool
	}{
		{
			name:           "matching case, target exists",
			slice:          []string{"one", "two", "three"},
			target:         "two",
			expectedBool:   true,
			expectedString: "two",
			expectedIndex:  1,
			ignoreCase:     false,
		},
		{
			name:           "non-matching case, target exists, ignore case",
			slice:          []string{"one", "two", "three"},
			target:         "Two",
			expectedBool:   true,
			expectedString: "two",
			expectedIndex:  1,
			ignoreCase:     true,
		},
		{
			name:           "non-matching case, target in wrong case, case respected",
			slice:          []string{"one", "two", "three"},
			target:         "Two",
			expectedBool:   false,
			expectedString: "",
			expectedIndex:  0,
			ignoreCase:     false,
		},
		{
			name:           "target not in slice",
			slice:          []string{"one", "two", "three"},
			target:         "four",
			expectedBool:   false,
			expectedString: "",
			expectedIndex:  0,
			ignoreCase:     false,
		},
	}
	for _, testCase := range testCases {
		resultBool, resultString, resultIndex := SliceContainsString(testCase.target, testCase.slice, testCase.ignoreCase)
		if resultBool != testCase.expectedBool {
			t.Errorf("%s: bool values do not match. Got: %t, expected: %t", testCase.name, resultBool, testCase.expectedBool)
		}
		if resultString != testCase.expectedString {
			t.Errorf("%s: string values do not match. Got: %s, expected: %s", testCase.name, resultString, testCase.expectedString)
		}
		if resultIndex != testCase.expectedIndex {
			t.Errorf("%s: index values do not match. Got: %d, expected: %d", testCase.name, resultIndex, testCase.expectedIndex)
		}
	}
}

func TestGenerateRandomPassword_Length(t *testing.T) {
	pass := GenerateRandomPassword(true, true, true, true, 16)
	if len(pass) != 16 {
		t.Errorf("expected length 16, got %d", len(pass))
	}
}

func TestGenerateRandomPassword_Empty(t *testing.T) {
	pass := GenerateRandomPassword(false, false, false, false, 10)
	if pass != "" {
		t.Errorf("expected empty string, got %q", pass)
	}
}

func TestGenerateRandomPassword_RequiredSets(t *testing.T) {
	tests := []struct {
		name    string
		lower   bool
		upper   bool
		numeric bool
		special bool
	}{
		{"lower only", true, false, false, false},
		{"upper only", false, true, false, false},
		{"numeric only", false, false, true, false},
		{"special only", false, false, false, true},
		{"all", true, true, true, true},
		{"lower+upper", true, true, false, false},
		{"lower+numeric", true, false, true, false},
		{"upper+special", false, true, false, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pass := GenerateRandomPassword(tc.lower, tc.upper, tc.numeric, tc.special, 12)
			if len(pass) != 12 {
				t.Errorf("expected length 12, got %d", len(pass))
			}
			if tc.lower && !contains(pass, unicode.IsLower) {
				t.Errorf("expected at least one lowercase letter")
			}
			if tc.upper && !contains(pass, unicode.IsUpper) {
				t.Errorf("expected at least one uppercase letter")
			}
			if tc.numeric && !contains(pass, unicode.IsDigit) {
				t.Errorf("expected at least one digit")
			}
			if tc.special && !containsSpecial(pass) {
				t.Errorf("expected at least one special character")
			}
		})
	}
}

func TestGenerateRandomPassword_ShortLength(t *testing.T) {
	pass := GenerateRandomPassword(true, true, true, true, 0)
	if pass != "" {
		t.Errorf("expected empty string for length 0, got %q", pass)
	}
}

func contains(s string, fn func(rune) bool) bool {
	for _, r := range s {
		if fn(r) {
			return true
		}
	}
	return false
}

func containsSpecial(s string) bool {
	specials := "!@#$%^&*()-_=+[]{}|;:',.<>?/"
	for _, r := range s {
		for _, sr := range specials {
			if r == sr {
				return true
			}
		}
	}
	return false
}
