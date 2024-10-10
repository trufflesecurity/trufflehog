package common

import (
	"io"
	"reflect"
	"strings"
	"testing"
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
