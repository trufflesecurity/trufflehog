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
	testReader := strings.NewReader("ey: abc")
	testReadCloser := io.NopCloser(testReader)
	found, err := ParseResponseForKeywords(testReadCloser, []string{"ey"})

	if err != nil {
		t.Errorf("Error: %v", err)
	}

	if !found {
		t.Errorf("Expected true, got %+v", found)
	}

	testReader2 := strings.NewReader("fake response")
	testReadCloser2 := io.NopCloser(testReader2)
	found, err = ParseResponseForKeywords(testReadCloser2, []string{"ey"})

	if err != nil {
		t.Errorf("Error: %v", err)
	}

	if found {
		t.Errorf("Expected false, got %+v", found)
	}

}
