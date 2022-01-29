package common

import (
	"reflect"
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
