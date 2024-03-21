package postman

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestNewSubstitution(t *testing.T) {
	sub := NewSubstitution()
	if sub.variables == nil {
		t.Error("NewSubstitution should initialize variables map")
	}
}

func TestSubstitution_Add(t *testing.T) {
	sub := NewSubstitution()
	metadata := Metadata{
		CollectionInfo: Info{PostmanID: "col1"},
	}
	sub.add(metadata, "key1", "value1")
	sub.add(metadata, "key1", "value2")
	sub.add(metadata, "key2", "value3")

	expected := map[string][]VariableInfo{
		"key1": {
			{value: "value1", Metadata: metadata},
			{value: "value2", Metadata: metadata},
		},
		"key2": {
			{value: "value3", Metadata: metadata},
		},
	}

	if !reflect.DeepEqual(sub.variables, expected) {
		t.Errorf("Expected variables: %+v, got: %+v", expected, sub.variables)
	}
}

func TestSource_KeywordCombinations(t *testing.T) {
	s := &Source{
		DetectorKeywords: map[string]struct{}{
			"keyword1": {},
			"keyword2": {},
		},
		keywords: make(map[string]struct{}),
	}
	s.addKeyword("keyword1")
	s.addKeyword("keyword2")
	s.addKeyword("keyword3")

	// remove that \n from the end of the string
	got := strings.Split(strings.TrimSuffix(s.keywordCombinations("test"), "\n"), "\n")
	expected := []string{"keyword1:test", "keyword2:test"}

	sort.Strings(got)
	sort.Strings(expected)

	if !reflect.DeepEqual(got, expected) {
		t.Errorf("Expected keyword combinations: %q, got: %q", expected, got)
	}
}

func TestSource_BuildSubstituteSet(t *testing.T) {
	s := &Source{
		sub: NewSubstitution(),
	}
	s.sub.add(Metadata{Type: GLOBAL_TYPE}, "var1", "value1")
	s.sub.add(Metadata{Type: GLOBAL_TYPE}, "var2", "value2")

	metadata := Metadata{
		Type: GLOBAL_TYPE,
	}

	testCases := []struct {
		data     string
		expected []string
	}{
		{"{{var1}}", []string{"value1"}},
		{"{{var2}}", []string{"value2"}},
		{"{{var1}}:{{var2}}", []string{"value1:value2"}},
		{"no variables", []string{"no variables"}},
	}

	for _, tc := range testCases {
		result := s.buildSubstitueSet(metadata, tc.data)
		if !reflect.DeepEqual(result, tc.expected) {
			t.Errorf("Expected substitution set: %v, got: %v", tc.expected, result)
		}
	}
}

func TestRemoveDuplicateStr(t *testing.T) {
	testCases := []struct {
		input    []string
		expected []string
	}{
		{[]string{"a", "b", "c", "a", "b"}, []string{"a", "b", "c"}},
		{[]string{"a", "a", "a"}, []string{"a"}},
		{[]string{}, []string{}},
	}

	for _, tc := range testCases {
		result := removeDuplicateStr(tc.input)
		if !reflect.DeepEqual(result, tc.expected) {
			t.Errorf("Expected result: %v, got: %v", tc.expected, result)
		}
	}
}

func TestSource_FormatAndInjectKeywords(t *testing.T) {
	s := &Source{
		DetectorKeywords: map[string]struct{}{
			"keyword1": {},
			"keyword2": {},
		},
		keywords: make(map[string]struct{}),
	}
	s.addKeyword("keyword1")
	s.addKeyword("keyword2")
	s.addKeyword("keyword3")

	testCases := []struct {
		input    []string
		expected string
	}{
		{
			[]string{"data1", "data2"},
			"keyword1:data1\nkeyword2:data1\nkeyword1:data2\nkeyword2:data2\n",
		},
		{
			[]string{"data1"},
			"keyword1:data1\nkeyword2:data1\n",
		},
		{
			[]string{},
			"",
		},
	}

	for _, tc := range testCases {
		result := s.formatAndInjectKeywords(tc.input)
		got := strings.Split(result, "\n")
		expected := strings.Split(tc.expected, "\n")
		sort.Strings(got)
		sort.Strings(expected)

		if !reflect.DeepEqual(got, expected) {
			t.Errorf("Expected result: %q, got: %q", tc.expected, result)
		}
	}
}
