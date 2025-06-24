package postman

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
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
	s.attemptToAddKeyword("keyword1")
	s.attemptToAddKeyword("keyword2")
	s.attemptToAddKeyword("keyword3")

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
	ctx := context.Background()

	s := &Source{
		sub: NewSubstitution(),
	}
	s.sub.add(Metadata{Type: ENVIRONMENT_TYPE}, "var1", "value1")
	s.sub.add(Metadata{Type: ENVIRONMENT_TYPE}, "var2", "value2")
	s.sub.add(Metadata{Type: ENVIRONMENT_TYPE}, "", "value2")
	s.sub.add(Metadata{Type: ENVIRONMENT_TYPE}, "continuation_token", "'{{continuation_token}}'")     // this caused an infinite loop in the original implementation
	s.sub.add(Metadata{Type: ENVIRONMENT_TYPE}, "continuation_token2", "'{{{continuation_token2}}}'") // this caused an infinite loop in the original implementation

	metadata := Metadata{
		Type: ENVIRONMENT_TYPE,
	}

	testCases := []struct {
		data     string
		expected []string
	}{
		{"{{var1}}", []string{"value1"}},
		{"{{var2}}", []string{"value2"}},
		{"{{var1}}:{{var2}}", []string{"value1:value2"}},
		{"no variables", []string{"no variables"}},
		{"{{var1}}:{{continuation_token}}", []string{"value1:{{continuation_token}}"}},
		{"{{var1}}:{{continuation_token2}}", []string{"value1:{{continuation_token2}}"}},
	}

	for _, tc := range testCases {
		result := s.buildSubstituteSet(ctx, metadata, tc.data, DefaultMaxRecursionDepth)
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
	s.attemptToAddKeyword("keyword1")
	s.attemptToAddKeyword("keyword2")
	s.attemptToAddKeyword("keyword3")

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

func TestSource_BuildSubstitution_RecursionLimit(t *testing.T) {
	ctx := context.Background()

	s := &Source{
		sub: NewSubstitution(),
	}
	metadata := Metadata{
		Type: ENVIRONMENT_TYPE,
	}

	// Setup test cases

	// 1. Self-referential variable (should be skipped)
	s.sub.add(metadata, "self_ref", "{{self_ref}}")

	// 2. Nested variables for testing recursion depth
	s.sub.add(metadata, "var1", "{{var2}}")
	s.sub.add(metadata, "var2", "{{var3}}")
	s.sub.add(metadata, "var3", "{{var4}}")
	s.sub.add(metadata, "var4", "{{var5}}")
	s.sub.add(metadata, "var5", "{{var6}}")
	s.sub.add(metadata, "var6", "{{var7}}")
	s.sub.add(metadata, "var7", "{{var8}}")
	s.sub.add(metadata, "var8", "{{var9}}")
	s.sub.add(metadata, "var9", "{{var10}}")
	s.sub.add(metadata, "var10", "{{var11}}")
	s.sub.add(metadata, "var11", "{{var12}}")
	s.sub.add(metadata, "var12", "final_value")

	// 3. Circular reference
	s.sub.add(metadata, "circular1", "{{circular2}}")
	s.sub.add(metadata, "circular2", "{{circular3}}")
	s.sub.add(metadata, "circular3", "{{circular1}}")

	testCases := []struct {
		name     string
		data     string
		expected []string
		maxDepth int
	}{
		{
			name:     "Self-referential variable",
			data:     "{{self_ref}}",
			expected: []string{"{{self_ref}}"},
		},
		{
			name:     "Nested variables within depth limit",
			data:     "{{var8}}",
			expected: []string{"{{var11}}"},
		},
		{
			name:     "Nested variables exceeding depth limit",
			data:     "{{var1}}",
			expected: []string{"{{var4}}"},
		},
		{
			name:     "Circular reference",
			data:     "{{circular1}}",
			expected: []string{"{{circular1}}"},
		},
		{
			name:     "Custom recursion depth limit (5)",
			data:     "{{var1}}",
			expected: []string{"{{var7}}"},
			maxDepth: 5,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			combos := make(map[string]struct{})

			// Use custom maxDepth if provided, otherwise use default
			if tc.maxDepth > 0 {
				s.buildSubstitution(ctx, tc.data, metadata, combos, 0, tc.maxDepth)
			} else {
				s.buildSubstitution(ctx, tc.data, metadata, combos, 0, DefaultMaxRecursionDepth)
			}

			var result []string
			for combo := range combos {
				result = append(result, combo)
			}

			// If no substitutions were made, the original data should be returned
			if len(result) == 0 {
				result = []string{tc.data}
			}

			// Sort both slices for consistent comparison
			sort.Strings(result)
			sort.Strings(tc.expected)

			if !reflect.DeepEqual(result, tc.expected) {
				t.Errorf("Expected: %v, got: %v", tc.expected, result)
			}
		})
	}
}
