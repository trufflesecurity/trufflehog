package common

import "testing"

func TestSkipFile(t *testing.T) {
	type testCase struct {
		file string
		want bool
	}

	// Add a test case for each ignored extension.
	testCases := make([]testCase, 0, len(IgnoredExtensions)+1)
	for _, ext := range IgnoredExtensions {
		testCases = append(testCases, testCase{
			file: "test." + ext,
			want: true,
		})
	}

	// Add a test case for a file that should not be skipped.
	testCases = append(testCases, testCase{file: "test.txt", want: false})

	for _, tt := range testCases {
		t.Run(tt.file, func(t *testing.T) {
			if got := SkipFile(tt.file); got != tt.want {
				t.Errorf("SkipFile(%v) got %v, want %v", tt.file, got, tt.want)
			}
		})
	}
}

func BenchmarkSkipFile(b *testing.B) {
	for i := 0; i < b.N; i++ {
		SkipFile("test.mp4")
	}
}
