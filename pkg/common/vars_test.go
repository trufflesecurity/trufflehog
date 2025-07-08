package common

import (
	"strings"
	"testing"
)

func TestSkipFile(t *testing.T) {
	type testCase struct {
		file string
		want bool
	}

	// Add a test case for each ignored extension.
	testCases := make([]testCase, 0, (len(ignoredExtensions)+1)*2)
	for ext := range ignoredExtensions {
		testCases = append(testCases, testCase{
			file: "test." + ext,
			want: true,
		})

		testCases = append(testCases, testCase{
			file: "test." + strings.ToUpper(ext),
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

func TestIsBinary(t *testing.T) {
	type testCase struct {
		file string
		want bool
	}

	// Add a test case for each binary extension.
	testCases := make([]testCase, 0, len(binaryExtensions)+1)
	for ext := range binaryExtensions {
		testCases = append(testCases, testCase{
			file: "test." + ext,
			want: true,
		})
	}

	// Add a test case for a file that should not be skipped.
	testCases = append(testCases, testCase{file: "test.txt", want: false})

	for _, tt := range testCases {
		t.Run(tt.file, func(t *testing.T) {
			if got := IsBinary(tt.file); got != tt.want {
				t.Errorf("IsBinary(%v) got %v, want %v", tt.file, got, tt.want)
			}
		})
	}
}

func BenchmarkIsBinary(b *testing.B) {
	for i := 0; i < b.N; i++ {
		IsBinary("test.exe")
	}
}
