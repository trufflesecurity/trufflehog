package gitparse

import (
	"testing"
)

type testCase struct {
	pass     []byte
	fails    [][]byte
	function func([]byte) bool
}

func TestIsIndexLine(t *testing.T) {
	tests := map[string]testCase{
		"indexLine": {
			pass:     []byte("index 1ed6fbee1..aea1e643a 100644"),
			fails:    [][]byte{[]byte("notcorrect")},
			function: isIndexLine,
		},
		"modeLine": {
			pass:     []byte("new file mode 100644"),
			fails:    [][]byte{[]byte("notcorrect")},
			function: isModeLine,
		},
		"minusFileLine": {
			pass:     []byte("--- a/internal/addrs/move_endpoint_module.go"),
			fails:    [][]byte{[]byte("notcorrect"), []byte("short")},
			function: isMinusFileLine,
		},
		"plusFileLine": {
			pass:     []byte("+++ b/internal/addrs/move_endpoint_module.go"),
			fails:    [][]byte{[]byte("notcorrect"), []byte("short")},
			function: isPlusFileLine,
		},
		"plusDiffLine": {
			pass:     []byte("+fmt.Println"),
			fails:    [][]byte{[]byte("notcorrect")},
			function: isPlusDiffLine,
		},
		"minusDiffLine": {
			pass:     []byte("-fmt.Println"),
			function: isMinusDiffLine,
		},
		"messageLine": {
			pass:     []byte("    committed"),
			fails:    [][]byte{[]byte("notcorrect")},
			function: isMessageLine,
		},
		"binaryLine": {
			pass:     []byte("Binary files /dev/null and b/plugin.sig differ"),
			fails:    [][]byte{[]byte("notcorrect")},
			function: isBinaryLine,
		},
		"lineNumberLine": {
			pass:     []byte("@@ -298 +298 @@ func maxRetryErrorHandler(resp *http.Response, err error, numTries int)"),
			fails:    [][]byte{[]byte("notcorrect")},
			function: isLineNumberDiffLine,
		},
	}

	for name, test := range tests {
		if !test.function(test.pass) {
			t.Errorf("%s: Parser did not recognize correct line.", name)
		}
		for _, fail := range test.fails {
			if test.function(fail) {
				t.Errorf("%s: Parser did not recognize incorrect line.", name)
			}
		}
	}
}

func TestBinaryPathParse(t *testing.T) {
	filename := pathFromBinaryLine([]byte("Binary files /dev/null and b/plugin.sig differ"))
	expected := "plugin.sig"
	if filename != expected {
		t.Errorf("Expected: %s, Got: %s", expected, filename)
	}

}
