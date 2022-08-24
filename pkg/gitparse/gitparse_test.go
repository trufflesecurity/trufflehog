package gitparse

import (
	"testing"
)

type testCase struct {
	pass     []byte
	fail     []byte
	function func([]byte) bool
}

func TestIsIndexLine(t *testing.T) {
	tests := map[string]testCase{
		"indexLine": {
			pass:     []byte("index 1ed6fbee1..aea1e643a 100644"),
			fail:     []byte("notcorrect"),
			function: isIndexLine,
		},
		"modeLine": {
			pass:     []byte("new file mode 100644"),
			fail:     []byte("notcorrect"),
			function: isModeLine,
		},
		"minusFileLine": {
			pass:     []byte("--- a/internal/addrs/move_endpoint_module.go"),
			fail:     []byte("notcorrect"),
			function: isMinusFileLine,
		},
		"plusFileLine": {
			pass:     []byte("+++ b/internal/addrs/move_endpoint_module.go"),
			fail:     []byte("notcorrect"),
			function: isPlusFileLine,
		},
		"plusDiffLine": {
			pass:     []byte("+fmt.Println"),
			fail:     []byte("notcorrect"),
			function: isPlusDiffLine,
		},
		"minusDiffLine": {
			pass:     []byte("-fmt.Println"),
			fail:     []byte("notcorrect"),
			function: isMinusDiffLine,
		},
		"messageLine": {
			pass:     []byte("    committed"),
			fail:     []byte("notcorrect"),
			function: isMessageLine,
		},
		"binaryLine": {
			pass:     []byte("Binary files /dev/null and b/plugin.sig differ"),
			fail:     []byte("notcorrect"),
			function: isBinaryLine,
		},
		"lineNumberLine": {
			pass:     []byte("@@ -298 +298 @@ func maxRetryErrorHandler(resp *http.Response, err error, numTries int)"),
			fail:     []byte("notcorrect"),
			function: isLineNumberDiffLine,
		},
	}

	for name, test := range tests {
		if !test.function(test.pass) {
			t.Errorf("%s: Parser did not recognize correct line.", name)
		}
		if test.function(test.fail) {
			t.Errorf("%s: Parser matched an incorrect line.", name)
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
