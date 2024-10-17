package hasher

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHasherHash(t *testing.T) {
	testCases := []struct {
		name        string
		hasher      Hasher
		input       []byte
		expectedHex string
		expectError error
	}{
		{
			name:        "Blake2b with 'Hello, World!'",
			hasher:      NewBlake2B(),
			input:       []byte("Hello, World!"),
			expectedHex: "511bc81dde11180838c562c82bb35f3223f46061ebde4a955c27b3f489cf1e03",
		},
		{
			name:        "Blake2b input at max size",
			hasher:      NewBlake2B(),
			input:       bytes.Repeat([]byte("a"), maxInputSize),
			expectedHex: "605fd8458957df95394e9bf812f385264267c679e4899dc198ca67db4029d0ea",
		},
		{
			name:        "Blake2b empty input",
			hasher:      NewBlake2B(),
			input:       []byte(""),
			expectedHex: "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := tc.hasher.Hash(tc.input)
			checkError(t, err, tc.expectError, len(tc.input))

			if tc.expectError != nil {
				return
			}

			expected, err := hex.DecodeString(tc.expectedHex)
			if err != nil {
				t.Fatalf("invalid expected hex string '%s': %v", tc.expectedHex, err)
			}

			if !bytes.Equal(got, expected) {
				t.Errorf("hash mismatch.\nGot:      %x\nExpected: %x", got, expected)
			}
		})
	}
}

func checkError(t *testing.T, err, expectError error, inputSize int) {
	t.Helper()

	if expectError != nil {
		var inputTooLargeError *InputTooLargeError
		if errors.As(expectError, &inputTooLargeError) {
			var inputTooLargeErr *InputTooLargeError
			if assert.ErrorAs(t, err, &inputTooLargeErr) {
				assert.Equal(t, inputSize, inputTooLargeErr.inputSize)
				assert.Equal(t, maxInputSize, inputTooLargeErr.maxSize)
			}
		}
	} else {
		assert.NoError(t, err)
	}
}

func TestBlake2bHashIdempotency(t *testing.T) {
	t.Parallel()

	hasher := NewBlake2B()
	input := bytes.Repeat([]byte("a"), maxInputSize)

	hash1, err1 := hasher.Hash(input)
	assert.NoError(t, err1, "unexpected error on first hash")

	hash2, err2 := hasher.Hash(input)
	assert.NoError(t, err2, "unexpected error on second hash")

	if !bytes.Equal(hash1, hash2) {
		t.Errorf("hash results are not identical.\nFirst:  %x\nSecond: %x", hash1, hash2)
	}
}

var sampleData = []byte("The quick brown fox jumps over the lazy dog")

// BenchmarkHasherPerGoroutine_Blake2b benchmarks hashing using separate Blake2b Hasher instances
// for each goroutine, eliminating the need for synchronization.
func BenchmarkHasherPerGoroutine_Blake2b(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		hasher := NewBlake2B()
		for pb.Next() {
			_, err := hasher.Hash(sampleData)
			assert.NoError(b, err)
		}
	})
}
