package decoders

import (
	"bytes"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func TestUTF16Decoder(t *testing.T) {
	testCases := []struct {
		name      string
		input     []byte
		expected  []byte
		expectNil bool
	}{
		{
			name:      "Valid UTF-16LE input",
			input:     []byte{72, 0, 101, 0, 108, 0, 108, 0, 111, 0, 32, 0, 87, 0, 111, 0, 114, 0, 108, 0, 100, 0},
			expected:  []byte("Hello World"),
			expectNil: false,
		},
		{
			name:      "Valid UTF-16BE input",
			input:     []byte{0, 72, 0, 101, 0, 108, 0, 108, 0, 111, 0, 32, 0, 87, 0, 111, 0, 114, 0, 108, 0, 100},
			expected:  []byte("Hello World"),
			expectNil: false,
		},
		{
			name:      "Invalid UTF-16 input (it's UTF-8)",
			input:     []byte("Hello World!"),
			expected:  nil,
			expectNil: true,
		},
		{
			name:      "Invalid UTF-16 input (odd length)",
			input:     []byte{72, 0, 101, 0, 108, 0, 108, 0, 111, 0, 32, 0, 87, 0, 111, 0, 114, 0, 108, 0, 0},
			expected:  nil,
			expectNil: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			chunk := &sources.Chunk{Data: tc.input}
			decoder := &UTF16{}
			decodedChunk := decoder.FromChunk(chunk)

			if tc.expectNil {
				if decodedChunk != nil {
					t.Errorf("Expected nil, got chunk with data: %v", decodedChunk.Data)
				}
				return
			}
			if decodedChunk == nil {
				t.Errorf("Expected chunk with data, got nil")
				return
			}
			if !bytes.Equal(decodedChunk.Data, tc.expected) {
				t.Errorf("Expected decoded data: %v, got: %v", tc.expected, decodedChunk.Data)
			}
		})
	}
}

func BenchmarkUtf16ToUtf8(b *testing.B) {
	// Example UTF-16LE encoded data
	data := []byte{72, 0, 101, 0, 108, 0, 108, 0, 111, 0, 32, 0, 87, 0, 111, 0, 114, 0, 108, 0, 100, 0}

	for n := 0; n < b.N; n++ {
		_, _ = utf16ToUTF8(data)
	}
}
