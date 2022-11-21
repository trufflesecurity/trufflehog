package decoders

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func DefaultDecoders() []Decoder {
	return []Decoder{
		&UTF8{},
		&Base64{},
	}
}

type Decoder interface {
	FromChunk(chunk *sources.Chunk) *sources.Chunk
}

// Fuzz is an entrypoint for go-fuzz, which is an AFL-style fuzzing tool.
// This one attempts to uncover any panics during decoding.
func Fuzz(data []byte) int {
	decoded := false
	for i, decoder := range DefaultDecoders() {
		// Skip the first decoder (plain), because it will always decode and give
		// priority to the input (return 1).
		if i == 0 {
			continue
		}
		chunk := decoder.FromChunk(&sources.Chunk{Data: data})
		if chunk != nil {
			decoded = true
		}
	}
	if decoded {
		return 1 // prioritize the input
	}
	return -1 // Don't add input to the corpus.
}
