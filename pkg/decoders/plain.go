package decoders

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// Ensure the Decoder satisfies the interface at compile time
var _ Decoder = (*Plain)(nil)

type Plain struct{}

func (d *Plain) FromChunk(chunk *sources.Chunk) *sources.Chunk {
	return chunk
}
