package decoders

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

type UTF16 struct{}

func (d *UTF16) FromChunk(chunk *sources.Chunk) *sources.Chunk {
	if chunk == nil || len(chunk.Data) == 0 {
		return nil
	}

	if utf16Data, err := utf16ToUTF8(chunk.Data); err == nil {
		chunk.Data = utf16Data
		return chunk
	}

	return nil
}

// utf16ToUTF8 converts a byte slice containing UTF-16 encoded data to a UTF-8 encoded byte slice.
func utf16ToUTF8(b []byte) ([]byte, error) {
	if len(b)%2 != 0 {
		return nil, fmt.Errorf("input length must be even")
	}

	u16 := make([]uint16, len(b)/2)
	for i := 0; i < len(b); i += 2 {
		u16[i/2] = binary.LittleEndian.Uint16(b[i:])
	}

	decoded := utf16.Decode(u16)
	buf := &bytes.Buffer{}
	for _, r := range decoded {
		if utf8.ValidRune(r) {
			buf.WriteRune(r)
		}
	}

	return buf.Bytes(), nil
}
