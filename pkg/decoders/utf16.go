package decoders

import (
	"bytes"
	"encoding/binary"
	"fmt"
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
	endianness, err := guessUTF16Endianness(b)
	if err != nil {
		return nil, err
	}

	buf := &bytes.Buffer{}
	for i := 0; i < len(b); i += 2 {
		r := rune(endianness.Uint16(b[i:]))
		if utf8.ValidRune(r) {
			buf.WriteRune(r)
		}
	}

	return buf.Bytes(), nil
}

func guessUTF16Endianness(b []byte) (binary.ByteOrder, error) {
	if len(b) < 2 || len(b)%2 != 0 {
		return nil, fmt.Errorf("input length must be even and at least 2 bytes long")
	}

	var evenNullBytes, oddNullBytes int

	for i := 0; i < len(b); i += 2 {
		if b[i] == 0 {
			oddNullBytes++
		}
		if b[i+1] == 0 {
			evenNullBytes++
		}
	}

	if evenNullBytes > oddNullBytes {
		return binary.LittleEndian, nil
	}
	if oddNullBytes > evenNullBytes {
		return binary.BigEndian, nil
	}
	return nil, fmt.Errorf("could not determine endianness")
}
