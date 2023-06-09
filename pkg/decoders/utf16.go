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
	var bufBE, bufLE bytes.Buffer
	for i := 0; i < len(b)-1; i += 2 {
		if r := rune(binary.BigEndian.Uint16(b[i:])); b[i] == 0 && utf8.ValidRune(r) {
			bufBE.WriteRune(r)
		}
		if r := rune(binary.LittleEndian.Uint16(b[i:])); b[i+1] == 0 && utf8.ValidRune(r) {
			bufLE.WriteRune(r)
		}
		// Guard against index out of bounds for the next check.
		if i+1 >= len(b)-1 {
			continue
		}
	}

	return append(bufLE.Bytes(), bufBE.Bytes()...), nil
}

func guessUTF16Endianness(b []byte) (binary.ByteOrder, error) {
	if len(b) < 2 {
		return nil, fmt.Errorf("input length must at least 2 bytes long")
	}

	var evenNullBytes, oddNullBytes int

	for i := 0; i < len(b)-1; i += 2 {
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
