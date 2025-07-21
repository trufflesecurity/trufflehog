package decoders

import (
	"bytes"
	"encoding/binary"
	"unicode/utf8"

	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

type UTF16 struct{}

func (d *UTF16) Type() detectorspb.DecoderType {
	return detectorspb.DecoderType_UTF16
}

func (d *UTF16) FromChunk(chunk *sources.Chunk) *DecodableChunk {
	if chunk == nil || len(chunk.Data) == 0 {
		return nil
	}

	decodableChunk := &DecodableChunk{Chunk: chunk, DecoderType: d.Type()}
	if utf16Data, err := utf16ToUTF8(chunk.Data); err == nil {
		if len(utf16Data) == 0 {
			return nil
		}
		chunk.Data = utf16Data
		return decodableChunk
	}

	return nil
}

// utf16ToUTF8 converts a byte slice containing UTF-16 encoded data to a UTF-8 encoded byte slice.
func utf16ToUTF8(b []byte) ([]byte, error) {

	if len(b) < 2 {
		return []byte{}, nil
	}

	start := 0
	if b[0] == 0xFF && b[1] == 0xFE {
		start = 2
	} else if b[0] == 0xFE && b[1] == 0xFF {
		start = 2
	}

	var bufBE, bufLE bytes.Buffer
	for i := start; i < len(b)-1; i += 2 {
		if r := rune(binary.BigEndian.Uint16(b[i:])); b[i] == 0 && utf8.ValidRune(r) {
			if isPrintableByte(byte(r)) {
				bufBE.WriteRune(r)
			}
		}
		if r := rune(binary.LittleEndian.Uint16(b[i:])); b[i+1] == 0 && utf8.ValidRune(r) {
			if isPrintableByte(byte(r)) {
				bufLE.WriteRune(r)
			}
		}
	}

	return append(bufLE.Bytes(), bufBE.Bytes()...), nil
}
