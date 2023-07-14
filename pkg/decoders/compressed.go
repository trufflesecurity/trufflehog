package decoders

import (
	"bytes"

	"github.com/mholt/archiver/v4"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

type (
	Compressed struct{}
)

func (d *Compressed) FromChunk(chunk *sources.Chunk) *sources.Chunk {

	unzipped, err := func(decoded *sources.Chunk) (*bytes.Buffer, error) {
		format, reader, err := archiver.Identify("", bytes.NewReader(decoded.Data))
		buf := new(bytes.Buffer)

		switch archive := format.(type) {
		case archiver.Decompressor:
			compReader, err := archive.OpenReader(reader)
			if err != nil {
				return buf, err
			}
			buf.ReadFrom(compReader)
			compReader.Close()
		default:
			return buf, err
		}

		return buf, err
	}(chunk)

	if err != nil || len(unzipped.Bytes()) == 0 {
		return nil
	}

	if len(unzipped.Bytes()) > 0 {
		chunk.Data = unzipped.Bytes()
		return chunk
	}

	return nil
}
