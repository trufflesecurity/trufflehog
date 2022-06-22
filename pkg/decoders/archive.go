package decoders

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/mholt/archiver/v4"
	log "github.com/sirupsen/logrus"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// Ensure the Decoder satisfies the interface at compile time
var _ Decoder = (*Archive)(nil)

type Archive struct {
	newChunkData bytes.Buffer
}

func (d *Archive) FromChunk(chunk *sources.Chunk) *sources.Chunk {
	byteReader := bytes.NewReader(chunk.Data)
	chunkReader, err := d.openArchive(byteReader)
	if err != nil {
		if errors.Is(err, archiver.ErrNoMatch) {
			return nil
		}
		log.WithError(err).Debug("Error unarchiving chunk.")
		return nil
	}
	newChunkData, err := ioutil.ReadAll(chunkReader)
	if err != nil {
		log.WithError(err).Debug("Error reading unarchived chunk")
		return nil
	}
	chunk.Data = newChunkData
	return chunk
}

func (d *Archive) openArchive(reader io.Reader) (io.Reader, error) {
	ctx := context.TODO()
	format, reader, err := archiver.Identify("", reader)
	if err != nil {
		return nil, err
	}
	switch archive := format.(type) {
	case archiver.Extractor:
		log.Debug("chunk is archived")
		err := archive.Extract(ctx, reader, nil, d.extractorHandler)
		if err != nil {
			return nil, err
		}
		buf := &bytes.Buffer{}
		teedReader := io.TeeReader(&d.newChunkData, buf)
		if d.isArchive(teedReader) {
			return d.openArchive(buf)
		}
		return buf, nil
	case archiver.Decompressor:
		log.Debug("chunk is compressed")
		compReader, err := archive.OpenReader(reader)
		if err != nil {
			return nil, err
		}
		if d.isArchive(compReader) {
			return d.openArchive(compReader)
		}
		return compReader, nil
	}
	return nil, fmt.Errorf("Unknown archive type: %s", format.Name())
}

func (d *Archive) isArchive(reader io.Reader) bool {
	format, _, err := archiver.Identify("", reader)
	if err != nil {
		return false
	}
	switch format.(type) {
	case archiver.Extractor:
		return true
	case archiver.Decompressor:
		return true
	}
	return false
}

func (d *Archive) extractorHandler(ctx context.Context, f archiver.File) error {
	fReader, err := f.Open()
	if err != nil {
		return err
	}
	fileBytes, err := ioutil.ReadAll(fReader)
	if err != nil {
		return err
	}
	_, err = d.newChunkData.Write(fileBytes)
	if err != nil {
		return err
	}
	return nil
}
