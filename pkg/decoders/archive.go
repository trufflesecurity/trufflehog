package decoders

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/mholt/archiver/v4"
	log "github.com/sirupsen/logrus"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// Ensure the Decoder satisfies the interface at compile time
var _ Decoder = (*Archive)(nil)

var (
	MaxDepth = 5
	MaxSize  = 100 // In MB
)

type Archive struct {
	files        [][]byte
	newChunkData bytes.Buffer
}

func (d *Archive) FromChunk(chunk *sources.Chunk) *sources.Chunk {
	ctx := context.Background()
	byteReader := bytes.NewReader(chunk.Data)
	err := d.openArchive(ctx, 0, byteReader)
	if err != nil {
		if errors.Is(err, archiver.ErrNoMatch) {
			return nil
		}
		log.WithError(err).Debug("Error unarchiving chunk.")
		return nil
	}
	chunk.Data = bytes.Join(d.files, []byte{})
	return chunk
}

func (d *Archive) openArchive(ctx context.Context, depth int, reader io.Reader) error {
	if depth >= MaxDepth {
		return fmt.Errorf("max archive depth reached")
	}
	format, reader, err := archiver.Identify("", reader)
	if err != nil {
		if errors.Is(err, archiver.ErrNoMatch) && depth > 0 {
			fileBytes, err := ReadToMax(reader)
			if err != nil {
				return err
			}
			d.files = append(d.files, fileBytes)
			return nil
		}
		return err
	}
	switch archive := format.(type) {
	case archiver.Extractor:
		log.Debug("chunk is archived")
		err := archive.Extract(context.WithValue(ctx, "depth", depth+1), reader, nil, d.extractorHandler)
		if err != nil {
			return err
		}
		return nil
	case archiver.Decompressor:
		log.Debug("chunk is compressed")
		compReader, err := archive.OpenReader(reader)
		if err != nil {
			return err
		}
		return d.openArchive(ctx, depth+1, compReader)
	}
	return fmt.Errorf("Unknown archive type: %s", format.Name())
}

func IsArchive(reader io.Reader) bool {
	format, readerB, err := archiver.Identify("", reader)
	reader = readerB
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
	depth := 0
	if ctxDepth, ok := ctx.Value("depth").(int); ok {
		depth = ctxDepth
	}

	fReader, err := f.Open()
	if err != nil {
		return err
	}
	fileBytes, err := ReadToMax(fReader)
	if err != nil {
		return err
	}
	fileContent := bytes.NewReader(fileBytes)
	err = d.openArchive(ctx, depth, fileContent)
	if err != nil {
		return err
	}
	return nil
}

func ReadToMax(reader io.Reader) ([]byte, error) {
	// Read the file up to the max size.
	fileContent := bytes.Buffer{}
	for i := 0; i <= MaxSize*1024; i++ {
		fileChunk := make([]byte, 1024)
		bRead, err := reader.Read(fileChunk)
		if err != nil {
			return []byte{}, err
		}
		fileContent.Write(fileChunk[0:bRead])
		if bRead < 1024 {
			break
		}
		if i == MaxSize*1024 && bRead == 1024 {
			log.Debug("Max archive size reached.")
		}
	}
	return fileContent.Bytes(), nil
}
