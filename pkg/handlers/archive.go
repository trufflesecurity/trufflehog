package handlers

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/mholt/archiver/v4"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

type ctxKey int

const (
	depthKey ctxKey = iota
)

var (
	maxDepth   = 5
	maxSize    = 250 * 1024 * 1024 // 20MB
	maxTimeout = time.Duration(30) * time.Second
)

// Archive is a handler for extracting and decompressing archives.
type Archive struct {
	size int
}

// New sets a default maximum size and current size counter.
func (d *Archive) New() {
	d.size = 0
}

// SetArchiveMaxSize sets the maximum size of the archive.
func SetArchiveMaxSize(size int) {
	maxSize = size
}

// SetArchiveMaxDepth sets the maximum depth of the archive.
func SetArchiveMaxDepth(depth int) {
	maxDepth = depth
}

// SetArchiveMaxTimeout sets the maximum timeout for the archive handler.
func SetArchiveMaxTimeout(timeout time.Duration) {
	maxTimeout = timeout
}

// FromFile extracts the files from an archive.
func (d *Archive) FromFile(originalCtx context.Context, data io.Reader) chan ([]byte) {
	archiveChan := make(chan ([]byte), 512)
	go func() {
		ctx, cancel := context.WithTimeout(originalCtx, maxTimeout)
		logger := logContext.AddLogger(ctx).Logger()
		defer cancel()
		defer close(archiveChan)
		err := d.openArchive(ctx, 0, data, archiveChan)
		if err != nil {
			if errors.Is(err, archiver.ErrNoMatch) {
				return
			}
			logger.V(2).Info("Error unarchiving chunk.")
		}
	}()
	return archiveChan
}

// openArchive takes a reader and extracts the contents up to the maximum depth.
func (d *Archive) openArchive(ctx context.Context, depth int, reader io.Reader, archiveChan chan ([]byte)) error {
	if depth >= maxDepth {
		return fmt.Errorf("max archive depth reached")
	}
	format, reader, err := archiver.Identify("", reader)
	if err != nil {
		if errors.Is(err, archiver.ErrNoMatch) && depth > 0 {
			chunkSize := 10 * 1024
			for {
				chunk := make([]byte, chunkSize)
				n, _ := reader.Read(chunk)
				archiveChan <- chunk
				if n < chunkSize {
					break
				}
			}
			return nil
		}
		return err
	}
	switch archive := format.(type) {
	case archiver.Extractor:
		err := archive.Extract(context.WithValue(ctx, depthKey, depth+1), reader, nil, d.extractorHandler(archiveChan))
		if err != nil {
			return err
		}
		return nil
	case archiver.Decompressor:
		compReader, err := archive.OpenReader(reader)
		if err != nil {
			return err
		}
		fileBytes, err := d.ReadToMax(ctx, compReader)
		if err != nil {
			return err
		}
		newReader := bytes.NewReader(fileBytes)
		return d.openArchive(ctx, depth+1, newReader, archiveChan)
	}
	return fmt.Errorf("Unknown archive type: %s", format.Name())
}

// IsFiletype returns true if the provided reader is an archive.
func (d *Archive) IsFiletype(ctx context.Context, reader io.Reader) (io.Reader, bool) {
	format, readerB, err := archiver.Identify("", reader)
	if err != nil {
		return readerB, false
	}
	switch format.(type) {
	case archiver.Extractor:
		return readerB, true
	case archiver.Decompressor:
		return readerB, true
	}
	return readerB, false
}

// extractorHandler is applied to each file in an archiver.Extractor file.
func (d *Archive) extractorHandler(archiveChan chan ([]byte)) func(context.Context, archiver.File) error {
	return func(ctx context.Context, f archiver.File) error {
		logger := logContext.AddLogger(ctx).Logger()
		logger.V(5).Info("Handling extracted file.", "filename", f.Name())
		depth := 0
		if ctxDepth, ok := ctx.Value(depthKey).(int); ok {
			depth = ctxDepth
		}

		fReader, err := f.Open()
		if err != nil {
			return err
		}
		fileBytes, err := d.ReadToMax(ctx, fReader)
		if err != nil {
			return err
		}
		fileContent := bytes.NewReader(fileBytes)

		err = d.openArchive(ctx, depth, fileContent, archiveChan)
		if err != nil {
			return err
		}
		return nil
	}
}

// ReadToMax reads up to the max size.
func (d *Archive) ReadToMax(ctx context.Context, reader io.Reader) (data []byte, err error) {
	// Archiver v4 is in alpha and using an experimental version of
	// rardecode. There is a bug somewhere with rar decoder format 29
	// that can lead to a panic. An issue is open in rardecode repo
	// https://github.com/nwaples/rardecode/issues/30.
	logger := logContext.AddLogger(ctx).Logger()
	defer func() {
		if r := recover(); r != nil {
			// Return an error from ReadToMax.
			if e, ok := r.(error); ok {
				err = e
			} else {
				err = fmt.Errorf("Panic occurred: %v", r)
			}
			logger.Error(err, "Panic occurred when reading archive")
		}
	}()
	fileContent := bytes.Buffer{}
	logger.V(5).Info("Remaining buffer capacity", "bytes", maxSize-d.size)
	for i := 0; i <= maxSize/512; i++ {
		if common.IsDone(ctx) {
			return nil, ctx.Err()
		}
		fileChunk := make([]byte, 512)
		bRead, err := reader.Read(fileChunk)
		if err != nil && !errors.Is(err, io.EOF) {
			return []byte{}, err
		}
		d.size += bRead
		if len(fileChunk) > 0 {
			fileContent.Write(fileChunk[0:bRead])
		}
		if bRead < 512 {
			return fileContent.Bytes(), nil
		}
		if d.size >= maxSize && bRead == 512 {
			logger.V(2).Info("Max archive size reached.")
			return fileContent.Bytes(), nil
		}
	}
	return fileContent.Bytes(), nil
}
