package sources

import (
	"bufio"
	"bytes"
	"errors"
	"io"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

const (
	// ChunkSize is the maximum size of a chunk.
	ChunkSize = 10 * 1024
	// PeekSize is the size of the peek into the previous chunk.
	PeekSize = 3 * 1024
	// TotalChunkSize is the total size of a chunk with peek data.
	TotalChunkSize = ChunkSize + PeekSize
)

// Chunker takes a chunk and splits it into chunks of ChunkSize.
func Chunker(originalChunk *Chunk) chan *Chunk {
	chunkChan := make(chan *Chunk)
	go func() {
		defer close(chunkChan)
		if len(originalChunk.Data) <= TotalChunkSize {
			chunkChan <- originalChunk
			return
		}

		r := bytes.NewReader(originalChunk.Data)
		reader := bufio.NewReaderSize(bufio.NewReader(r), ChunkSize)
		for {
			chunkBytes := make([]byte, TotalChunkSize)
			chunk := *originalChunk
			chunkBytes = chunkBytes[:ChunkSize]
			n, err := reader.Read(chunkBytes)
			if n > 0 {
				peekData, _ := reader.Peek(len(chunkBytes) - n)
				chunkBytes = append(chunkBytes[:n], peekData...)
				chunk.Data = chunkBytes
				chunkChan <- &chunk
			}
			if err != nil {
				break
			}
		}
	}()
	return chunkChan
}

type chunkerConfig struct {
	chunkSize int
	totalSize int
	peekSize  int
}

// ConfigOption is a function that configures a chunker.
type ConfigOption func(*chunkerConfig)

// WithChunkSize sets the chunk size.
func WithChunkSize(size int) ConfigOption {
	return func(c *chunkerConfig) {
		c.chunkSize = size
	}
}

// WithTotalChunkSize sets the total chunk size.
// This is the chunk size plus the peek size.
func WithTotalChunkSize(size int) ConfigOption {
	return func(c *chunkerConfig) {
		c.totalSize = size
	}
}

// WithPeekSize sets the peek size.
func WithPeekSize(size int) ConfigOption {
	return func(c *chunkerConfig) {
		c.peekSize = size
	}
}

// ChunkReader reads chunks from a reader and returns a channel of chunks and a channel of errors.
// The channel of chunks is closed when the reader is closed.
// This should be used whenever a large amount of data is read from a reader.
// Ex: reading attachments, archives, etc.
type ChunkReader func(ctx context.Context, reader io.Reader) (<-chan []byte, <-chan error)

// NewChunkReader returns a ChunkReader with the given options.
func NewChunkReader(opts ...ConfigOption) ChunkReader {
	config := applyOptions(opts)
	return createReaderFn(config)
}

func applyOptions(opts []ConfigOption) *chunkerConfig {
	// Set defaults.
	config := &chunkerConfig{
		chunkSize: ChunkSize,      // default
		totalSize: TotalChunkSize, // default
		peekSize:  PeekSize,       // default
	}

	for _, opt := range opts {
		opt(config)
	}

	return config
}

func createReaderFn(config *chunkerConfig) ChunkReader {
	return func(ctx context.Context, reader io.Reader) (<-chan []byte, <-chan error) {
		return readInChunks(ctx, reader, config)
	}
}

func readInChunks(ctx context.Context, reader io.Reader, config *chunkerConfig) (<-chan []byte, <-chan error) {
	const channelSize = 1
	chunkReader := bufio.NewReaderSize(reader, config.chunkSize)
	dataChan := make(chan []byte, channelSize)
	errChan := make(chan error, channelSize)

	go func() {
		defer close(dataChan)
		defer close(errChan)

		for {
			chunkBytes := make([]byte, config.totalSize)
			chunkBytes = chunkBytes[:config.chunkSize]
			n, err := chunkReader.Read(chunkBytes)
			if n > 0 {
				peekData, _ := chunkReader.Peek(len(chunkBytes) - n)
				chunkBytes = append(chunkBytes[:n], peekData...)
				dataChan <- chunkBytes
			}

			if err != nil {
				if !errors.Is(err, io.EOF) {
					ctx.Logger().Error(err, "error reading chunk")
					errChan <- err
				}
				return
			}
		}
	}()
	return dataChan, errChan
}
