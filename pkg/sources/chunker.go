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
	chunkChan := make(chan *Chunk, 1)
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
			n, err := io.ReadFull(reader, chunkBytes)
			if n > 0 {
				peekData, _ := reader.Peek(TotalChunkSize - n)
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

type chunkReaderConfig struct {
	chunkSize int
	totalSize int
	peekSize  int
}

// ConfigOption is a function that configures a chunker.
type ConfigOption func(*chunkReaderConfig)

// WithChunkSize sets the chunk size.
func WithChunkSize(size int) ConfigOption {
	return func(c *chunkReaderConfig) {
		c.chunkSize = size
	}
}

// WithPeekSize sets the peek size.
func WithPeekSize(size int) ConfigOption {
	return func(c *chunkReaderConfig) {
		c.peekSize = size
	}
}

// ChunkResult is the output unit of a ChunkReader,
// it contains the data and error of a chunk.
type ChunkResult struct {
	data []byte
	err  error
}

// Bytes for a ChunkResult.
func (cr ChunkResult) Bytes() []byte {
	return cr.data
}

// Error for a ChunkResult.
func (cr ChunkResult) Error() error {
	return cr.err
}

// ChunkReader reads chunks from a reader and returns a channel of chunks and a channel of errors.
// The channel of chunks is closed when the reader is closed.
// This should be used whenever a large amount of data is read from a reader.
// Ex: reading attachments, archives, etc.
type ChunkReader func(ctx context.Context, reader io.Reader) <-chan ChunkResult

// NewChunkReader returns a ChunkReader with the given options.
func NewChunkReader(opts ...ConfigOption) ChunkReader {
	config := applyOptions(opts)
	return createReaderFn(config)
}

func applyOptions(opts []ConfigOption) *chunkReaderConfig {
	// Set defaults.
	config := &chunkReaderConfig{
		chunkSize: ChunkSize, // default
		peekSize:  PeekSize,  // default
	}

	for _, opt := range opts {
		opt(config)
	}

	config.totalSize = config.chunkSize + config.peekSize

	return config
}

func createReaderFn(config *chunkReaderConfig) ChunkReader {
	return func(ctx context.Context, reader io.Reader) <-chan ChunkResult {
		return readInChunks(ctx, reader, config)
	}
}

func readInChunks(ctx context.Context, reader io.Reader, config *chunkReaderConfig) <-chan ChunkResult {
	const channelSize = 1
	chunkReader := bufio.NewReaderSize(reader, config.chunkSize)
	chunkResultChan := make(chan ChunkResult, channelSize)

	go func() {
		defer close(chunkResultChan)

		for {
			chunkRes := ChunkResult{}
			chunkBytes := make([]byte, config.totalSize)
			chunkBytes = chunkBytes[:config.chunkSize]
			n, err := io.ReadFull(chunkReader, chunkBytes)
			if n > 0 {
				peekData, _ := chunkReader.Peek(config.totalSize - n)
				chunkBytes = append(chunkBytes[:n], peekData...)
				chunkRes.data = chunkBytes
			}

			// If there is an error other than EOF, or if we have read some bytes, send the chunk.
			// io.ReadFull will only return io.EOF when n == 0.
			switch {
			case isErrAndNotEOF(err):
				ctx.Logger().Error(err, "error reading chunk")
				chunkRes.err = err
			case n > 0:
				chunkRes.err = nil
			default:
				return
			}

			select {
			case <-ctx.Done():
				return
			case chunkResultChan <- chunkRes:
			}

			if err != nil {
				return
			}
		}
	}()
	return chunkResultChan
}

// reportableErr checks whether the error is one we are interested in flagging.
func isErrAndNotEOF(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return false
	}
	return true
}
