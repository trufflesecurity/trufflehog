package sources

import (
	"bytes"
	"io"
	"math/rand"
	"runtime"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

func TestNewChunkedReader(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		chunkSize  int
		peekSize   int
		wantChunks []string
		wantErr    bool
	}{
		{
			name:       "Smaller data than default chunkSize and peekSize",
			input:      "example input",
			chunkSize:  DefaultChunkSize,
			peekSize:   DefaultPeekSize,
			wantChunks: []string{"example input"},
			wantErr:    false,
		},
		{
			name:       "Reader with no data",
			input:      "",
			chunkSize:  1024,
			peekSize:   512,
			wantChunks: []string{},
			wantErr:    false,
		},
		{
			name:       "Smaller data than chunkSize and peekSize",
			input:      "small data",
			chunkSize:  1024,
			peekSize:   512,
			wantChunks: []string{"small data"},
			wantErr:    false,
		},
		{
			name:       "Equal to chunkSize",
			input:      strings.Repeat("a", 1024),
			chunkSize:  1024,
			peekSize:   512,
			wantChunks: []string{strings.Repeat("a", 1024)},
			wantErr:    false,
		},
		{
			name:       "Equal to chunkSize + peekSize",
			input:      strings.Repeat("a", 1536),
			chunkSize:  1024,
			peekSize:   512,
			wantChunks: []string{strings.Repeat("a", 1536), strings.Repeat("a", 512)},
			wantErr:    false,
		},
		{
			name:       "EOF during peeking",
			input:      strings.Repeat("a", 1300),
			chunkSize:  1024,
			peekSize:   512,
			wantChunks: []string{strings.Repeat("a", 1300), strings.Repeat("a", 276)},
			wantErr:    false,
		},
		{
			name:       "EOF during reading",
			input:      strings.Repeat("a", 512),
			chunkSize:  1024,
			peekSize:   512,
			wantChunks: []string{strings.Repeat("a", 512)},
			wantErr:    false,
		},
		{
			name:       "Equal to totalSize",
			input:      strings.Repeat("a", 2048),
			chunkSize:  1024,
			peekSize:   1024,
			wantChunks: []string{strings.Repeat("a", 2048), strings.Repeat("a", 1024)},
			wantErr:    false,
		},
		{
			name:       "Larger than totalSize",
			input:      strings.Repeat("a", 4096),
			chunkSize:  1024,
			peekSize:   1024,
			wantChunks: []string{strings.Repeat("a", 2048), strings.Repeat("a", 2048), strings.Repeat("a", 2048), strings.Repeat("a", 1024)},
			wantErr:    false,
		},
		{
			name:       "binary data - bin",
			input:      string(generateBinaryContent("bin")),
			chunkSize:  DefaultChunkSize,
			peekSize:   DefaultPeekSize,
			wantChunks: []string{"TuffleHog"},
			wantErr:    false,
		},
		{
			name:       "binary data - exe",
			input:      string(generateBinaryContent("exe")),
			chunkSize:  DefaultChunkSize,
			peekSize:   DefaultPeekSize,
			wantChunks: []string{"MZ\x90\x03\x00\x04\x00\xff\x00\xb8:\xf2~\x11]\x9b\xc8O\xa1g0\xeb\x94,\rzV\x88\xfa\x19+\xc3\xd0nTuffleHog\xab\xcd8\x04W\xf1j\x9e\x03\xd8A\xb6/u\xcc\v\x94\xe7P8\xad\x1fc{\x0e\xf5)\xc4m\x82\x10"},
			wantErr:    false,
		},
		{
			name:       "binary data - dmg",
			input:      string(generateBinaryContent("dmg")),
			chunkSize:  DefaultChunkSize,
			peekSize:   DefaultPeekSize,
			wantChunks: []string{"\x00\x00\x00\x00TruffleHog\x00\x00\x00\x00koly"},
			wantErr:    false,
		},
		{
			name:       "binary data - tag.gz",
			input:      string(generateBinaryContent("tar.gz")),
			chunkSize:  DefaultChunkSize,
			peekSize:   DefaultPeekSize,
			wantChunks: []string{"\x1f\x8b\bthis is binary content - trufflehog\x00\x00\x00\x00"},
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			readerFunc := NewChunkReader(WithChunkSize(tt.chunkSize), WithPeekSize(tt.peekSize))
			reader := strings.NewReader(tt.input)
			ctx := context.Background()
			chunkResChan := readerFunc(ctx, reader)

			var err error
			chunks := make([]string, 0)
			for data := range chunkResChan {
				chunks = append(chunks, string(data.Bytes()))
				err = data.Error()
			}

			assert.Equal(t, tt.wantChunks, chunks, "Chunks do not match")
			if tt.wantErr {
				assert.Error(t, err, "Expected an error")
			} else {
				assert.NoError(t, err, "Unexpected error")
			}
		})
	}
}

type panicReader struct{}

var _ io.Reader = (*panicReader)(nil)

func (_ panicReader) Read([]byte) (int, error) {
	panic("panic for testing")
}

func TestChunkReader_UnderlyingReaderPanics_DoesNotPanic(t *testing.T) {
	require.NotPanics(t, func() {
		for range NewChunkReader()(context.Background(), &panicReader{}) {
		}
	})
}

func BenchmarkChunkReader(b *testing.B) {
	var bigChunk = make([]byte, 1<<24) // 16MB

	reader := bytes.NewReader(bigChunk)
	chunkReader := NewChunkReader(WithChunkSize(DefaultChunkSize), WithPeekSize(DefaultPeekSize))

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		b.StartTimer()
		chunkResChan := chunkReader(context.Background(), reader)

		// Drain the channel.
		for range chunkResChan {
		}

		b.StopTimer()
		_, err := reader.Seek(0, 0)
		assert.Nil(b, err)
	}
}

func TestFlakyChunkReader(t *testing.T) {
	a := "aaaa"
	b := "bbbb"

	reader := iotest.OneByteReader(strings.NewReader(a + b))

	chunkReader := NewChunkReader()
	chunkResChan := chunkReader(context.TODO(), reader)

	var chunks []ChunkResult
	for chunk := range chunkResChan {
		chunks = append(chunks, chunk)
	}

	assert.Equal(t, 1, len(chunks))
	chunk := chunks[0]
	assert.NoError(t, chunk.Error())
	assert.Equal(t, a+b, string(chunk.Bytes()))
}

func TestReadInChunksWithCancellation(t *testing.T) {
	largeData := strings.Repeat("large test data ", 1024*1024) // Large data string.

	for i := 0; i < 10; i++ {
		initialGoroutines := runtime.NumGoroutine()

		for j := 0; j < 5; j++ { // Call readInChunks multiple times
			ctx, cancel := context.WithCancel(context.Background())

			reader := strings.NewReader(largeData)
			chunkReader := NewChunkReader()

			chunkChan := chunkReader(ctx, reader)

			if rand.Intn(2) == 0 { // Randomly decide to cancel the context
				cancel()
			} else {
				for range chunkChan {
				}
			}
		}

		// Allow for goroutine finalization.
		time.Sleep(time.Millisecond * 100)

		// Check for goroutine leaks.
		if runtime.NumGoroutine() > initialGoroutines {
			t.Error("Potential goroutine leak detected")
		}
	}
}

// https://en.wikipedia.org/wiki/List_of_file_signatures
func generateBinaryContent(contentType string) []byte {
	switch contentType {
	case "tar.gz":
		return []byte{
			0x1F, 0x8B, 0x08, // GZIP magic + compression method
			0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20,
			0x62, 0x69, 0x6E, 0x61, 0x72, 0x79, 0x20, 0x63,
			0x6F, 0x6E, 0x74, 0x65, 0x6E, 0x74, 0x20, 0x2D,
			0x20, 0x74, 0x72, 0x75, 0x66, 0x66, 0x6C, 0x65,
			0x68, 0x6F, 0x67, 0x00, 0x00, 0x00, 0x00,
		}
	case "exe":
		return []byte{
			// https://superuser.com/questions/1334140/how-to-check-if-a-binary-is-16-bit-on-windows
			0x4D, 0x5A, // 'MZ' magic number for EXE
			0x90, 0x03, 0x00, 0x04, 0x00, 0xff, 0x00, 0xb8,
			0x3a, 0xf2, 0x7e, 0x11, 0x5d, 0x9b, 0xc8, 0x4f,
			0xa1, 0x67, 0x30, 0xeb, 0x94, 0x2c, 0x0d, 0x7a,
			0x56, 0x88, 0xfa, 0x19, 0x2b, 0xc3, 0xd0, 0x6e,
			0x54, 0x75, 0x66, 0x66, 0x6C, 0x65, 0x48, 0x6F,
			0x67, 0xab, 0xcd, 0x38, 0x04, 0x57, 0xf1, 0x6a,
			0x9e, 0x03, 0xd8, 0x41, 0xb6, 0x2f, 0x75, 0xcc,
			0x0b, 0x94, 0xe7, 0x50, 0x38, 0xad, 0x1f, 0x63,
			0x7b, 0x0e, 0xf5, 0x29, 0xc4, 0x6d, 0x82, 0x10,
		}
	case "bin":
		return []byte{0x54, 0x75, 0x66, 0x66, 0x6C, 0x65, 0x48, 0x6F, 0x67}
	case "dmg":
		return []byte{
			0x00, 0x00, 0x00, 0x00,
			0x54, 0x72, 0x75, 0x66, 0x66, 0x6C, 0x65, 0x48, 0x6F, 0x67,
			0x00, 0x00, 0x00, 0x00,
			0x6B, 0x6F, 0x6C, 0x79, // "koly" magic number for dmg
		}
	}

	return nil
}
