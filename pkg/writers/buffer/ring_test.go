package buffer

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/exp/rand"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

func TestRingWrite(t *testing.T) {
	type writeTest struct {
		name        string
		initBufSize int    // Initial buffer size
		initData    []byte // Initial data to preload the buffer
		writeData   []byte // Data to write in the test
		wantWritten int    // Expected number of bytes written
		wantBufSize int    // Expected buffer size after write
		wantBufData []byte // Expected buffer data after write
	}

	testCases := []writeTest{
		{
			name:        "WriteWithEmptyBuffer",
			initBufSize: 10,
			initData:    nil,
			writeData:   []byte("hello"),
			wantWritten: 5,
			wantBufSize: 10,
			wantBufData: []byte("hello"),
		},
		{
			name:        "WriteWithExactFillNoInitialData",
			initBufSize: 5,
			initData:    nil,
			writeData:   []byte("hello"),
			wantWritten: 5,
			wantBufSize: 10,
			wantBufData: []byte("hello"),
		},
		{
			name:        "WriteWithPartialFill",
			initBufSize: 10,
			initData:    []byte("hi"),
			writeData:   []byte("there"),
			wantWritten: 5,
			wantBufSize: 10,
			wantBufData: []byte("hithere"),
		},
		{
			name:        "WriteWithExactFill",
			initBufSize: 5,
			initData:    []byte("hi"),
			writeData:   []byte("123"),
			wantWritten: 3,
			wantBufSize: 5,
			wantBufData: []byte("hi123"),
		},
		{
			name:        "WriteWithOverflowRequiresResize",
			initBufSize: 5,
			initData:    []byte("hi"),
			writeData:   []byte("12345"),
			wantWritten: 5,
			wantBufSize: 7, // Expecting resize to accommodate new data
			wantBufData: []byte("hi12345"),
		},
		{
			name:        "WriteWithZeroLengthData",
			initBufSize: 10,
			initData:    []byte("data"),
			writeData:   nil,
			wantWritten: 0,
			wantBufSize: 10,
			wantBufData: []byte("data"),
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := NewRingBuffer(tc.initBufSize)
			ctx := context.Background()
			if len(tc.initData) > 0 {
				_, _ = r.Write(ctx, tc.initData)
			}

			gotWritten, err := r.Write(ctx, tc.writeData)
			assert.NoError(t, err)

			assert.Equal(t, tc.wantWritten, gotWritten)
			assert.Equal(t, tc.wantBufSize, len(r.buf))
			if tc.wantWritten >= tc.initBufSize {
				assert.Equal(t, tc.wantBufData, r.buf)
			} else {
				assert.Equal(t, tc.wantBufData, r.buf[:tc.wantWritten+len(tc.initData)])
			}
		})
	}
}

func BenchmarkRingWrite(b *testing.B) {
	type benchCase struct {
		name     string
		dataSize int // Size of the data to write in bytes
	}

	benchmarks := []benchCase{
		{"1KB", 1 << 10},     // 1KB
		{"4KB", 4 << 10},     // 4KB
		{"16KB", 16 << 10},   // 16KB
		{"64KB", 64 << 10},   // 64KB
		{"256KB", 256 << 10}, // 256KB
		{"1MB", 1 << 20},     // 1MB
		{"4MB", 4 << 20},     // 4MB
		{"16MB", 16 << 20},   // 16MB
		{"64MB", 64 << 20},   // 64MB
	}

	// for _, bc := range benchmarks {
	// 	bc := bc
	data := generateData(benchmarks[3].dataSize) // Generate pseudo-random data for this benchmark case
	// b.Run(bc.name, func(b *testing.B) {
	ctx := context.Background()

	r := NewRingBuffer(defaultBufferSize)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := r.Write(ctx, data)
		assert.NoError(b, err)
		r.Reset()
	}
	// })
	// }
}

func generateData(size int) []byte {
	rand.Seed(42)
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(rand.Intn(256))
	}
	return data
}

func TestRingBufferBytes(t *testing.T) {
	tests := []struct {
		name        string
		initBufSize int
		initData    []byte
		wantBytes   []byte
	}{
		{
			name:        "EmptyBuffer",
			initBufSize: 10,
		},
		{
			name:        "PartialFill",
			initBufSize: 10,
			initData:    []byte("hello"),
			wantBytes:   []byte("hello"),
		},
		{
			name:        "FullFill",
			initBufSize: 5,
			initData:    []byte("hello"),
			wantBytes:   []byte("hello"),
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := NewRingBuffer(tc.initBufSize)
			if tc.initData != nil {
				_, _ = r.Write(context.Background(), tc.initData)
			}

			assert.Equal(t, tc.wantBytes, r.Bytes())
		})
	}
}

func TestRingBufferLen(t *testing.T) {
	tests := []struct {
		name        string
		initBufSize int
		initData    []byte
		wantLen     int
	}{
		{
			name:        "EmptyBuffer",
			initBufSize: 10,
		},
		{
			name:        "PartialFill",
			initBufSize: 10,
			initData:    []byte("hello"),
			wantLen:     5,
		},
		{
			name:        "FullFill",
			initBufSize: 5,
			initData:    []byte("hello"),
			wantLen:     5,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := NewRingBuffer(tc.initBufSize)
			if tc.initData != nil {
				_, _ = r.Write(context.Background(), tc.initData)
			}

			assert.Equal(t, tc.wantLen, r.Len())
		})
	}
}

func TestRingBufferCap(t *testing.T) {
	tests := []struct {
		name        string
		initBufSize int
		wantCap     int
	}{
		{
			name:        "InitialCapacity",
			initBufSize: 10,
			wantCap:     10,
		},
		{
			name: "ZeroCapacity",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := NewRingBuffer(tc.initBufSize)

			assert.Equal(t, tc.wantCap, r.Cap())
		})
	}
}

func TestRingBufferReset(t *testing.T) {
	tests := []struct {
		name        string
		initBufSize int
		initData    []byte
	}{
		{
			name:        "AfterWrite",
			initBufSize: 10,
			initData:    []byte("reset"),
		},
		{
			name:        "EmptyBuffer",
			initBufSize: 10,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := NewRingBuffer(tc.initBufSize)
			if tc.initData != nil {
				_, _ = r.Write(context.Background(), tc.initData)
			}

			r.Reset()
			assert.Equal(t, 0, r.Len())
			assert.Equal(t, tc.initBufSize, r.Cap())
			assert.True(t, r.isEmpty())
		})
	}
}

func TestRingBufferRead(t *testing.T) {
	tests := []struct {
		name         string
		initBufSize  int
		writeData    []byte
		readLen      int
		wantReadData []byte
	}{
		{
			name:         "ReadPartialData",
			initBufSize:  10,
			writeData:    []byte("hello"),
			readLen:      5,
			wantReadData: []byte("hello"),
		},
		{
			name:         "ReadFullData",
			initBufSize:  5,
			writeData:    []byte("hello"),
			readLen:      5,
			wantReadData: []byte("hello"),
		},
		{
			name:         "ReadEmptyBuffer",
			initBufSize:  10,
			writeData:    nil,
			readLen:      5,
			wantReadData: []byte{},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := NewRingBuffer(tc.initBufSize)
			if tc.writeData != nil {
				_, _ = r.Write(context.Background(), tc.writeData)
			}

			readData := make([]byte, tc.readLen)
			n, err := r.Read(readData)
			assert.NoError(t, err)

			assert.Equal(t, tc.wantReadData, readData[:n])
		})
	}
}
