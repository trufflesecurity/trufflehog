package handlers

import (
	"bytes"
	"encoding/binary"
	"io"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ulikunitz/xz/lzma"
)

// largeDeclaredDict is a dictionary size far above maxCoderMemory that a
// crafted 7z header can declare.
const largeDeclaredDict = 3 << 30

// lzma2DictProp39 is the LZMA2 property byte that declares a 3 GiB dictionary.
const lzma2DictProp39 = 39

func oneReader(data []byte) []io.ReadCloser {
	return []io.ReadCloser{io.NopCloser(bytes.NewReader(data))}
}

// encodeLZMA compresses data as a raw 7z LZMA stream and returns its 5
// property bytes with the dictionary size replaced by dictSize.
func encodeLZMA(t *testing.T, data []byte, dictSize uint32) (props, stream []byte) {
	t.Helper()
	var buf bytes.Buffer
	w, err := lzma.WriterConfig{Size: int64(len(data))}.NewWriter(&buf)
	require.NoError(t, err)
	_, err = w.Write(data)
	require.NoError(t, err)
	require.NoError(t, w.Close())

	// A classic LZMA stream starts with a 13-byte header: the properties
	// byte, the dictionary size and the uncompressed size. 7z stores the
	// first two as coder properties and the size in the archive header.
	out := buf.Bytes()
	props = append([]byte{out[0]}, binary.LittleEndian.AppendUint32(nil, dictSize)...)
	return props, out[lzma.HeaderLen:]
}

// encodeLZMA2 compresses data as a raw LZMA2 stream.
func encodeLZMA2(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := lzma.Writer2Config{}.NewWriter2(&buf)
	require.NoError(t, err)
	_, err = w.Write(data)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return buf.Bytes()
}

// heapGrowth reports how much the live heap grows while open runs and the
// reader it returns is still reachable.
func heapGrowth(t *testing.T, open func() (io.ReadCloser, error)) (io.ReadCloser, uint64) {
	t.Helper()
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	rc, err := open()
	require.NoError(t, err)
	runtime.ReadMemStats(&after)
	if after.HeapAlloc < before.HeapAlloc {
		return rc, 0
	}
	return rc, after.HeapAlloc - before.HeapAlloc
}

func TestCappedPPMdReaderRejectsLargeModelMemory(t *testing.T) {
	props := []byte{6, 0, 0, 0, 0}

	binary.LittleEndian.PutUint32(props[1:], 0xF0000000)
	_, err := newCappedPPMdReader(props, 10, oneReader(make([]byte, 16)))
	assert.ErrorContains(t, err, "exceeds limit")

	binary.LittleEndian.PutUint32(props[1:], 1<<20)
	rc, err := newCappedPPMdReader(props, 10, oneReader(make([]byte, 16)))
	assert.NoError(t, err)
	assert.NoError(t, rc.Close())
}

func TestCappedLZMAReaderShrinksDictionaryToData(t *testing.T) {
	data := []byte("file a\nThe LZMA header declares a dictionary far larger than this.\n")
	props, stream := encodeLZMA(t, data, largeDeclaredDict)

	rc, grown := heapGrowth(t, func() (io.ReadCloser, error) {
		return newCappedLZMAReader(props, uint64(len(data)), oneReader(stream))
	})
	assert.Less(t, grown, uint64(64<<20), "dictionary should be sized to the data, not the header")

	got, err := io.ReadAll(rc)
	require.NoError(t, err)
	assert.Equal(t, data, got)
	assert.NoError(t, rc.Close())
}

func TestCappedLZMAReaderRejectsLargeDictionary(t *testing.T) {
	props, stream := encodeLZMA(t, []byte("unused"), largeDeclaredDict)
	_, err := newCappedLZMAReader(props, 1<<32, oneReader(stream))
	assert.ErrorContains(t, err, "exceeds limit")
}

func TestCappedLZMA2ReaderShrinksDictionaryToData(t *testing.T) {
	data := []byte("file a\nThe LZMA2 property declares a dictionary far larger than this.\n")
	stream := encodeLZMA2(t, data)

	rc, grown := heapGrowth(t, func() (io.ReadCloser, error) {
		return newCappedLZMA2Reader([]byte{lzma2DictProp39}, uint64(len(data)), oneReader(stream))
	})
	assert.Less(t, grown, uint64(64<<20), "dictionary should be sized to the data, not the property")

	got, err := io.ReadAll(rc)
	require.NoError(t, err)
	assert.Equal(t, data, got)
	assert.NoError(t, rc.Close())
}

func TestCappedLZMA2ReaderRejectsLargeDictionary(t *testing.T) {
	_, err := newCappedLZMA2Reader([]byte{lzma2DictProp39}, 1<<32, oneReader(nil))
	assert.ErrorContains(t, err, "exceeds limit")
}

func TestCappedCodersRejectMalformedProperties(t *testing.T) {
	tests := []struct {
		name string
		open func() (io.ReadCloser, error)
	}{
		{"ppmd short properties", func() (io.ReadCloser, error) {
			return newCappedPPMdReader([]byte{6}, 10, oneReader(nil))
		}},
		{"lzma short properties", func() (io.ReadCloser, error) {
			return newCappedLZMAReader([]byte{0x5d}, 10, oneReader(nil))
		}},
		{"lzma2 missing property", func() (io.ReadCloser, error) {
			return newCappedLZMA2Reader(nil, 10, oneReader(nil))
		}},
		{"lzma2 property out of range", func() (io.ReadCloser, error) {
			return newCappedLZMA2Reader([]byte{41}, 10, oneReader(nil))
		}},
		{"lzma two readers", func() (io.ReadCloser, error) {
			return newCappedLZMAReader(make([]byte, 5), 10, append(oneReader(nil), oneReader(nil)...))
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.open()
			assert.Error(t, err)
		})
	}
}
