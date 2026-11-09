package handlers

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/bodgit/sevenzip"
	"github.com/stangelandcl/ppmd"
	"github.com/ulikunitz/xz/lzma"
)

// maxCoderMemory caps the working memory that a PPMd, LZMA or LZMA2 coder in a
// 7z archive may make the decoder allocate. Each of these decoders allocates
// the size declared in the archive header in one call when an entry is opened,
// before any archive size limit applies, so without a cap a small crafted
// archive can force an allocation of up to 4 GiB. 7-Zip's highest presets use
// 192 MiB for the PPMd model and 64 MiB for LZMA and LZMA2 dictionaries.
const maxCoderMemory = 256 << 20

// 7z method IDs of the coders registered below.
var (
	ppmdMethodID  = []byte{0x03, 0x04, 0x01}
	lzmaMethodID  = []byte{0x03, 0x01, 0x01}
	lzma2MethodID = []byte{0x21}
)

// sevenzip registers its own decompressors for these methods in its init, which
// runs before this one because this package imports it. Registering again
// replaces them for every 7z reader in the process.
func init() {
	sevenzip.RegisterDecompressor(ppmdMethodID, newCappedPPMdReader)
	sevenzip.RegisterDecompressor(lzmaMethodID, newCappedLZMAReader)
	sevenzip.RegisterDecompressor(lzma2MethodID, newCappedLZMA2Reader)
}

// newCappedPPMdReader is a 7z PPMd decompressor that rejects coders declaring
// more than maxCoderMemory. Otherwise it decodes the same way as the PPMd
// decompressor that sevenzip registers. Unlike a dictionary, the PPMd model
// size changes how the data decodes, so it cannot be reduced to fit the data.
func newCappedPPMdReader(props []byte, uncompressedSize uint64, readers []io.ReadCloser) (io.ReadCloser, error) {
	if len(readers) != 1 {
		return nil, fmt.Errorf("ppmd: need exactly one reader")
	}
	if len(props) != 5 {
		return nil, fmt.Errorf("ppmd: need 5 property bytes, got %d", len(props))
	}
	order := int(props[0])
	memory := binary.LittleEndian.Uint32(props[1:])
	if memory > maxCoderMemory {
		return nil, fmt.Errorf("ppmd: model memory %d exceeds limit %d", memory, maxCoderMemory)
	}

	r, err := ppmd.NewH7zReader(readers[0], order, int(memory), int(uncompressedSize))
	if err != nil {
		return nil, fmt.Errorf("ppmd: error creating reader: %w", err)
	}
	return struct {
		io.Reader
		io.Closer
	}{&r, readers[0]}, nil
}

// newCappedLZMAReader is a 7z LZMA decompressor that sizes the dictionary with
// cappedDictSize. Otherwise it decodes the same way as the LZMA decompressor
// that sevenzip registers, which prepends the coder properties and the
// uncompressed size to the stream to form a classic LZMA header.
func newCappedLZMAReader(props []byte, uncompressedSize uint64, readers []io.ReadCloser) (io.ReadCloser, error) {
	if len(readers) != 1 {
		return nil, fmt.Errorf("lzma: need exactly one reader")
	}
	if len(props) != 5 {
		return nil, fmt.Errorf("lzma: need 5 property bytes, got %d", len(props))
	}
	dictSize, err := cappedDictSize(uint64(binary.LittleEndian.Uint32(props[1:])), uncompressedSize)
	if err != nil {
		return nil, fmt.Errorf("lzma: %w", err)
	}

	header := make([]byte, 0, lzma.HeaderLen)
	header = append(header, props[0])
	header = binary.LittleEndian.AppendUint32(header, uint32(dictSize))
	header = binary.LittleEndian.AppendUint64(header, uncompressedSize)

	// The LZMA decoder reads byte by byte, and a reader without ReadByte is
	// wrapped in one that issues a Read call per byte. The input belongs to
	// this coder alone, so buffering past the end of the stream is harmless.
	r, err := lzma.NewReader(bufio.NewReader(io.MultiReader(bytes.NewReader(header), readers[0])))
	if err != nil {
		return nil, fmt.Errorf("lzma: error creating reader: %w", err)
	}
	return struct {
		io.Reader
		io.Closer
	}{r, readers[0]}, nil
}

// newCappedLZMA2Reader is a 7z LZMA2 decompressor that sizes the dictionary
// with cappedDictSize. Otherwise it decodes the same way as the LZMA2
// decompressor that sevenzip registers.
func newCappedLZMA2Reader(props []byte, uncompressedSize uint64, readers []io.ReadCloser) (io.ReadCloser, error) {
	if len(readers) != 1 {
		return nil, fmt.Errorf("lzma2: need exactly one reader")
	}
	if len(props) != 1 {
		return nil, fmt.Errorf("lzma2: need 1 property byte, got %d", len(props))
	}
	if props[0] > 40 {
		return nil, fmt.Errorf("lzma2: invalid dictionary size property %d", props[0])
	}
	// The property byte encodes the dictionary size as 2 or 3 times a power of
	// two, the same decoding as Lzma2Dec.c in the 7-Zip sources.
	declared := uint64(2|props[0]&1) << (props[0]/2 + 11)
	dictSize, err := cappedDictSize(declared, uncompressedSize)
	if err != nil {
		return nil, fmt.Errorf("lzma2: %w", err)
	}

	config := lzma.Reader2Config{DictCap: int(dictSize)}
	r, err := config.NewReader2(readers[0])
	if err != nil {
		return nil, fmt.Errorf("lzma2: error creating reader: %w", err)
	}
	return struct {
		io.Reader
		io.Closer
	}{r, readers[0]}, nil
}

// cappedDictSize returns the dictionary size to decode an LZMA or LZMA2 stream
// with, or an error if it exceeds maxCoderMemory. A back-reference never
// reaches further than the data decoded so far, so a dictionary larger than
// the stream's uncompressed size is never filled. Decoding with one reduced to
// that size gives the same output, and it means an archive that declares a
// large dictionary for a small amount of data is not rejected.
func cappedDictSize(declared, uncompressedSize uint64) (uint64, error) {
	size := max(min(declared, uncompressedSize), lzma.MinDictCap)
	if size > maxCoderMemory {
		return 0, fmt.Errorf("dictionary size %d exceeds limit %d", size, maxCoderMemory)
	}
	return size, nil
}
