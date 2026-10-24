package handlers

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/bodgit/sevenzip"
	"github.com/stangelandcl/ppmd"
)

// maxPPMdMemory caps the model memory that a PPMd coder in a 7z archive may
// declare. The PPMd decoder allocates the declared size in one call when an
// entry is opened, before any archive size limit applies, so without a cap a
// small crafted archive could force an allocation of almost 4 GiB. 7-Zip's
// highest PPMd preset uses 192 MiB.
const maxPPMdMemory = 256 << 20

// ppmdMethodID is the 7z method ID of the PPMd coder.
var ppmdMethodID = []byte{0x03, 0x04, 0x01}

func init() {
	sevenzip.RegisterDecompressor(ppmdMethodID, newCappedPPMdReader)
}

// newCappedPPMdReader is a 7z PPMd decompressor that rejects coders declaring
// more than maxPPMdMemory. Otherwise it decodes the same way as the PPMd
// decompressor that sevenzip registers.
func newCappedPPMdReader(props []byte, uncompressedSize uint64, readers []io.ReadCloser) (io.ReadCloser, error) {
	if len(readers) != 1 {
		return nil, fmt.Errorf("ppmd: need exactly one reader")
	}
	if len(props) != 5 {
		return nil, fmt.Errorf("ppmd: need 5 property bytes, got %d", len(props))
	}
	order := int(props[0])
	memory := binary.LittleEndian.Uint32(props[1:])
	if memory > maxPPMdMemory {
		return nil, fmt.Errorf("ppmd: model memory %d exceeds limit %d", memory, maxPPMdMemory)
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
