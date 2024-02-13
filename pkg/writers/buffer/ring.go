package buffer

import (
	"fmt"
	"io"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

// Ring is a ring buffer implementation that implements the io.Writer and io.Reader interfaces.
type Ring struct {
	buf    []byte
	size   int
	rp     int // Read pointer
	wp     int // Write pointer
	isFull bool
	// availableCap tracks the available capacity in the buffer.
	// It avoids recalculating the available capacity on every write operation,
	// which is needed in case the buffer needs to be resized.
	availableCap int
}

func NewRingBuffer(size int) *Ring {
	return &Ring{
		buf:          make([]byte, size),
		size:         size,
		availableCap: size,
	}
}

func (r *Ring) Write(_ context.Context, p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}

	if len(p) > r.availableCap {
		oldLen := r.Len()
		r.resize(len(p)+oldLen, oldLen) // Ensure there's enough space for new data
	}

	return r.write(p)
}

func (r *Ring) WriteTo(w io.Writer) (n int64, err error) {
	if r.isEmpty() {
		return 0, nil // Nothing to write
	}

	var totalWritten int64

	// If the data wraps in the buffer, write in two parts: from read pointer to end, and from start to write pointer.
	if r.wp > r.rp {
		// Data does not wrap, can directly write from r to w
		n, err := w.Write(r.buf[r.rp:r.wp])
		totalWritten += int64(n)
		if err != nil {
			return totalWritten, err
		}
	} else {
		// Data wraps, write from r to end of buffer
		n, err := w.Write(r.buf[r.rp:])
		totalWritten += int64(n)
		if err != nil {
			return totalWritten, err
		}
		// Then, write from start of buffer to w
		if r.wp > 0 {
			n, err := w.Write(r.buf[:r.wp])
			totalWritten += int64(n)
			if err != nil {
				return totalWritten, err
			}
		}
	}

	// Update the ring buffer's read pointer and full flag after successful write.
	// Since all data has been read, we can reset the ring buffer.
	r.rp = 0
	r.wp = 0
	r.isFull = false
	r.availableCap = r.size

	return totalWritten, nil
}

func (r *Ring) write(p []byte) (n int, err error) {
	endPos := (r.wp + len(p)) % r.size
	if r.wp >= r.rp {
		if endPos < r.wp { // Write wraps the buffer
			copy(r.buf[r.wp:], p[:r.size-r.wp])
			copy(r.buf[:endPos], p[r.size-r.wp:])
		} else {
			copy(r.buf[r.wp:], p)
		}
	} else {
		copy(r.buf[r.wp:endPos], p)
	}
	r.wp = endPos
	r.isFull = r.wp == r.rp && len(p) != 0

	r.availableCap -= n
	if r.availableCap < 0 {
		r.availableCap = 0
	}

	return len(p), nil
}

func (r *Ring) resize(newSize, oldLen int) {
	newBuf := make([]byte, newSize)
	r.read(newBuf)
	r.buf = newBuf
	r.size = newSize
	r.rp = 0
	r.wp = oldLen
	r.isFull = false

	r.availableCap = newSize - r.Len()
}

func (r *Ring) Read(p []byte) (n int, err error) {
	if r.isEmpty() {
		return 0, fmt.Errorf("ring buffer is empty")
	}

	start := r.rp
	if r.wp > r.rp {
		n = copy(p, r.buf[start:r.wp])
	} else { // The buffer wraps around
		// First copy from start to the end of the buffer.
		n = copy(p, r.buf[start:])
		if n < len(p) && r.wp > 0 { // If there's more space in p and data wrapped
			// Copy the remaining data from the beginning of the buffer.
			n += copy(p[n:], r.buf[:r.wp])
		}
	}

	r.rp = (r.rp + n) % r.size
	r.isFull = false // After a read, the buffer can't be full

	r.availableCap += n
	if r.availableCap > r.size {
		r.availableCap = r.size
	}

	return n, nil
}

func (r *Ring) read(p []byte) int {
	n := copy(p, r.buf[r.rp:])
	if r.wp < r.rp {
		n += copy(p[n:], r.buf[:r.wp])
	}
	return n
}

// Bytes returns a copy of the buffer's data.
func (r *Ring) Bytes() []byte {
	if r.isEmpty() {
		return nil
	}

	data := make([]byte, r.Len())
	r.Read(data)
	return data
}

func (r *Ring) isEmpty() bool { return r.Len() == 0 }

// Len return the length of available read bytes.
func (r *Ring) Len() int {
	if r.wp == r.rp {
		if r.isFull {
			return r.size
		}
		return 0
	}

	if r.wp > r.rp {
		return r.wp - r.rp
	}

	return r.size - r.rp + r.wp
}

// Cap returns the size of the underlying buffer.
func (r *Ring) Cap() int {
	return r.size
}

// Reset resets the buffer.
func (r *Ring) Reset() {
	r.rp = 0
	r.wp = 0
	r.isFull = false
	r.availableCap = r.size
}
