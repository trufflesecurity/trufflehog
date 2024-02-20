package buffer

import (
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

// NewRingBuffer creates a new ring buffer with the given size.
func NewRingBuffer(size int) *Ring {
	return &Ring{
		buf:          make([]byte, size),
		size:         size,
		availableCap: size,
	}
}

// Write writes len(p) bytes from p to the underlying data buffer.
func (r *Ring) Write(_ context.Context, p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	if len(p) > r.availableCap {
		oldLen := r.Len()
		r.resize(len(p)+oldLen, oldLen) // Ensure there's enough space for new data
	}
	n := r.write(p)

	return n, nil
}

// WriteTo writes the buffer's data to w.
func (r *Ring) WriteTo(w io.Writer) (int64, error) {
	if r.isEmpty() {
		return 0, nil // Nothing to write
	}

	var totalWritten int64

	// If the data wraps in the buffer, write in two parts: from read pointer to end, and from start to write pointer.
	if r.wp <= r.rp {
		// Data does not wrap, can directly write from r to w
		n, err := w.Write(r.buf[r.rp:r.wp])
		totalWritten += int64(n)
		if err != nil {
			return totalWritten, err
		}
		r.rp = 0
	}

	// Data does not wrap, or we are continuing from a previous write after a wrap.
	if r.wp > 0 {
		// Data wraps, write from r to end of buffer.
		n, err := w.Write(r.buf[r.rp:])
		totalWritten += int64(n)
		if err != nil {
			r.rp = (r.rp + n) % r.size
			return totalWritten, err
		}
	}

	// Update the ring buffer's read pointer and full flag after successful write.
	// Since all data has been read, we can reset the ring buffer.
	r.Reset()

	return totalWritten, nil
}

func (r *Ring) write(p []byte) int {
	endPos := (r.wp + len(p)) % r.size
	n := len(p) // The number of bytes to write is determined by the length of p.

	// Execute the copy operation based on the relative positions of wp and rp.
	if r.wp >= r.rp {
		// Write wraps the buffer when the buffer is being re-used.
		if endPos < r.wp {
			copy(r.buf[r.wp:], p[:r.size-r.wp])
			copy(r.buf[:endPos], p[r.size-r.wp:])
		} else {
			copy(r.buf[r.wp:], p)
		}
	} else {
		copy(r.buf[r.wp:endPos], p)
	}

	r.wp = endPos
	// The buffer is full if after the write, the next write position (wp) would overwrite the read position (rp).
	// Calculate the next write position after this write.
	nextWp := (r.wp + 1) % r.size
	// Initially check if the next position after wp is rp, indicating a full buffer on the next write.
	r.isFull = nextWp == r.rp

	// Exactly full if the next write position is the read position.
	if r.wp == r.rp && n > 0 {
		r.isFull = true
	}

	r.availableCap -= n
	if r.availableCap < 0 {
		r.availableCap = 0
	}

	return n
}

func (r *Ring) resize(newSize, oldLen int) {
	newBuf := make([]byte, newSize)
	r.read(newBuf)
	r.buf = newBuf
	r.size = newSize
	r.rp = 0
	r.wp = oldLen
	r.isFull = false

	r.availableCap = newSize - oldLen
}

// Read reads up to len(p) bytes into p from the underlying data buffer.
func (r *Ring) Read(p []byte) (int, error) {
	if r.isEmpty() {
		return 0, nil
	}

	var n int
	if r.wp > r.rp {
		// Non-wrapped data: directly copy from rp to wp.
		n = copy(p, r.buf[r.rp:r.wp])
	} else {
		// Wrapped data: copy in two steps.
		// First, from rp to the end of the buffer.
		n = copy(p, r.buf[r.rp:])
		// If there's more space in p and data wrapped, copy the remaining data from the beginning.
		if n < len(p) {
			n += copy(p[n:], r.buf[:r.wp])
		}
	}

	// Update the read pointer and re-calculate the available capacity.
	r.rp = (r.rp + n) % r.size
	r.isFull = false // The buffer cannot be full after a read operation.

	r.availableCap = r.size - r.Len()

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

	return r.buf[r.rp:r.wp]
}

// isEmpty returns true if the buffer is empty.
func (r *Ring) isEmpty() bool { return !r.isFull && r.rp == r.wp }

// Len return the length of available read bytes.
func (r *Ring) Len() int {
	if r.isFull {
		return r.size
	}
	if r.wp >= r.rp {
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
