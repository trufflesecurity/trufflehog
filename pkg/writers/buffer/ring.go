package buffer

import (
	"errors"
	"io"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

// Ring is a ring buffer implementation that implements the io.Writer and io.Reader interfaces.
type Ring struct {
	buf          []byte
	size         int
	r            int // Read pointer
	w            int // Write pointer
	isFull       bool
	availableCap int
}

func NewRingBuffer(size int) *Ring {
	return &Ring{
		buf:  make([]byte, size),
		size: size,
	}
}

func (r *Ring) Write(_ context.Context, p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}

	if len(p) > r.availableCap {
		r.resize(len(p) + r.Len()) // Ensure there's enough space for new data
	}

	return r.write(p)
}

func (r *Ring) WriteTo(w io.Writer) (n int64, err error) {
	if r.isEmpty() {
		return 0, nil // Nothing to write
	}

	var totalWritten int64

	// If the data wraps in the buffer, write in two parts: from read pointer to end, and from start to write pointer.
	if r.w > r.r {
		// Data does not wrap, can directly write from r to w
		n, err := w.Write(r.buf[r.r:r.w])
		totalWritten += int64(n)
		if err != nil {
			return totalWritten, err
		}
	} else {
		// Data wraps, write from r to end of buffer
		n, err := w.Write(r.buf[r.r:])
		totalWritten += int64(n)
		if err != nil {
			return totalWritten, err
		}
		// Then, write from start of buffer to w
		if r.w > 0 {
			n, err := w.Write(r.buf[:r.w])
			totalWritten += int64(n)
			if err != nil {
				return totalWritten, err
			}
		}
	}

	// Update the ring buffer's read pointer and full flag after successful write
	// Since all data has been read, we can reset the ring buffer
	r.r = 0
	r.w = 0
	r.isFull = false
	r.availableCap = r.size

	return totalWritten, nil
}

func (r *Ring) write(p []byte) (n int, err error) {
	endPos := (r.w + len(p)) % r.size
	if r.w >= r.r {
		if endPos < r.w { // Write wraps the buffer
			copy(r.buf[r.w:], p[:r.size-r.w])
			copy(r.buf[:endPos], p[r.size-r.w:])
		} else {
			copy(r.buf[r.w:], p)
		}
	} else {
		copy(r.buf[r.w:endPos], p)
	}
	r.w = endPos
	r.isFull = r.w == r.r && len(p) != 0

	r.availableCap -= n
	if r.availableCap < 0 {
		r.availableCap = 0
	}

	return len(p), nil
}

func (r *Ring) resize(newSize int) {
	newBuf := make([]byte, newSize)
	oldLen := r.Len()
	r.read(newBuf)
	r.buf = newBuf
	r.size = newSize
	r.r = 0
	r.w = oldLen
	r.isFull = false

	r.availableCap = newSize - r.Len()
}

func (r *Ring) Read(p []byte) (n int, err error) {
	if r.isEmpty() {
		return 0, errors.New("ring buffer is empty")
	}

	start := r.r
	if r.w > r.r {
		n = copy(p, r.buf[start:r.w])
	} else { // The buffer wraps around
		// First copy from start to the end of the buffer
		n = copy(p, r.buf[start:])
		if n < len(p) && r.w > 0 { // If there's more space in p and data wrapped
			// Copy the remaining data from the beginning of the buffer
			n += copy(p[n:], r.buf[:r.w])
		}
	}

	r.r = (r.r + n) % r.size
	r.isFull = false // After a read, the buffer can't be full

	r.availableCap += n
	if r.availableCap > r.size {
		r.availableCap = r.size
	}

	return n, nil
}

func (r *Ring) read(p []byte) int {
	n := copy(p, r.buf[r.r:])
	if r.w < r.r {
		n += copy(p[n:], r.buf[:r.w])
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
	if r.w == r.r {
		if r.isFull {
			return r.size
		}
		return 0
	}

	if r.w > r.r {
		return r.w - r.r
	}

	return r.size - r.r + r.w
}

// Cap returns the size of the underlying buffer.
func (r *Ring) Cap() int {
	return r.size
}

// Reset resets the buffer.
func (r *Ring) Reset() {
	r.r = 0
	r.w = 0
	r.isFull = false
	r.availableCap = r.size
}
