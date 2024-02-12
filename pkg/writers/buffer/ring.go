package buffer

import (
	"errors"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

var (
	ErrBufferFull         = errors.New("ring buffer is full")
	ErrTooManyDataToWrite = errors.New("too much data to write to ring buffer")
	ErrAcquireLock        = errors.New("unable to acquire lock for writing")
)

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
	if r.IsEmpty() {
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

// Cap returns the current capacity of the buffer.

// Bytes returns a copy of the buffer's data.
func (r *Ring) Bytes() []byte {
	if r.IsEmpty() {
		return nil
	}

	data := make([]byte, r.Len())
	r.Read(data)
	return data
}

// IsEmpty returns true if the buffer is empty.
func (r *Ring) IsEmpty() bool { return r.Len() == 0 }

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
