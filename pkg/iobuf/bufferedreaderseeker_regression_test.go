package iobuf

// Regression tests for https://github.com/trufflesecurity/trufflehog/issues/4569
// (BufferedReadSeeker state corruption): after the 16MB in-memory threshold
// is crossed, seeks back into already-buffered data returned bytes from the
// wrong offset, and seek prefetching re-entered Read through the reader
// itself. The deterministic test below failed before the fix (bytes from
// the 16MB mark came back for offset 0) and passes after it.

import (
	"bytes"
	"io"
	"math/rand"
	"testing"
)

// Non-seekable reader that returns short reads (like a zip decompressor).
type shortReader struct {
	data []byte
	pos  int
	max  int
}

func (s *shortReader) Read(p []byte) (int, error) {
	if s.pos >= len(s.data) {
		return 0, io.EOF
	}
	n := len(p)
	if n > s.max {
		n = s.max
	}
	if n > len(s.data)-s.pos {
		n = len(s.data) - s.pos
	}
	copy(p, s.data[s.pos:s.pos+n])
	s.pos += n
	return n, nil
}

func patternData(n int) []byte {
	d := make([]byte, n)
	for i := range d {
		d[i] = byte((i*31 + i/257) % 256)
	}
	return d
}

// TestBufferedReadSeekerPostFlushSeek deterministically probes reads after the 16MB
// in-memory threshold is crossed (temp file path, Size() never called).
func TestBufferedReadSeekerPostFlushSeek(t *testing.T) {
	data := patternData(20 << 20)
	br := NewBufferedReaderSeeker(&shortReader{data: data, max: 65536})
	defer br.Close()
	// Sequential read past the threshold to force a flush to disk.
	buf := make([]byte, 1<<20)
	var total int
	for total < len(data) {
		n, err := br.Read(buf)
		total += n
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("sequential read err: %v", err)
		}
	}
	if total != len(data) {
		t.Fatalf("sequential read got %d bytes, want %d", total, len(data))
	}
	check := func(off int64, want []byte) {
		t.Helper()
		if _, err := br.Seek(off, io.SeekStart); err != nil {
			t.Fatalf("Seek(%d) err: %v", off, err)
		}
		got := make([]byte, len(want))
		n, err := br.Read(got)
		if err != nil && err != io.EOF {
			t.Fatalf("Read at %d err: %v", off, err)
		}
		if n != len(want) || !bytes.Equal(got[:n], want) {
			t.Fatalf("Read at %d: got %d bytes %v..., want %v...", off, n, got[:min(n, 8)], want[:8])
		}
	}
	check(0, data[0:64])
	check(100, data[100:164])
	check((16<<20)-100, data[(16<<20)-100:(16<<20)-36])
	check(16<<20, data[16<<20:16<<20+64])
	check(int64(len(data))-64, data[len(data)-64:])
	// ReadAt variants on the same reader.
	for _, off := range []int64{0, 100, (16 << 20) - 100, 16 << 20, int64(len(data)) - 64} {
		got := make([]byte, 64)
		n, err := br.ReadAt(got, off)
		if err != nil && err != io.EOF {
			t.Fatalf("ReadAt(%d) err: %v", off, err)
		}
		if n != 64 || !bytes.Equal(got, data[off:off+64]) {
			t.Fatalf("ReadAt(%d): got %d bytes %v..., want %v...", off, n, got[:8], data[off:off+8])
		}
	}
}

// TestBufferedReadSeekerRandomSeekRead mimics dextk-style random ReadAt/Seek traffic, including
// huge offsets from malformed dex data, over a non-seekable stream.
func TestBufferedReadSeekerRandomSeekRead(t *testing.T) {
	for _, size := range []int{100_000, 300_000} {
		data := patternData(size)
		br := NewBufferedReaderSeeker(&shortReader{data: data, max: 8192})
		defer br.Close()
		rng := rand.New(rand.NewSource(42))
		for i := 0; i < 2000; i++ {
			switch rng.Intn(3) {
			case 0: // ReadAt at random offset, sometimes huge (malformed dex)
				off := int64(rng.Intn(size + 1000))
				if rng.Intn(10) == 0 {
					off = int64(rng.Intn(1 << 31))
				}
				buf := make([]byte, rng.Intn(8192)+1)
				n, err := br.ReadAt(buf, off)
				if off < int64(size) {
					if err != nil && err != io.EOF {
						t.Fatalf("size %d iter %d: ReadAt(%d) err %v", size, i, off, err)
					}
					if n > 0 && !bytes.Equal(buf[:n], data[off:off+int64(n)]) {
						t.Fatalf("size %d iter %d: ReadAt(%d) data mismatch n=%d", size, i, off, n)
					}
				}
			case 1: // Seek + Read
				off := int64(rng.Intn(size + 1000))
				if _, err := br.Seek(off, io.SeekStart); err != nil {
					t.Fatalf("size %d iter %d: Seek(%d) err %v", size, i, off, err)
				}
				buf := make([]byte, rng.Intn(4096)+1)
				n, _ := br.Read(buf)
				if off < int64(size) && n > 0 && !bytes.Equal(buf[:n], data[off:off+int64(n)]) {
					t.Fatalf("size %d iter %d: Seek+Read(%d) data mismatch n=%d", size, i, off, n)
				}
			case 2: // sequential read
				buf := make([]byte, rng.Intn(4096)+1)
				pos, _ := br.Seek(0, io.SeekCurrent)
				n, _ := br.Read(buf)
				if pos < int64(size) && n > 0 && !bytes.Equal(buf[:n], data[pos:pos+int64(n)]) {
					t.Fatalf("size %d iter %d: seq Read at %d mismatch n=%d", size, i, pos, n)
				}
			}
		}
	}
}
