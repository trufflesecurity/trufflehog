package hasher

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHasherHash(t *testing.T) {
	testCases := []struct {
		name        string
		hasher      Hasher
		input       []byte
		expectedHex string
		expectError error
	}{
		{
			name:        "FNV-64a with 'Hello, World!'",
			hasher:      NewFNVHasher(),
			input:       []byte("Hello, World!"),
			expectedHex: "6ef05bd7cc857c54",
		},
		{
			name:        "SHA-256 with 'Hello, World!'",
			hasher:      NewSHA256Hasher(),
			input:       []byte("Hello, World!"),
			expectedHex: "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f",
		},
		{
			name:        "SHA-256 input at max size",
			hasher:      NewSHA256Hasher(),
			input:       bytes.Repeat([]byte("a"), maxInputSize),
			expectedHex: "f3336bea752b5a28743033dd2c844a4a63fba08871aaee2586a2bf2d69be83a2",
		},
		{
			name:        "FN-64a input exceeds max size",
			hasher:      NewFNVHasher(),
			input:       bytes.Repeat([]byte("a"), maxInputSize+1),
			expectError: &InputTooLargeError{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := tc.hasher.Hash(tc.input)
			checkError(t, err, tc.expectError, len(tc.input))

			if tc.expectError != nil {
				return
			}

			expected, err := hex.DecodeString(tc.expectedHex)
			if err != nil {
				t.Fatalf("invalid expected hex string '%s': %v", tc.expectedHex, err)
			}

			if !bytes.Equal(got, expected) {
				t.Errorf("hash mismatch.\nGot:      %x\nExpected: %x", got, expected)
			}
		})
	}
}

func checkError(t *testing.T, err, expectError error, inputSize int) {
	t.Helper()

	if expectError != nil {
		var inputTooLargeError *InputTooLargeError
		if errors.As(expectError, &inputTooLargeError) {
			var inputTooLargeErr *InputTooLargeError
			if assert.ErrorAs(t, err, &inputTooLargeErr) {
				assert.Equal(t, inputSize, inputTooLargeErr.inputSize)
				assert.Equal(t, maxInputSize, inputTooLargeErr.maxSize)
			}
		}
	} else {
		assert.NoError(t, err)
	}
}

func TestBaseHasherHashIdempotency(t *testing.T) {
	t.Parallel()

	hasher := NewFNVHasher()
	input := bytes.Repeat([]byte("a"), maxInputSize)

	hash1, err1 := hasher.Hash(input)
	assert.NoError(t, err1, "unexpected error on first hash")

	hash2, err2 := hasher.Hash(input)
	assert.NoError(t, err2, "unexpected error on second hash")

	if !bytes.Equal(hash1, hash2) {
		t.Errorf("hash results are not identical.\nFirst:  %x\nSecond: %x", hash1, hash2)
	}
}

const (
	numGoroutines = 512
	numIterations = 10_000
)

// TestMutexHasherConcurrentHash verifies that MutexHasher is thread-safe
// and produces consistent hash results when used concurrently.
func TestMutexHasherConcurrentHash(t *testing.T) {
	t.Parallel()

	mutexHasher := NewMutexHasher(NewSHA256Hasher())

	input := []byte("Concurrent Hashing Test")

	// Compute the expected hash once for comparison.
	expectedHash, err := mutexHasher.Hash(input)
	assert.NoError(t, err, "unexpected error computing expected hash")

	// Channel to collect errors from goroutines.
	// Buffered to prevent goroutines from blocking if the main thread is slow.
	errs := make(chan error, numGoroutines*numIterations)

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Launch multiple goroutines to perform hashing concurrently.
	for i := range numGoroutines {
		go func(goroutineID int) {
			defer wg.Done()
			for j := range numIterations {
				hash, err := mutexHasher.Hash(input)
				if err != nil {
					errs <- fmt.Errorf("goroutine %d: hash error: %v", goroutineID, err)
					continue
				}
				if !bytes.Equal(hash, expectedHash) {
					errs <- fmt.Errorf("goroutine %d: hash mismatch on iteration %d", goroutineID, j)
				}
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}
}

var sampleData = []byte("The quick brown fox jumps over the lazy dog")

// BenchmarkHasherWithMutex_SHA256 benchmarks hashing using a single SHA-256 Hasher instance
// protected by a sync.Mutex across multiple goroutines.
func BenchmarkHasherWithMutex_SHA256(b *testing.B) {
	mutexHasher := NewMutexHasher(NewSHA256Hasher())

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := mutexHasher.Hash(sampleData)
			assert.NoError(b, err)
		}
	})
}

// BenchmarkHasherPerGoroutine_SHA256 benchmarks hashing using separate SHA-256 Hasher instances
// for each goroutine, eliminating the need for synchronization.
func BenchmarkHasherPerGoroutine_SHA256(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		// Each goroutine maintains its own Hasher instance.
		hasher := NewSHA256Hasher()
		for pb.Next() {
			_, err := hasher.Hash(sampleData)
			assert.NoError(b, err)
		}
	})
}

// BenchmarkHasherWithMutex_FNV benchmarks hashing using a single FNV-64a Hasher instance
// protected by a sync.Mutex across multiple goroutines.
func BenchmarkHasherWithMutex_FNV(b *testing.B) {
	mutexHasher := NewMutexHasher(NewFNVHasher())

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := mutexHasher.Hash(sampleData)
			assert.NoError(b, err)
		}
	})
}

// BenchmarkHasherPerGoroutine_FNV benchmarks hashing using separate FNV-64a Hasher instances
// for each goroutine, eliminating the need for synchronization.
func BenchmarkHasherPerGoroutine_FNV(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		hasher := NewFNVHasher()
		for pb.Next() {
			_, err := hasher.Hash(sampleData)
			assert.NoError(b, err)
		}
	})
}

// BenchmarkHasherWithMutex_Blake2b benchmarks hashing using a single Blake2b Hasher instance
// protected by a sync.Mutex across multiple goroutines.
func BenchmarkHasherWithMutex_Blake2b(b *testing.B) {
	mutexHasher := NewMutexHasher(NewBlaker2bHasher())

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := mutexHasher.Hash(sampleData)
			assert.NoError(b, err)
		}
	})
}

// BenchmarkHasherPerGoroutine_Blake2b benchmarks hashing using separate Blake2b Hasher instances
// for each goroutine, eliminating the need for synchronization.
func BenchmarkHasherPerGoroutine_Blake2b(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		hasher := NewBlaker2bHasher()
		for pb.Next() {
			_, err := hasher.Hash(sampleData)
			assert.NoError(b, err)
		}
	})
}
