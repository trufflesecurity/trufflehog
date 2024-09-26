package hasher

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
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
			expectedHex: "dd4e6730520932767ec0a9e33fe19c4ce24399d6eba4ff62f13013c9ed30ef87",
		},
		{
			name:        "FN-64a input exceeds max size",
			hasher:      NewFNVHasher(),
			input:       bytes.Repeat([]byte("a"), maxInputSize+1),
			expectError: &InputTooLargeError{},
		},
		{
			name:        "FNV-64a with empty input",
			hasher:      NewFNVHasher(),
			input:       []byte(""),
			expectedHex: "",
			expectError: ErrEmptyData,
		},
		{
			name:        "SHA-256 with empty input",
			hasher:      NewSHA256Hasher(),
			input:       []byte(""),
			expectedHex: "",
			expectError: ErrEmptyData,
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

// TestHasherHashWithContextIdempotency confirms that multiple invocations
// of HashWithContext with the same input produce identical results.
func TestHasherHashWithContextIdempotency(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		hasher      Hasher
		input       []byte
		expectedHex string
		expectError bool
	}{
		{
			name:        "FNVHasher idempotency",
			hasher:      NewFNVHasher(),
			input:       []byte("Idempotency test"),
			expectedHex: "7a011bc470bdd8d6",
		},
		{
			name:        "SHA256Hasher idempotency",
			hasher:      NewSHA256Hasher(),
			input:       []byte("Idempotency test"),
			expectedHex: "75bc5c31f67c5f9f3bbf2edbe30af0319b137a6128eaa9f33e006f30eeff9f5b",
		},
		{
			name:        "MutexHasher wrapping FNVHasher idempotency",
			hasher:      NewMutexHasher(NewFNVHasher()),
			input:       []byte("Idempotency test"),
			expectedHex: "7a011bc470bdd8d6",
		},
		{
			name:        "MutexHasher wrapping SHA256Hasher idempotency",
			hasher:      NewMutexHasher(NewSHA256Hasher()),
			input:       []byte("Idempotency test"),
			expectedHex: "75bc5c31f67c5f9f3bbf2edbe30af0319b137a6128eaa9f33e006f30eeff9f5b",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hash1, err1 := tc.hasher.HashWithContext(context.Background(), tc.input)
			assert.NoError(t, err1, "unexpected error on first hash")

			hash2, err2 := tc.hasher.HashWithContext(context.Background(), tc.input)
			assert.NoError(t, err2, "unexpected error on second hash")

			// Verify that both hash results are identical.
			if !bytes.Equal(hash1, hash2) {
				t.Errorf("hash results are not identical.\nFirst:  %x\nSecond: %x", hash1, hash2)
			}

			// Additionally, verify against the expected hash.
			expected, err := hex.DecodeString(tc.expectedHex)
			assert.NoError(t, err, "invalid expected hex string")

			assert.True(t, bytes.Equal(hash1, expected), "first hash does not match expected hash")
			assert.True(t, bytes.Equal(hash2, expected), "second hash does not match expected hash")
		})
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

// TestMutexHasherHashWithContextConcurrent verifies that MutexHasher correctly
// synchronizes access when multiple goroutines concurrently invoke HashWithContext.
func TestMutexHasherHashWithContextConcurrent(t *testing.T) {
	t.Parallel()

	mutexHasher := NewMutexHasher(NewSHA256Hasher())

	input := []byte("Concurrent Hashing with Context Test")

	// Compute the expected hash once for comparison.
	expectedHash, err := mutexHasher.Hash(input)
	assert.NoError(t, err, "unexpected error computing expected hash")

	// Channel to collect errors from goroutines.
	// Buffered to prevent goroutines from blocking if the main thread is slow.
	errs := make(chan error, numGoroutines*numIterations)

	// WaitGroup to synchronize all goroutines.
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Launch multiple goroutines to perform hashing concurrently.
	for i := range numGoroutines {
		go func(goroutineID int) {
			defer wg.Done()
			// Each goroutine uses a background context.
			ctx := context.Background()
			for j := range numIterations {
				hash, err := mutexHasher.HashWithContext(ctx, input)
				if err != nil {
					errs <- fmt.Errorf("goroutine %d: hash error on iteration %d: %v", goroutineID, j, err)
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

// TestHasherHashWithContextCanceled ensures that HashWithContext returns promptly
// with ctx.Err() when the context is canceled before hashing.
func TestHasherHashWithContextCanceled(t *testing.T) {
	t.Parallel()

	mutexHasher := NewMutexHasher(NewSHA256Hasher())

	input := []byte("Canceled context test")

	// Create a canceled context.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	hash, err := mutexHasher.HashWithContext(ctx, input)

	assert.Error(t, err, "expected an error due to canceled context")
	assert.Nil(t, hash, "expected no hash result on error")
}

// TestHasherHashWithContextTimeout checks that HashWithContext respects context deadlines.
func TestHasherHashWithContextTimeout(t *testing.T) {
	t.Parallel()

	mutexHasher := NewMutexHasher(NewSHA256Hasher())

	input := []byte("Timeout context test")
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Microsecond)
	defer cancel()

	// Allow the context to timeout.
	time.Sleep(5 * time.Microsecond)

	hash, err := mutexHasher.HashWithContext(ctx, input)

	// Expect an error due to context deadline exceeded.
	assert.Error(t, err, "expected an error due to context deadline exceeded")
	assert.Nil(t, hash, "expected no hash result on error")
}

// BenchmarkHasherWithMutex benchmarks hashing using a single SHA-256 Hasher instance
// protected by a sync.Mutex across multiple goroutines.
func BenchmarkHasherWithMutex_SHA256(b *testing.B) {
	sampleData := []byte("The quick brown fox jumps over the lazy dog")

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

// BenchmarkHasherPerGoroutine benchmarks hashing using separate SHA-256 Hasher instances
// for each goroutine, eliminating the need for synchronization.
func BenchmarkHasherPerGoroutine_SHA256(b *testing.B) {
	sampleData := []byte("The quick brown fox jumps over the lazy dog")

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

// BenchmarkHasherWithMutex benchmarks hashing using a single FNV-64a Hasher instance
// protected by a sync.Mutex across multiple goroutines.
func BenchmarkHasherWithMutex_FNV(b *testing.B) {
	sampleData := []byte("The quick brown fox jumps over the lazy dog")

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

// BenchmarkHasherPerGoroutine benchmarks hashing using separate FNV-64a Hasher instances
// for each goroutine, eliminating the need for synchronization.
func BenchmarkHasherPerGoroutine_FNV(b *testing.B) {
	sampleData := []byte("The quick brown fox jumps over the lazy dog")

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
