// Package hasher provides a generic interface and base implementation for hashing data.
package hasher

import (
	"fmt"
	"hash"
)

// Hasher defines a generic interface for hashing data.
// Implementations of this interface may choose to be safe for concurrent use,
// but it is not a requirement. Users should check the documentation of specific
// implementations for concurrent safety guarantees.
type Hasher interface {
	// Hash takes input data and returns the hashed result.
	// It returns an error if the input data is too large.
	// The function is idempotent - calling it multiple times with the same input
	// will produce the same output, assuming the underlying hash function is deterministic.
	Hash(data []byte) ([]byte, error)
}

// baseHasher provides a base implementation for the Hasher interface.
// It uses the hash.Hash interface from the standard library to perform the actual hashing.
// This implementation is not safe for concurrent use. Each goroutine/worker should
// use its own instance of baseHasher for concurrent operations.
// Implementations that require concurrent access should wrap baseHasher with a mutex. (e.g., MutexHasher)
type baseHasher struct{ hash hash.Hash }

// InputTooLargeError is returned when the input data exceeds the maximum allowed size.
type InputTooLargeError struct {
	inputSize int
	maxSize   int
}

func (e *InputTooLargeError) Error() string {
	return fmt.Sprintf("input data exceeds the maximum allowed size: %d > %d", e.inputSize, e.maxSize)
}

const maxInputSize = 1 << 14 // 16KB

// Hash computes the hash of the given data.
// It returns an InputTooLargeError if the input data exceeds the maximum allowed size.
// This method resets the underlying hash before each computation to ensure
// that previous hashing operations do not affect the result.
func (b *baseHasher) Hash(data []byte) ([]byte, error) {
	if len(data) > maxInputSize {
		return nil, &InputTooLargeError{inputSize: len(data), maxSize: maxInputSize}
	}
	b.hash.Reset()
	// nolint:errcheck
	// The hash.Hash interface does not return errors on Write.
	// (https://cs.opensource.google/go/go/+/refs/tags/go1.23.1:src/hash/hash.go;l=27-28)
	_, _ = b.hash.Write(data)
	return b.hash.Sum(nil), nil
}
