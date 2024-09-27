package hasher

import "golang.org/x/crypto/blake2b"

// Blake2bHasher implements the Hasher interface using Blake2b algorithm.
type Blake2bHasher struct{ baseHasher }

// NewBlaker2bHasher creates a new Blake2bHasher.
func NewBlaker2bHasher() *Blake2bHasher {
	h, _ := blake2b.New256(nil)
	return &Blake2bHasher{
		baseHasher: baseHasher{hash: h},
	}
}
