package hasher

import "golang.org/x/crypto/blake2b"

// Blake2b implements the Hasher interface using Blake2b algorithm.
type Blake2b struct{ baseHasher }

// NewBlake2B creates a new Blake2b hasher.
func NewBlake2B() *Blake2b {
	h, _ := blake2b.New256(nil)
	return &Blake2b{baseHasher: baseHasher{hash: h}}
}
