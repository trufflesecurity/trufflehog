package hasher

import "golang.org/x/crypto/blake2b"

// Blaker2bHasher implements the Hasher interface using Blake2b algorithm.
type Blaker2bHasher struct{ baseHasher }

// NewBlaker2bHasher creates a new Blaker2bHasher.
func NewBlaker2bHasher() (*Blaker2bHasher, error) {
	h, err := blake2b.New256(nil)
	if err != nil {
		return nil, err
	}
	return &Blaker2bHasher{
		baseHasher: baseHasher{hash: h},
	}, nil
}
