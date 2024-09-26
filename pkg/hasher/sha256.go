package hasher

import "crypto/sha256"

// SHA256Hasher implements the Hasher interface using SHA-256 algorithm.
type SHA256Hasher struct{ baseHasher }

// NewSHA256Hasher creates a new SHA256Hasher.
func NewSHA256Hasher() *SHA256Hasher {
	return &SHA256Hasher{
		baseHasher: baseHasher{hash: sha256.New()},
	}
}
