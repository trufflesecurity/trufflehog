package hasher

import "hash/fnv"

// FNVHasher implements the Hasher interface using FNV algorithm.
type FNVHasher struct{ baseHasher }

// NewFNVHasher creates a new FNVHasher.
func NewFNVHasher() *FNVHasher {
	return &FNVHasher{
		baseHasher: baseHasher{hash: fnv.New64a()},
	}
}
