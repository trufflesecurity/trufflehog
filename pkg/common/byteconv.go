package common

import "unsafe"

// BytesToString converts a byte slice to a string without allocating.
func BytesToString(b []byte) string {
	return unsafe.String(unsafe.SliceData(b), len(b))
}
