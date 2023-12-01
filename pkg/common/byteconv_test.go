package common

import (
	"math/rand"
	"reflect"
	"testing"
	"testing/quick"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestBytesToString_IdentityProperty(t *testing.T) {
	identityProperty := func(b []byte) bool {
		return BytesToString(b) == string(b)
	}

	genRandBytes := func(size int) []byte {
		b := make([]byte, size)

		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		for i := 0; i < size; i++ {
			b[i] = byte(r.Intn(256))
		}

		return b
	}

	cfg := &quick.Config{
		Values: func(values []reflect.Value, rand *rand.Rand) {
			// 2% chance to return a nil slice.
			if rand.Intn(2) == 0 {
				values[0] = reflect.Zero(reflect.TypeOf([]byte{}))
				return
			}
			values[0] = reflect.ValueOf(genRandBytes(rand.Intn(100_000)))
		},
	}

	assert.NoError(t, quick.Check(identityProperty, cfg))
}

func TestBytesToString_LengthProperty(t *testing.T) {
	lengthProperty := func(b []byte) bool {
		return len(BytesToString(b)) == len(b)
	}

	assert.NoError(t, quick.Check(lengthProperty, nil))
}

// TestBytesToString_SharedDataConsistency checks if mutating the input byte slice
// after conversion affects the string output from BytesToString, testing that the
// underlying data sharing between the slice and the string is handled correctly.
func TestBytesToString_SharedDataConsistency(t *testing.T) {
	immutabilityProperty := func(b []byte) bool {
		if len(b) == 0 {
			return BytesToString(b) == string(b)
		}
		s := BytesToString(b)
		b[0] = 0 // modify byte slice
		return s == BytesToString(b)
	}

	assert.NoError(t, quick.Check(immutabilityProperty, nil))
}

// TestBytesToString_ConsistencyProperty checks if BytesToString returns consistent
// results for the same byte slice input, ensuring deterministic behavior.
func TestBytesToString_ConsistencyProperty(t *testing.T) {
	consistencyProperty := func(b []byte) bool {
		s1 := BytesToString(b)
		s2 := BytesToString(b)
		return s1 == s2
	}

	assert.NoError(t, quick.Check(consistencyProperty, nil))
}
