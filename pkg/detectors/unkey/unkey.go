package unkey

import (
	"context"
	"encoding/binary"
	"hash/crc32"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

const (
	// Bitcoin Base58 alphabet. Zero is '1'.
	base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	checksumLength = 6
)

var (
	// Root keys are unkey_ + 8 Base58 characters + the literal unkeyv1 + 42
	// Base58 characters (63 characters in all). The final 6 characters are a
	// checksum, checked in validChecksum.
	keyPat = regexp.MustCompile(`\b(unkey_[1-9A-HJ-NP-Za-km-z]{8}unkeyv1[1-9A-HJ-NP-Za-km-z]{42})\b`)

	checksumTable = crc32.MakeTable(crc32.Castagnoli)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"unkeyv1"}
}

// FromData finds Unkey root keys. Verification is not performed here: Unkey
// checks keys reported to its revocation webhook. verify is ignored, matching
// other pattern-only detectors. Every result is unverified and has no
// verification error.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(string(data), -1) {
		key := match[1]
		if !validChecksum(key) {
			continue
		}
		uniqueMatches[key] = struct{}{}
	}

	for key := range uniqueMatches {
		results = append(results, detectors.Result{
			DetectorType: detector_typepb.DetectorType_Unkey,
			Raw:          []byte(key),
			SecretParts:  map[string]string{"key": key},
		})
	}

	return results, nil
}

// validChecksum reports whether the trailing 6 characters are the CRC-32C
// of the rest of the key. The checksum is the unsigned 32-bit sum written
// big-endian, Base58-encoded, and left-padded with '1' to 6 characters.
func validChecksum(key string) bool {
	if len(key) <= checksumLength {
		return false
	}
	unsigned := key[:len(key)-checksumLength]
	return checksum(unsigned) == key[len(key)-checksumLength:]
}

func checksum(unsigned string) string {
	sum := crc32.Checksum([]byte(unsigned), checksumTable)
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], sum)
	encoded := encodeBase58(raw[:])
	if len(encoded) >= checksumLength {
		return encoded
	}
	return strings.Repeat("1", checksumLength-len(encoded)) + encoded
}

// encodeBase58 encodes with the Bitcoin alphabet and preserves leading zero
// bytes as '1', matching the encoder Unkey uses for the checksum.
func encodeBase58(buf []byte) string {
	size := len(buf)

	zcount := 0
	for zcount < size && buf[zcount] == 0 {
		zcount++
	}

	// Integer simplification of ceil(log(256)/log(58)).
	size = zcount + (size-zcount)*555/406 + 1

	out := make([]byte, size)

	var i, high int
	var carry uint32

	high = size - 1
	for _, b := range buf {
		i = size - 1
		for carry = uint32(b); i > high || carry != 0; i-- {
			carry += 256 * uint32(out[i])
			out[i] = byte(carry % 58)
			carry /= 58
		}
		high = i
	}

	for i = zcount; i < size && out[i] == 0; i++ {
	}

	val := out[i-zcount:]
	size = len(val)
	for i = 0; i < size; i++ {
		out[i] = base58Alphabet[val[i]]
	}

	return string(out[:size])
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Unkey
}

func (s Scanner) Description() string {
	return "Unkey is an API key platform. Root keys authenticate requests to the Unkey API for a workspace."
}
