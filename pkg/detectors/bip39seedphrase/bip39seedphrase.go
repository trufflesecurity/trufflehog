package bip39seedphrase

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/seedphrase"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

//go:embed wordlist-bip39-en.txt
var wordlistRaw string

var (
	bip39Words    map[string]int
	bip39Keywords []string
)

func init() {
	bip39Words = make(map[string]int)
	bip39Keywords = []string{"mnemonic", "seed phrase", "recovery phrase", "twelve words", "backup phrase", "wallet seed"}
	for i, w := range strings.Split(strings.TrimSpace(wordlistRaw), "\n") {
		word := strings.TrimSpace(strings.ToLower(w))
		bip39Words[word] = i
		bip39Keywords = append(bip39Keywords, word)
	}
}

const minSequenceLength = 12

var validSequenceLengths = []int{24, 21, 18, 15, 12}

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.CustomFalsePositiveChecker = (*Scanner)(nil)

func (s Scanner) Keywords() []string {
	return bip39Keywords
}

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	words := seedphrase.NormalizeWords(data)
	if len(words) < minSequenceLength {
		return nil, nil
	}

	candidates := seedphrase.FindCandidates(words, validSequenceLengths, verifyBIP39Checksum)
	candidates = seedphrase.RemoveContainedCandidates(candidates)

	var results []detectors.Result
	for _, candidate := range candidates {
		results = append(results, detectors.Result{
			DetectorType: detector_typepb.DetectorType_BIP39SeedPhrase,
			Raw:          []byte(candidate.Phrase),
			ExtraData:    map[string]string{"word_count": strconv.Itoa(len(strings.Fields(candidate.Phrase)))},
		})
	}

	return results, nil
}

func (s Scanner) IsFalsePositive(_ detectors.Result) (bool, string) {
	return false, ""
}

// verifyBIP39Checksum validates the BIP39 checksum embedded in the last word.
func verifyBIP39Checksum(words []string) bool {
	numWords := len(words)
	if !isValidSequenceLength(numWords) {
		return false
	}

	// Total bits = 11 * numWords. Entropy = 8/32 bytes. Checksum = 4/8 bits.
	totalBits := 11 * numWords
	checksumBits := totalBits / 33
	entropyBits := totalBits - checksumBits

	// Build the bit string from word indices.
	var bitString strings.Builder
	for _, w := range words {
		idx, ok := bip39Words[w]
		if !ok {
			return false
		}
		bitString.WriteString(padBits(int64(idx), 11))
	}

	bits := bitString.String()
	if len(bits) != totalBits {
		return false
	}

	entropyStr := bits[:entropyBits]
	checksumStr := bits[entropyBits:]

	// Convert entropy bits to bytes.
	entropyBytes, err := bitsToBytes(entropyStr)
	if err != nil {
		return false
	}

	// SHA256 of entropy.
	hash := sha256.Sum256(entropyBytes)
	hashBits := bytesToBits(hash[:])

	return strings.HasPrefix(hashBits, checksumStr)
}

func isValidSequenceLength(length int) bool {
	for _, validLength := range validSequenceLengths {
		if length == validLength {
			return true
		}
	}
	return false
}

func padBits(v int64, width int) string {
	b := strconv.FormatInt(v, 2)
	if len(b) < width {
		b = strings.Repeat("0", width-len(b)) + b
	}
	return b
}

func bitsToBytes(bits string) ([]byte, error) {
	n := new(big.Int)
	_, ok := n.SetString(bits, 2)
	if !ok {
		return nil, fmt.Errorf("invalid bit string")
	}
	result := n.Bytes()
	// Pad to the correct number of bytes (bits length / 8).
	expectedLen := len(bits) / 8
	if len(result) < expectedLen {
		padded := make([]byte, expectedLen)
		copy(padded[expectedLen-len(result):], result)
		result = padded
	}
	return result, nil
}

func bytesToBits(b []byte) string {
	var sb strings.Builder
	for _, byteVal := range b {
		sb.WriteString(padBits(int64(byteVal), 8))
	}
	return sb.String()
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_BIP39SeedPhrase
}

func (s Scanner) Description() string {
	return "BIP39 mnemonic seed phrases are used to derive cryptocurrency wallet keys. Exposure allows full theft of associated funds."
}
