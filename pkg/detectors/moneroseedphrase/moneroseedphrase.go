package moneroseedphrase

import (
	"context"
	_ "embed"
	"hash/crc32"
	"strconv"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/seedphrase"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

//go:embed wordlist.txt
var wordlistRaw string

var (
	moneroWords    map[string]int
	moneroKeywords []string
)

func init() {
	moneroWords = make(map[string]int)
	moneroKeywords = []string{"monero", "mnemonic", "seed phrase", "recovery phrase", "25 words"}
	for i, w := range strings.Split(strings.TrimSpace(wordlistRaw), "\n") {
		word := strings.TrimSpace(strings.ToLower(w))
		moneroWords[word] = i
	}
}

const minSequenceLength = 25
const checksumPrefixLength = 3

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

func (s Scanner) Keywords() []string {
	return moneroKeywords
}

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	words := seedphrase.NormalizeWords(data)
	if len(words) < minSequenceLength {
		return nil, nil
	}

	var results []detectors.Result
	candidates := seedphrase.FindCandidates(words, []int{minSequenceLength}, verifyMoneroChecksum)
	for _, candidate := range candidates {
		results = append(results, detectors.Result{
			DetectorType: detector_typepb.DetectorType_MoneroSeedPhrase,
			Raw:          []byte(candidate.Phrase),
			ExtraData:    map[string]string{"word_count": strconv.Itoa(len(strings.Fields(candidate.Phrase)))},
		})
	}

	return results, nil
}

// verifyMoneroChecksum validates the 25th word as Monero's Electrum checksum.
func verifyMoneroChecksum(words []string) bool {
	if len(words) != minSequenceLength {
		return false
	}

	var checksumInput strings.Builder
	for i := 0; i < 24; i++ {
		word := words[i]
		if _, ok := moneroWords[word]; !ok || len(word) < checksumPrefixLength {
			return false
		}
		checksumInput.WriteString(word[:checksumPrefixLength])
	}

	checksumWord := words[int(crc32.ChecksumIEEE([]byte(checksumInput.String()))%24)]
	if _, ok := moneroWords[words[24]]; !ok {
		return false
	}
	return words[24] == checksumWord
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_MoneroSeedPhrase
}

func (s Scanner) Description() string {
	return "Monero mnemonic seed phrases are used to derive Monero wallet keys. Exposure allows full theft of associated funds."
}
