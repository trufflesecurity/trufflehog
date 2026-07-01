package moneroseedphrase

import (
	"context"
	"hash/crc32"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

const validMoneroMnemonic = "arises army around arrow arsenic artistic ascend ashtray aside asked asleep aspire assorted asylum athlete atlas atom atrium attire auburn auctions audio august aunt atrium"

func computeLastWord(first24 []string) string {
	var checksumInput strings.Builder
	for _, word := range first24 {
		word = strings.ToLower(word)
		if _, ok := moneroWords[word]; !ok {
			panic("word not in monero wordlist: " + word)
		}
		checksumInput.WriteString(word[:checksumPrefixLength])
	}
	return first24[int(crc32.ChecksumIEEE([]byte(checksumInput.String()))%24)]
}

func numberedMnemonic(words []string) string {
	var input strings.Builder
	for i, word := range words {
		if i > 0 {
			switch i % 3 {
			case 0:
				input.WriteString("\n")
			case 1:
				input.WriteString(",\t")
			default:
				input.WriteString(", ")
			}
		}
		input.WriteString(strings.ToUpper(word[:1]))
		input.WriteString(word[1:])
		input.WriteString(" ")
		input.WriteString(strconv.Itoa(i + 1))
		input.WriteString(".")
	}
	return input.String()
}

func moneroWordlist(t *testing.T) []string {
	t.Helper()
	words := strings.Fields(strings.ToLower(wordlistRaw))
	if len(words) == 0 {
		t.Fatal("expected non-empty Monero wordlist")
	}
	return words
}

func first24Words(seed string) []string {
	words := strings.Fields(seed)
	return append([]string{}, words[:24]...)
}

func differentMoneroWord(t *testing.T, original string) string {
	t.Helper()
	for _, word := range moneroWordlist(t) {
		if word != original {
			return word
		}
	}
	t.Fatal("could not find different Monero word")
	return ""
}

func TestMonero_Keywords(t *testing.T) {
	d := Scanner{}
	keywords := d.Keywords()
	if len(keywords) == 0 {
		t.Fatal("expected non-empty keywords")
	}

	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	input := "monero mnemonic: " + validMoneroMnemonic

	detectorMatches := ahoCorasickCore.FindDetectorMatches([]byte(input))
	if len(detectorMatches) == 0 {
		t.Errorf("keywords '%v' not matched by: %s", d.Keywords(), input)
		return
	}

	results, err := d.FromData(context.Background(), false, []byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	t.Run("bare mnemonic triggers through wordlist keyword", func(t *testing.T) {
		detectorMatches := ahoCorasickCore.FindDetectorMatches([]byte(validMoneroMnemonic))
		if len(detectorMatches) == 0 {
			t.Errorf("keywords '%v' did not match bare mnemonic", d.Keywords())
		}

		results, err := d.FromData(context.Background(), false, []byte(validMoneroMnemonic))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(results) != 1 {
			t.Fatalf("expected direct detection of bare mnemonic, got %d results", len(results))
		}
	})
}

func TestMonero_IsFalsePositive(t *testing.T) {
	isFalsePositive, reason := detectors.GetFalsePositiveCheck(Scanner{})(detectors.Result{
		Raw: []byte(validMoneroMnemonic),
	})
	if isFalsePositive {
		t.Fatalf("expected seed phrase not to be filtered as false positive: %s", reason)
	}
}

func TestMonero_Detection(t *testing.T) {
	d := Scanner{}

	first24 := first24Words(validMoneroMnemonic)
	invalidWords := append([]string{}, strings.Fields(validMoneroMnemonic)...)
	invalidWords[24] = differentMoneroWord(t, computeLastWord(first24))

	tests := []struct {
		name    string
		input   string
		wantRaw []string
	}{
		{
			name:    "valid 25-word mnemonic",
			input:   "seed phrase: " + validMoneroMnemonic,
			wantRaw: []string{validMoneroMnemonic},
		},
		{
			name:    "mnemonic surrounded by text",
			input:   "recovery phrase: " + validMoneroMnemonic + " ::",
			wantRaw: []string{validMoneroMnemonic},
		},
		{
			name:  "invalid checksum returns no results",
			input: strings.Join(invalidWords, " "),
		},
		{
			name:  "repeated Monero word noise returns no results",
			input: strings.Repeat(moneroWordlist(t)[0]+" ", 30),
		},
		{
			name:    "one word per line 25-word phrase",
			input:   strings.Join(strings.Fields(validMoneroMnemonic), "\n"),
			wantRaw: []string{validMoneroMnemonic},
		},
		{
			name:    "comma tab newline numbering and mixed case separators",
			input:   numberedMnemonic(strings.Fields(validMoneroMnemonic)),
			wantRaw: []string{validMoneroMnemonic},
		},
		{
			name:  "no match - too few words",
			input: "monero mnemonic: " + strings.Join(first24[:20], " "),
		},
		{
			name:  "no match - non-Monero words",
			input: "recovery phrase: qqqq rrrr ssss tttt uuuu vvvv wwww xxxx yyyy zzzz qqqq rrrr ssss tttt uuuu vvvv wwww xxxx yyyy zzzz qqqq rrrr ssss tttt uuuu",
		},
		{
			name:  "no match - empty input",
			input: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := d.FromData(context.Background(), false, []byte(tt.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantRaw == nil {
				tt.wantRaw = []string{}
			}

			gotRaw := []string{}
			for i, result := range results {
				gotRaw = append(gotRaw, string(result.Raw))
				if result.Verified {
					t.Errorf("result %d is verified", i)
				}
				if result.SecretParts != nil {
					t.Errorf("result %d SecretParts = %v, want nil", i, result.SecretParts)
				}
				wantExtraData := map[string]string{"word_count": strconv.Itoa(len(strings.Fields(gotRaw[len(gotRaw)-1])))}
				if diff := cmp.Diff(wantExtraData, result.ExtraData); diff != "" {
					t.Errorf("result %d ExtraData mismatch (-want +got):\n%s", i, diff)
				}
			}

			if diff := cmp.Diff(tt.wantRaw, gotRaw); diff != "" {
				t.Errorf("Raw results mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestMonero_ChecksumVerification(t *testing.T) {
	d := Scanner{}

	first24 := first24Words(validMoneroMnemonic)

	results, err := d.FromData(context.Background(), true, []byte(validMoneroMnemonic))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	if results[0].Verified {
		t.Error("expected valid Monero mnemonic to remain unverified")
	}
	if results[0].SecretParts != nil {
		t.Errorf("SecretParts = %v, want nil", results[0].SecretParts)
	}
	if diff := cmp.Diff(map[string]string{"word_count": "25"}, results[0].ExtraData); diff != "" {
		t.Errorf("ExtraData mismatch (-want +got):\n%s", diff)
	}

	wrongLast := differentMoneroWord(t, computeLastWord(first24))
	invalidWords := append([]string{}, first24...)
	invalidWords = append(invalidWords, wrongLast)
	invalidMnemonic := strings.Join(invalidWords, " ")

	results, err = d.FromData(context.Background(), true, []byte(invalidMnemonic))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(results))
	}
}

func TestMonero_RawContent(t *testing.T) {
	d := Scanner{}

	input := "monero seed phrase: " + validMoneroMnemonic

	results, err := d.FromData(context.Background(), false, []byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	if diff := cmp.Diff(validMoneroMnemonic, string(results[0].Raw)); diff != "" {
		t.Errorf("Raw mismatch (-want +got):\n%s", diff)
	}

	if results[0].SecretParts != nil {
		t.Errorf("SecretParts = %v, want nil", results[0].SecretParts)
	}

	if diff := cmp.Diff(map[string]string{"word_count": "25"}, results[0].ExtraData); diff != "" {
		t.Errorf("ExtraData mismatch (-want +got):\n%s", diff)
	}
}

func TestMonero_Type(t *testing.T) {
	d := Scanner{}
	if int(d.Type()) != 1057 {
		t.Errorf("expected type 1057 (MoneroSeedPhrase), got %d", d.Type())
	}
}

func TestMonero_KeywordsDoesNotIncludeCommonWords(t *testing.T) {
	d := Scanner{}
	keywords := map[string]struct{}{}
	for _, keyword := range d.Keywords() {
		keywords[keyword] = struct{}{}
	}

	commonWords := []string{"all", "air", "age", "act", "art", "ask", "arm", "add", "any", "aim"}
	for _, w := range commonWords {
		if _, ok := keywords[w]; ok {
			t.Errorf("expected common word %q to be excluded from Keywords()", w)
		}
	}

	uncommonMnemonicWords := []string{"arises", "arsenic"}
	for _, w := range uncommonMnemonicWords {
		if _, ok := keywords[w]; !ok {
			t.Errorf("expected uncommon mnemonic word %q to remain in Keywords()", w)
		}
	}
}
