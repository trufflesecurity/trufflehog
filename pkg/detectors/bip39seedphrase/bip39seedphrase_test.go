package bip39seedphrase

import (
	"context"
	"crypto/sha256"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

const (
	valid12WordMnemonic = "army office nephew thrive kiwi helmet spare guard floor shaft use rookie"
	valid15WordMnemonic = "audit light fee transfer ensure twin symbol already foil table control sadness useless awful arm"
	valid18WordMnemonic = "bamboo harvest because tackle once grass pool pig electric cross habit march canyon owner law spring rhythm sun"
	valid21WordMnemonic = "bench eyebrow spirit spread turtle toy reduce dutch document around prepare mean faculty buffalo giggle critic save tree duty grit asthma"
	valid24WordMnemonic = "blossom decrease mule simple demand genius lens total estate gold turkey need lift open fiction mystery ready moon amazing lake style evidence twin confirm"
)

func bip39Wordlist(t *testing.T) []string {
	t.Helper()
	words := strings.Fields(strings.ToLower(wordlistRaw))
	if len(words) != 2048 {
		t.Fatalf("expected 2048 BIP39 words, got %d", len(words))
	}
	return words
}

func corruptBIP39Mnemonic(t *testing.T, seed string) string {
	t.Helper()
	words := strings.Fields(seed)
	wordlist := bip39Wordlist(t)
	for _, replacement := range wordlist {
		if replacement != words[len(words)-1] {
			words[len(words)-1] = replacement
			return strings.Join(words, " ")
		}
	}
	t.Fatal("could not corrupt BIP39 mnemonic")
	return ""
}

func numberedBIP39Mnemonic(seed string) string {
	var input strings.Builder
	for i, word := range strings.Fields(seed) {
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
		input.WriteString(strconv.Itoa(i + 1))
		input.WriteString(". ")
		input.WriteString(word)
	}
	return input.String()
}

func generatedBareBIP39MnemonicWithKeyword(t *testing.T, keywords []string) string {
	t.Helper()

	keywordSet := make(map[string]struct{}, len(keywords))
	for _, keyword := range keywords {
		keywordSet[keyword] = struct{}{}
	}

	wordlist := bip39Wordlist(t)
	for counter := 0; counter < 10_000; counter++ {
		seed := sha256.Sum256([]byte("bip39 bare mnemonic keyword test vector " + strconv.Itoa(counter)))
		entropy := seed[:16]
		hash := sha256.Sum256(entropy)
		bits := bytesToBits(entropy) + bytesToBits(hash[:])[:4]

		words := make([]string, 0, 12)
		matchesKeyword := false
		for i := 0; i < len(bits); i += 11 {
			idx, err := strconv.ParseInt(bits[i:i+11], 2, 64)
			if err != nil {
				t.Fatalf("parse generated BIP39 index: %v", err)
			}
			word := wordlist[idx]
			words = append(words, word)
			if _, ok := keywordSet[word]; ok {
				matchesKeyword = true
			}
		}

		phrase := strings.Join(words, " ")
		if matchesKeyword && verifyBIP39Checksum(words) {
			return phrase
		}
	}

	t.Fatal("could not generate a bare BIP39 mnemonic containing a keyword")
	return ""
}

func TestBIP39_Keywords(t *testing.T) {
	d := Scanner{}
	keywords := d.Keywords()
	if len(keywords) == 0 {
		t.Fatal("expected non-empty keywords")
	}

	generatedBareMnemonic := generatedBareBIP39MnemonicWithKeyword(t, keywords)
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name      string
		input     string
		want      int
		wantMatch bool // whether AhoCorasick should match
	}{
		{
			name:      "detects 12-word mnemonic with keyword",
			input:     "mnemonic: " + valid12WordMnemonic,
			want:      1,
			wantMatch: true,
		},
		{
			name:      "detects generated bare mnemonic through wordlist keyword",
			input:     generatedBareMnemonic,
			want:      1,
			wantMatch: true,
		},
		{
			name:      "detects 24-word mnemonic with keyword",
			input:     "seed phrase: " + valid24WordMnemonic,
			want:      1,
			wantMatch: true,
		},
		{
			name:      "detects from numbered list with keyword",
			input:     "recovery phrase: " + numberedBIP39Mnemonic(valid12WordMnemonic),
			want:      1,
			wantMatch: true,
		},
		{
			name:      "one word per line with keyword",
			input:     "backup phrase:\n" + strings.Join(strings.Fields(valid12WordMnemonic), "\n"),
			want:      1,
			wantMatch: true,
		},
		{
			name:      "no match - too few words",
			input:     "mnemonic: " + strings.Join(strings.Fields(valid12WordMnemonic)[:5], " "),
			want:      0,
			wantMatch: true,
		},
		{
			name:      "no match - non-BIP39 words",
			input:     "recovery phrase: qqqq rrrr ssss tttt uuuu vvvv wwww xxxx yyyy zzzz qqqq rrrr",
			want:      0,
			wantMatch: true,
		},
		{
			name:      "no match - empty input",
			input:     "",
			want:      0,
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detectorMatches := ahoCorasickCore.FindDetectorMatches([]byte(tt.input))
			if tt.wantMatch && len(detectorMatches) == 0 {
				t.Errorf("expected keywords to match test input")
				return
			}
			if !tt.wantMatch && len(detectorMatches) != 0 {
				t.Errorf("expected keywords not to match test input")
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(tt.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(results) != tt.want {
				t.Errorf("expected %d results, got %d", tt.want, len(results))
			}
		})
	}
}

func TestBIP39_IsFalsePositive(t *testing.T) {
	isFalsePositive, reason := detectors.GetFalsePositiveCheck(Scanner{})(detectors.Result{
		Raw: []byte(valid12WordMnemonic),
	})
	if isFalsePositive {
		t.Fatalf("expected seed phrase not to be filtered as false positive: %s", reason)
	}
}

func TestBIP39_ChecksumVerification(t *testing.T) {
	d := Scanner{}

	tests := []struct {
		name string
		seed string
	}{
		{
			name: "valid 12-word mnemonic",
			seed: valid12WordMnemonic,
		},
		{
			name: "valid 15-word mnemonic",
			seed: valid15WordMnemonic,
		},
		{
			name: "valid 18-word mnemonic",
			seed: valid18WordMnemonic,
		},
		{
			name: "valid 21-word mnemonic",
			seed: valid21WordMnemonic,
		},
		{
			name: "valid 24-word mnemonic",
			seed: valid24WordMnemonic,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := d.FromData(context.Background(), true, []byte(tt.seed))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(results) != 1 {
				t.Fatalf("expected 1 result, got %d", len(results))
			}

			if results[0].Verified {
				t.Error("expected valid BIP39 mnemonic to remain unverified")
			}

			if diff := cmp.Diff(tt.seed, string(results[0].Raw)); diff != "" {
				t.Errorf("Raw mismatch (-want +got):\n%s", diff)
			}

			if results[0].SecretParts != nil {
				t.Errorf("SecretParts = %v, want nil", results[0].SecretParts)
			}

			wantExtraData := map[string]string{"word_count": strconv.Itoa(len(strings.Fields(tt.seed)))}
			if diff := cmp.Diff(wantExtraData, results[0].ExtraData); diff != "" {
				t.Errorf("ExtraData mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestBIP39_Detection(t *testing.T) {
	d := Scanner{}

	tests := []struct {
		name    string
		input   string
		wantRaw []string
	}{
		{
			name:  "invalid checksum wordlist run returns no results",
			input: corruptBIP39Mnemonic(t, valid12WordMnemonic),
		},
		{
			name:  "repeated word noise returns no results",
			input: strings.Repeat(bip39Wordlist(t)[0]+" ", 30),
		},
		{
			name:    "one word per line 24-word phrase",
			input:   strings.Join(strings.Fields(valid24WordMnemonic), "\n"),
			wantRaw: []string{valid24WordMnemonic},
		},
		{
			name:    "two adjacent phrases on consecutive lines",
			input:   valid12WordMnemonic + "\nqqqq\n" + valid24WordMnemonic,
			wantRaw: []string{valid12WordMnemonic, valid24WordMnemonic},
		},
		{
			name:  "comma tab newline and numbering separators",
			input: numberedBIP39Mnemonic(valid12WordMnemonic),
			wantRaw: []string{
				valid12WordMnemonic,
			},
		},
		{
			name:    "normalizes case and excludes surrounding words",
			input:   "recovery phrase: " + strings.ToUpper(valid12WordMnemonic),
			wantRaw: []string{valid12WordMnemonic},
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

func TestBIP39_Type(t *testing.T) {
	d := Scanner{}
	if int(d.Type()) != 1056 {
		t.Errorf("expected type 1056 (BIP39SeedPhrase), got %d", d.Type())
	}
}

func TestBIP39_KeywordsDoesNotIncludeCommonWords(t *testing.T) {
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

	uncommonMnemonicWords := []string{"dice", "stable"}
	for _, w := range uncommonMnemonicWords {
		if _, ok := keywords[w]; !ok {
			t.Errorf("expected uncommon mnemonic word %q to remain in Keywords()", w)
		}
	}
}
