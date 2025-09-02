package detectors

import (
	"context"
	_ "embed"
	"testing"

	"github.com/stretchr/testify/assert"

	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type fakeDetector struct{}
type customFalsePositiveChecker struct{ fakeDetector }

func (d fakeDetector) FromData(ctx context.Context, verify bool, data []byte) ([]Result, error) {
	return nil, nil
}

func (d fakeDetector) Keywords() []string {
	return nil
}

func (d fakeDetector) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType(0)
}

func (f fakeDetector) Description() string { return "" }

func (d customFalsePositiveChecker) IsFalsePositive(result Result) (bool, string) {
	return IsKnownFalsePositive(string(result.Raw), map[FalsePositive]struct{}{"a specific magic string": {}}, false)
}

func TestFilterKnownFalsePositives_DefaultLogic(t *testing.T) {
	results := []Result{
		{Raw: []byte("00000")},  // "default" false positive list
		{Raw: []byte("number")}, // from wordlist
		// from uuid list
		{Raw: []byte("00000000-0000-0000-0000-000000000000")},
		{Raw: []byte("xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")},
		// real secrets
		{Raw: []byte("hga8adshla3434g")},
		{Raw: []byte("f795f7db-2dfe-4095-96f3-8f8370c735f9")},
	}
	expected := []Result{
		{Raw: []byte("hga8adshla3434g")},
		{Raw: []byte("f795f7db-2dfe-4095-96f3-8f8370c735f9")},
	}
	filtered := FilterKnownFalsePositives(logContext.Background(), fakeDetector{}, results)
	assert.ElementsMatch(t, expected, filtered)
}

func TestFilterKnownFalsePositives_CustomLogic(t *testing.T) {
	results := []Result{
		{Raw: []byte("a specific magic string")}, // specific target
		{Raw: []byte("00000")},                   // "default" false positive list
		{Raw: []byte("number")},                  // from wordlist
		{Raw: []byte("hga8adshla3434g")},         // real secret
	}
	expected := []Result{
		{Raw: []byte("00000")},
		{Raw: []byte("number")},
		{Raw: []byte("hga8adshla3434g")},
	}
	filtered := FilterKnownFalsePositives(logContext.Background(), customFalsePositiveChecker{}, results)
	assert.ElementsMatch(t, expected, filtered)
}

func TestIsFalsePositive(t *testing.T) {
	type args struct {
		match          string
		falsePositives map[FalsePositive]struct{}
		useWordlist    bool
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "fp",
			args: args{
				match:          "example",
				falsePositives: DefaultFalsePositives,
				useWordlist:    false,
			},
			want: true,
		},
		{
			name: "fp - in wordlist",
			args: args{
				match:          "sdfdsfprivatesfsdfd",
				falsePositives: DefaultFalsePositives,
				useWordlist:    true,
			},
			want: true,
		},
		{
			name: "fp - not in wordlist",
			args: args{
				match:          "sdfdsfsfsdfd",
				falsePositives: DefaultFalsePositives,
				useWordlist:    true,
			},
			want: false,
		},
		{
			name: "not fp",
			args: args{
				match:          "notafp123",
				falsePositives: DefaultFalsePositives,
				useWordlist:    false,
			},
			want: false,
		},
		{
			name: "fp - in wordlist exact match",
			args: args{
				match:          "private",
				falsePositives: DefaultFalsePositives,
				useWordlist:    true,
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := IsKnownFalsePositive(tt.args.match, tt.args.falsePositives, tt.args.useWordlist); got != tt.want {
				t.Errorf("IsKnownFalsePositive() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStringShannonEntropy(t *testing.T) {
	type args struct {
		input string
	}
	tests := []struct {
		name string
		args args
		want float64
	}{
		{
			name: "entropy 1",
			args: args{
				input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			want: 0,
		},
		{
			name: "entropy 2",
			args: args{
				input: "aaaaaaaaaaaaaaaaaaaaaaaaaaab",
			},
			want: 0.22,
		},
		{
			name: "entropy 3",
			args: args{
				input: "aaaaaaaaaaaaaaaaaaaaaaaaaaabaaaaaaaaaaaaaaaaaaaaaaaaaaab",
			},
			want: 0.22,
		},
		{
			name: "empty",
			args: args{
				input: "",
			},
			want: 0.0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := StringShannonEntropy(tt.args.input)
			if len(tt.args.input) > 0 && tt.want != 0 {
				assert.InEpsilon(t, tt.want, got, 0.1)
			} else {
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestFilterWhitelistedSecrets(t *testing.T) {
	ctx := logContext.Background()

	tests := []struct {
		name               string
		results            []Result
		whitelistedSecrets map[string]struct{}
		expected           []Result
	}{
		{
			name: "exact string match",
			results: []Result{
				{Raw: []byte("secret123")},
				{Raw: []byte("password456")},
				{Raw: []byte("token789")},
			},
			whitelistedSecrets: map[string]struct{}{
				"secret123": {},
			},
			expected: []Result{
				{Raw: []byte("password456")},
				{Raw: []byte("token789")},
			},
		},
		{
			name: "regex pattern match",
			results: []Result{
				{Raw: []byte("test-api-key-12345")},
				{Raw: []byte("prod-api-key-67890")},
				{Raw: []byte("dev-token-abcdef")},
				{Raw: []byte("random-secret")},
			},
			whitelistedSecrets: map[string]struct{}{
				`^test-.*`:    {},
				`.*-token-.*`: {},
			},
			expected: []Result{
				{Raw: []byte("prod-api-key-67890")},
				{Raw: []byte("random-secret")},
			},
		},
		{
			name: "mixed exact and regex patterns",
			results: []Result{
				{Raw: []byte("exact-match")},
				{Raw: []byte("dev-key-123")},
				{Raw: []byte("prod-key-456")},
				{Raw: []byte("another-secret")},
			},
			whitelistedSecrets: map[string]struct{}{
				"exact-match": {}, // exact string
				`^dev-.*`:     {}, // regex pattern
			},
			expected: []Result{
				{Raw: []byte("prod-key-456")},
				{Raw: []byte("another-secret")},
			},
		},
		{
			name: "invalid regex treated as literal string",
			results: []Result{
				{Raw: []byte("[invalid")},
				{Raw: []byte("valid-secret")},
			},
			whitelistedSecrets: map[string]struct{}{
				"[invalid": {}, // invalid regex, treated as literal
			},
			expected: []Result{
				{Raw: []byte("valid-secret")},
			},
		},
		{
			name: "case sensitive regex",
			results: []Result{
				{Raw: []byte("Secret123")},
				{Raw: []byte("secret456")},
			},
			whitelistedSecrets: map[string]struct{}{
				`^secret.*`: {}, // case sensitive - should only match lowercase
			},
			expected: []Result{
				{Raw: []byte("Secret123")},
			},
		},
		{
			name: "case insensitive regex",
			results: []Result{
				{Raw: []byte("Secret123")},
				{Raw: []byte("secret456")},
				{Raw: []byte("other789")},
			},
			whitelistedSecrets: map[string]struct{}{
				`(?i)^secret.*`: {}, // case insensitive
			},
			expected: []Result{
				{Raw: []byte("other789")},
			},
		},
		{
			name: "RawV2 field testing",
			results: []Result{
				{
					Raw:   []byte("primary-secret"),
					RawV2: []byte("secondary-secret"),
				},
			},
			whitelistedSecrets: map[string]struct{}{
				"secondary-secret": {},
			},
			expected: []Result{}, // should be filtered out due to RawV2 match
		},
		{
			name:    "empty results",
			results: []Result{},
			whitelistedSecrets: map[string]struct{}{
				"any-pattern": {},
			},
			expected: []Result{},
		},
		{
			name: "empty whitelist",
			results: []Result{
				{Raw: []byte("secret123")},
			},
			whitelistedSecrets: map[string]struct{}{},
			expected: []Result{
				{Raw: []byte("secret123")},
			},
		},
		{
			name: "nil whitelist",
			results: []Result{
				{Raw: []byte("secret123")},
			},
			whitelistedSecrets: nil,
			expected: []Result{
				{Raw: []byte("secret123")},
			},
		},
		{
			name: "complex regex patterns",
			results: []Result{
				{Raw: []byte("api-key-12345")},
				{Raw: []byte("token-67890")},
				{Raw: []byte("secret-abcdef")},
				{Raw: []byte("random-secret-123")},
			},
			whitelistedSecrets: map[string]struct{}{
				`^api-key-\d+$`:   {}, // API keys with numbers
				`^token-\d+$`:     {}, // Tokens with numbers
				`^secret-[a-f]+$`: {}, // Secrets with hex chars
			},
			expected: []Result{
				{Raw: []byte("random-secret-123")}, // This doesn't match any pattern
			},
		},
		{
			name: "hexadecimal pattern matching",
			results: []Result{
				{Raw: []byte("abcdef1234567890")},    // 16-char hex
				{Raw: []byte("123456789abcdef0123")}, // 19-char hex
				{Raw: []byte("ghijklmnop123456")},    // not hex
				{Raw: []byte("ABC123DEF456")},        // mixed case hex
			},
			whitelistedSecrets: map[string]struct{}{
				`^[a-f0-9]{16}$`:    {}, // exactly 16 lowercase hex chars
				`^[A-F0-9a-f]{12}$`: {}, // exactly 12 mixed case hex chars
			},
			expected: []Result{
				{Raw: []byte("123456789abcdef0123")}, // 19 chars, doesn't match 16-char pattern
				{Raw: []byte("ghijklmnop123456")},    // contains non-hex chars
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FilterWhitelistedSecrets(ctx, tt.results, tt.whitelistedSecrets)
			assert.ElementsMatch(t, tt.expected, result)
		})
	}
}

func TestIsSecretWhitelisted(t *testing.T) {
	tests := []struct {
		name               string
		secret             string
		whitelistedSecrets map[string]struct{}
		expectedMatch      bool
		expectedReason     string
	}{
		{
			name:   "exact string match",
			secret: "exact-secret",
			whitelistedSecrets: map[string]struct{}{
				"exact-secret": {},
			},
			expectedMatch:  true,
			expectedReason: "exact match",
		},
		{
			name:   "regex pattern match",
			secret: "test-key-12345",
			whitelistedSecrets: map[string]struct{}{
				`^test-.*`: {},
			},
			expectedMatch:  true,
			expectedReason: "regex match: ^test-.*",
		},
		{
			name:   "no match",
			secret: "random-secret",
			whitelistedSecrets: map[string]struct{}{
				"different-secret": {},
				`^test-.*`:         {},
			},
			expectedMatch:  false,
			expectedReason: "",
		},
		{
			name:   "exact match takes precedence over regex",
			secret: "test-key",
			whitelistedSecrets: map[string]struct{}{
				"test-key": {}, // exact match
				`^test-.*`: {}, // regex match
			},
			expectedMatch:  true,
			expectedReason: "exact match", // should prefer exact over regex
		},
		{
			name:   "invalid regex treated as literal",
			secret: "[invalid",
			whitelistedSecrets: map[string]struct{}{
				"[invalid": {}, // invalid regex
			},
			expectedMatch:  true,
			expectedReason: "exact match",
		},
		{
			name:   "empty secret",
			secret: "",
			whitelistedSecrets: map[string]struct{}{
				"": {},
			},
			expectedMatch:  true,
			expectedReason: "exact match",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, reason := isSecretWhitelisted(tt.secret, tt.whitelistedSecrets)
			assert.Equal(t, tt.expectedMatch, match)
			assert.Equal(t, tt.expectedReason, reason)
		})
	}
}

func BenchmarkFilterWhitelistedSecrets(b *testing.B) {
	ctx := logContext.Background()

	results := []Result{
		{Raw: []byte("secret1")},
		{Raw: []byte("test-api-key-12345")},
		{Raw: []byte("prod-token-abcdef")},
		{Raw: []byte("random-secret-123")},
		{Raw: []byte("dev-key-67890")},
	}

	whitelistedSecrets := map[string]struct{}{
		"secret1":     {}, // exact match
		`^test-.*`:    {}, // regex
		`.*-token-.*`: {}, // regex
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		FilterWhitelistedSecrets(ctx, results, whitelistedSecrets)
	}
}

func BenchmarkIsSecretWhitelisted(b *testing.B) {
	whitelistedSecrets := map[string]struct{}{
		"exact-secret":   {},
		`^test-.*`:       {},
		`.*-token-.*`:    {},
		`^[a-f0-9]{32}$`: {},
	}

	secrets := []string{
		"exact-secret",                     // exact match
		"test-key-12345",                   // regex match
		"random-token-abc",                 // regex match
		"abcdef1234567890abcdef1234567890", // regex match
		"no-match-secret",                  // no match
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, secret := range secrets {
			isSecretWhitelisted(secret, whitelistedSecrets)
		}
	}
}

func BenchmarkDefaultIsKnownFalsePositive(b *testing.B) {
	for i := 0; i < b.N; i++ {
		// Use a string that won't be found in any dictionary for the worst case check.
		IsKnownFalsePositive("aoeuaoeuaoeuaoeuaoeuaoeu", DefaultFalsePositives, true)
	}
}
