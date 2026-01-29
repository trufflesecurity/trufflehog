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

// This test validates that GetFalsePositiveCheck, when invoked on a detector that does not implement
// CustomFalsePositiveChecker, returns a predicate that behaves as expected.
func TestGetFalsePositiveCheck_DefaultLogic(t *testing.T) {
	testCases := []struct {
		raw             string
		isFalsePositive bool
	}{
		{"00000", true},  // "default" false positive list
		{"number", true}, // from wordlist
		{"00000000-0000-0000-0000-000000000000", true}, // from uuid list
		{"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", true}, // from uuid list
		{"hga8adshla3434g", false},
		{"f795f7db-2dfe-4095-96f3-8f8370c735f9", false},
	}

	for _, tt := range testCases {
		isFalsePositive, _ := GetFalsePositiveCheck(fakeDetector{})(Result{Raw: []byte(tt.raw)})
		assert.Equal(t, tt.isFalsePositive, isFalsePositive, "secret %q had unexpected false positive status", tt.raw)
	}
}

// This test validates that GetFalsePositiveCheck, when invoked on a detector that implements
// CustomFalsePositiveChecker, returns a predicate that behaves as expected. (Specifically, the predicate should not
// flag secrets that are present in the standard false positive lists.)
func TestGetFalsePositiveCheck_CustomLogic(t *testing.T) {
	testCases := []struct {
		raw             string
		isFalsePositive bool
	}{
		{"a specific magic string", true}, // the specific value the custom checker is looking for
		{"00000", false},
		{"number", false},
		{"00000000-0000-0000-0000-000000000000", false},
		{"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", false},
		{"hga8adshla3434g", false},
		{"f795f7db-2dfe-4095-96f3-8f8370c735f9", false},
	}

	for _, tt := range testCases {
		isFalsePositive, _ := GetFalsePositiveCheck(customFalsePositiveChecker{})(Result{Raw: []byte(tt.raw)})
		assert.Equal(t, tt.isFalsePositive, isFalsePositive, "secret %q had unexpected false positive status", tt.raw)
	}
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

func BenchmarkDefaultIsKnownFalsePositive(b *testing.B) {
	for i := 0; i < b.N; i++ {
		// Use a string that won't be found in any dictionary for the worst case check.
		IsKnownFalsePositive("aoeuaoeuaoeuaoeuaoeuaoeu", DefaultFalsePositives, true)
	}
}
