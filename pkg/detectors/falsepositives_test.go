package detectors

import (
	_ "embed"
	"testing"

	"github.com/stretchr/testify/assert"
)

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
