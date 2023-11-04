//go:build detectors
// +build detectors

package detectors

import (
	_ "embed"
	"testing"
)

func TestIsFalsePositive(t *testing.T) {
	type args struct {
		match          string
		falsePositives []FalsePositive
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
			},
			want: true,
		},
		{
			name: "not fp",
			args: args{
				match:          "notafp123",
				falsePositives: DefaultFalsePositives,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsKnownFalsePositive(tt.args.match, tt.args.falsePositives, false); got != tt.want {
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
			want: 0.22228483068568816,
		},
		{
			name: "entropy 3",
			args: args{
				input: "aaaaaaaaaaaaaaaaaaaaaaaaaaabaaaaaaaaaaaaaaaaaaaaaaaaaaab",
			},
			want: 0.22228483068568816,
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
			if got := StringShannonEntropy(tt.args.input); got != tt.want {
				t.Errorf("StringShannonEntropy() = %v, want %v", got, tt.want)
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
