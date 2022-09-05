//go:build detectors
// +build detectors

package detectors

import "testing"

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
