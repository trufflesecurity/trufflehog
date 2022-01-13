package sanitizer

import "testing"

func TestUTF8(t *testing.T) {
	type args struct {
		in string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "valid",
			args: args{
				in: "hello123",
			},
			want: "hello123",
		},
		{
			name: "santized",
			args: args{
				in: "Gr\351gory Smith",
			},
			want: "Gr❗gory Smith",
		},
		{
			name: "santized",
			args: args{
				in: "no \x00 nulls because postgres does not support it in text fields",
			},
			want: "no  nulls because postgres does not support it in text fields",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := UTF8(tt.args.in); got != tt.want {
				t.Errorf("UTF8() = %v, want %v", got, tt.want)
			}
		})
	}
}
