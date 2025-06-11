package bitbucketapppassword

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestBitbucketAppPassword_FromData(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pair",
			input: "myuser:ATBB123abcDEF456ghiJKL789mnoPQR",
			want:  []string{"myuser:ATBB123abcDEF456ghiJKL789mnoPQR"},
		},
		{
			name:  "valid app password by itself (should not be found)",
			input: "ATBB123abcDEF456ghiJKL789mnoPQR",
			want:  []string{},
		},
		{
			name:  "pair with invalid username",
			input: "my-very-long-username-that-is-over-thirty-characters:ATBB123abcDEF456ghiJKL789mnoPQR",
			want:  []string{},
		},
		{
			name:  "url pattern",
			input: `https://anotheruser:ATBB123abcDEF456ghiJKL789mnoPQR@bitbucket.org`,
			want:  []string{"anotheruser:ATBB123abcDEF456ghiJKL789mnoPQR"},
		},
		{
			name:  "http basic auth pattern",
			input: `("basicauthuser", "ATBB123abcDEF456ghiJKL789mnoPQR")`,
			want:  []string{"basicauthuser:ATBB123abcDEF456ghiJKL789mnoPQR"},
		},
		{
			name:  "multiple matches",
			input: `user1:ATBB123abcDEF456ghiJKL789mnoPQR and then also user2:ATBBzyxwvUT987srqPON654mlkJIH`,
			want:  []string{"user1:ATBB123abcDEF456ghiJKL789mnoPQR", "user2:ATBBzyxwvUT987srqPON654mlkJIH"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := &Scanner{}
			results, err := d.FromData(context.Background(), false, []byte(tc.input))
			if err != nil {
				t.Fatalf("FromData() error = %v", err)
			}

			got := make(map[string]struct{})
			for _, r := range results {
				got[string(r.Raw)] = struct{}{}
			}

			wantSet := make(map[string]struct{})
			for _, w := range tc.want {
				wantSet[w] = struct{}{}
			}

			if diff := cmp.Diff(wantSet, got); diff != "" {
				t.Errorf("FromData() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
