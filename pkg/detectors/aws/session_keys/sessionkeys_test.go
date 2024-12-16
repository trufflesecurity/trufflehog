package session_keys

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern = `
		aws credentials{
			id: ASIABBKK02W42Q3IPSPG
			secret: fkhIiUwQY32Zu9e4a86g9r3WpTzfE1aXljVcgn8O
			session: >aSqfp/GTZbJP+=tXPNCZ9GoveoM0vgxtlYXdzPQ2uYNMPPgUkt0VT7SoTLasAo7iVqWWREOUC6DEenlcgDEKyzIEgQ=W5Ju/b9K/Z176uD2HJYCfq/lyowHtt5PvJi7LR=uf/urSorGbTcqNUvP=i42YP1Ps/4F6He9hQA1io3EAGBC3ICGHXWf2IlvFoTNUyPTqhjnPEKMWZ42jblqNA=dD7hLpzNXmmGhdLCjy99XK8+gjHdZHkOeD/FIjRPRZ7Jl0tdwdqFEwzRVCzL2uelMVMd3UaZ+d4I4Kf+J464piO//jxx48Fs/mG3zr5ba9m2S+6gvUZJq4j+0uJ+jf6cG/x2G9XSybqYQRwvxfNquKB4TcKiGVH5+ZbJT4ASkARadwoSPMGfvMPje+X2zAziSzXfsxYfIQKf6iJ9p7VavlDGi+Acr4kwFXW5IfQs4uGk6AVQFsoZK3o1hhLOkuOwWQEWhDQGNLXwJbFqXfELOnUQvM0Z5NUm46bjAAi4g+X9gLPNR/KjzXuuTTaWYrQEjXLb7PxS0sIttAb1w+sTXXtc1kDIsABC6KcsyGlEwji5sLkbkUa~
		}
	`
	invalidPattern = `
		aws credentials{
			id: ASIABBKK02W42Q3IPSPG
			secret: $YenOG.PKHl7LcdVYsjaR4LgQiZ1zw3MAnMyiondXC63;
		}
	`
)

func TestAWSSessionKey_Pattern(t *testing.T) {
	d := scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern",
			input: validPattern,
			want:  []string{"ASIABBKK02W42Q3IPSPGfkhIiUwQY32Zu9e4a86g9r3WpTzfE1aXljVcgn8OaSqfp/GTZbJP+=tXPNCZ9GoveoM0vgxtlYXdzPQ2uYNMPPgUkt0VT7SoTLasAo7iVqWWREOUC6DEenlcgDEKyzIEgQ=W5Ju/b9K/Z176uD2HJYCfq/lyowHtt5PvJi7LR=uf/urSorGbTcqNUvP=i42YP1Ps/4F6He9hQA1io3EAGBC3ICGHXWf2IlvFoTNUyPTqhjnPEKMWZ42jblqNA=dD7hLpzNXmmGhdLCjy99XK8+gjHdZHkOeD/FIjRPRZ7Jl0tdwdqFEwzRVCzL2uelMVMd3UaZ+d4I4Kf+J464piO//jxx48Fs/mG3zr5ba9m2S+6gvUZJq4j+0uJ+jf6cG/x2G9XSybqYQRwvxfNquKB4TcKiGVH5+ZbJT4ASkARadwoSPMGfvMPje+X2zAziSzXfsxYfIQKf6iJ9p7VavlDGi+Acr4kwFXW5IfQs4uGk6AVQFsoZK3o1hhLOkuOwWQEWhDQGNLXwJbFqXfELOnUQvM0Z5NUm46bjAAi4g+X9gLPNR/KjzXuuTTaWYrQEjXLb7PxS0sIttAb1w+sTXXtc1kDIsABC6KcsyGlEwji5sLkbkUa"},
		},
		{
			name:  "invalid pattern",
			input: invalidPattern,
			want:  nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
				t.Errorf("keywords '%v' not matched by: %s", d.Keywords(), test.input)
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			if err != nil {
				t.Errorf("error = %v", err)
				return
			}

			if len(results) != len(test.want) {
				if len(results) == 0 {
					t.Errorf("did not receive result")
				} else {
					t.Errorf("expected %d results, only received %d", len(test.want), len(results))
				}
				return
			}

			actual := make(map[string]struct{}, len(results))
			for _, r := range results {
				if len(r.RawV2) > 0 {
					actual[string(r.RawV2)] = struct{}{}
				} else {
					actual[string(r.Raw)] = struct{}{}
				}
			}
			expected := make(map[string]struct{}, len(test.want))
			for _, v := range test.want {
				expected[v] = struct{}{}
			}

			if diff := cmp.Diff(expected, actual); diff != "" {
				t.Errorf("%s diff: (-want +got)\n%s", test.name, diff)
			}
		})
	}
}
