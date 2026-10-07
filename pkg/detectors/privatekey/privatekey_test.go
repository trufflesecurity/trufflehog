package privatekey

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern = `-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu
KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQJAIJLixBy2qpFoS4DSmoEm
o3qGy0t6z09AIJtH+5OeRV1be+N4cDYJKffGzDa88vQENZiRm0GRq6a+HPGQMd2k
TQIhAKMSvzIBnni7ot/OSie2TmJLY4SwTQAevXysE2RbFDYdAiEBCUEaRQnMnbp7
9mxDXDf6AU0cN/RPBjb9qSHDcWZHGzUCIG2Es59z8ugGrDY+pxLQnwfotadxd+Uy
v/Ow5T0q5gIJAiEAyS4RaI9YG8EWx/2w0T67ZUVAw8eOMB6BIUg0Xcu+3okCIBOs
/5OiPgoTdSy7bcF9IGpSE8ZgGKzgYQVZeN97YE00
-----END RSA PRIVATE KEY-----
`
	invalidPattern = `-----BEGIN?RSA?PRIVATE?KEY-----
MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu
KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQJAIJLixBy2qpFoS4DSmoEm
o3qGy0t6z09AIJtH+5OeRV1be+N4cDYJKffGzDa88vQENZiRm0GRq6a+HPGQMd2k
TQIhAKMSvzIBnni7ot/OSie2TmJLY4SwTQAevXysE2RbFDYdAiEBCUEaRQnMnbp7
9mxDXDf6AU0cN/RPBjb9qSHDcWZHGzUCIG2Es59z8ugGrDY+pxLQnwfotadxd+Uy
v/Ow5T0q5gIJAiEAyS4RaI9YG8EWx/2w0T67ZUVAw8eOMB6BIUg0Xcu+3okCIBOs
/5OiPgoTdSy7bcF9IGpSE8ZgGKzgYQVZeN97YE00
-----END RSA PRIVATE KEY-----`
	keyword = "privatekey"
)

func TestPrivatekey_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword privatekey",
			input: fmt.Sprintf("%s token = '%s'", keyword, validPattern),
			want:  []string{validPattern},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("%s = '%s'", keyword, invalidPattern),
			want:  []string{},
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

// encryptedUncrackablePattern is an ed25519 key protected by a passphrase that
// is not present in the built-in wordlist (pkg/detectors/privatekey/list.txt),
// so Crack cannot recover it.
var encryptedUncrackablePattern = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABDnvQyInG
vB+yh/WYczTGXbAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAILUSv84lMSLVN0iP
knFlHoYobo1oohtLNp/ihBaf76QxAAAAoErDjg2HQs1hgYm0vfyrpBxWrcJ1u/LQG4o6cm
GJ3NnZmMmJemrnMXjGHB3zj63AEPxxyb6BWZH5Olb5gYMgWcnOU91cGvyC7aT6C5cOnFb1
ZtkdxTxqeUOMFS51gwDT04aURSz/caCV9KN4Y2MCHyW+GWxxD7eL0R6KhyT2j0z2BewCw9
kRN1fq3C2rTb+wTaNz8q9X0R+6JGxfXGhpTJ0=
-----END OPENSSH PRIVATE KEY-----
`

// TestPrivatekey_EncryptedKeyReported asserts that a passphrase-protected key
// whose passphrase cannot be cracked is still surfaced as an unverified finding
// rather than being dropped silently (issue #5115).
func TestPrivatekey_EncryptedKeyReported(t *testing.T) {
	d := Scanner{}
	input := fmt.Sprintf("%s = '%s'", keyword, encryptedUncrackablePattern)

	results, err := d.FromData(context.Background(), false, []byte(input))
	if err != nil {
		t.Fatalf("FromData error = %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result for an encrypted key with an uncrackable passphrase, got %d", len(results))
	}

	r := results[0]
	if r.Verified {
		t.Errorf("expected the finding to be unverified")
	}
	if r.VerificationError() == nil {
		t.Errorf("expected a verification error to be set on the finding")
	}
	if r.ExtraData["encrypted"] != "true" {
		t.Errorf("expected ExtraData[\"encrypted\"] = \"true\", got %q", r.ExtraData["encrypted"])
	}
}
