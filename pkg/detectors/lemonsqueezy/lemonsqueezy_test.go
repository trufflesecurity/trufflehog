package lemonsqueezy

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern   = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.TkOQyjzXNs1ExektRLyW2wxKeFk7VWEE0NVQwaBSKjO5EKaXBwZciTfpIPOFKupmt0PkIChZLcI8fX5XOHQK6hy1e2f7gWW0A00ixqbQUAUyfOTBXSHdrZrK6QNd9xi7q7B2m7ei3rfSipMMod7oHyxvVKwKckwcdfDlZ5OwtDy1lhBFeYZWcGiTM2qvTOWQkBMezkwhz23YONwYK2MOP0PaasJhryNui98LbiiXju20dV2tlxslqJD6i856axkolvQRhJWM7y2Jp37iDgIABh6b13LadPbWJgKiOKkrow4UyzYCrcDOQ5Y6to.c8zXA41FY2GgWUWXjwqoem5A6q46CgLicuYZ4M2XuGZ747WQz1ZmtbnLZn4nclSWLpJUEgdxQpNt8GBVBB2_3B4on1m2HkOHBqjrfn5kHuYSeR_zHNPdLXZBER4tpUPx7Dijl1T8WO6cri32vj8oM2o4ihLeFD1Ewd_OYpP-CIzC4jOKn4DFbgtr7CWaE4vf4XEFSn4B4v-XEjgjmSRDcw_a-wRXRnSZCL8UoiN9k0cMyxqXFHxfiFrMcghwFIKHt37fhHEidYh8SwJy3XdJzusRpynUtoHcpfNhgts9Ik3W7jg_HAhMvbg5XxMUYhtQty32sonozf5cVuoXUD0HOe7gbLNMxaHNT8RVYRSHTqzV1FXLdtGBsZMke-6pKuhC1erbPpLB57os6bKetCkwswk9yZI_eNi4MtR8KnhO8aeWUrz2QJUMY6xXI0a1E0yES8yxGQsSe3CHlVhGgjQuLZf9p2_30YB-yu3NIjJTkamgsaWA41H0eX_SuDci35uO"
	invalidPattern = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.TkOQyjzXNs1ExektRLyW2wxKeFk7VWEE0NVQwaBSKjO5EKaXBwZciTfpIPOFKupmt0PkIChZLcI8fX5XOHQK6hy1e2f7gWW0A00ixqbQUAUyfOTBXSHdrZrK6QNd9xi7q7B2m7ei3rfSipMMod7oHyxvVKwKc.c8zXA41FY2GgWUWXjwqoem5A6q46CgLicuYZ4M2XuGZ747WQz1ZmtbnLZn4nclSWLpJUEgdxQpNt8GBVBB2_3B4on1m2HkOHBqjrfn5kHuYSeR_zHNPdLXZBER4tpUPx7Dijl1T8WO6cri32vj8oM2o4ihLeFD1Ewd_OYpP-CIzC4jOKn4DFbgtr7CWaE4vf4XEFSn4B4v-XEjgjmSRDcw_a-wRXRnSZCL8UoiN9k0cMyxqXFHxfiFrMcghwFIKH"
	keyword        = "lemonsqueezy"
)

func TestLemonsqueezy_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword lemonsqueezy",
			input: fmt.Sprintf("%s token = '%s'", keyword, validPattern),
			want:  []string{validPattern},
		},
		{
			name:  "valid pattern - ignore duplicate",
			input: fmt.Sprintf("%s token = '%s' | '%s'", keyword, validPattern, validPattern),
			want:  []string{validPattern},
		},
		{
			name:  "valid pattern - key out of prefix range",
			input: fmt.Sprintf("%s keyword is not close to the real key in the data\n = '%s'", keyword, validPattern),
			want:  []string{},
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
