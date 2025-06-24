package anypoint

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern   = "1a2b3c4d-5e6f-7g8h-9i0j-k1l2m3n4o5p6 / org: abcd1234-ef56-gh78-ij90-klmn1234opqr"
	complexPattern = `
	# Secret Configuration File
	# Organization details
	ORG_NAME=my_organization
	ORG_ID=abcd1234-ef56-gh78-ij90-klmn1234opqr

	# Database credentials
	DB_USERNAME=iamnotadmin
	DB_PASSWORD=8f3b6d3e7c9a2f5e

	# OAuth tokens
	ACCESS_TOKEN=abcxyz123
	REFRESH_TOKEN=zyxwvutsrqponmlkji9876543210abcd

	# API keys
	API_KEY=sk-ant-api03-nothing-just-some-random-api-key-1234fghijklmnopAA
	SECRET_KEY=1a2b3c4d-5e6f-7g8h-9i0j-k1l2m3n4o5p6

	# Endpoints
	SERVICE_URL=https://api.example.com/v1/resource
	`
	invalidPattern = "1a2b3C4d-5E6f-7g8H-9i0J-k1l2M3n4o5p6 / abcd1234-eF56-gH78-ij90-klmn1234opqr"
)

func TestAnypoint_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern",
			input: fmt.Sprintf("anypoint credentials: %s", validPattern),
			want:  []string{"1a2b3c4d-5e6f-7g8h-9i0j-k1l2m3n4o5p6abcd1234-ef56-gh78-ij90-klmn1234opqr"},
		},
		{
			name:  "valid pattern - complex",
			input: fmt.Sprintf("anypoint credentials: %s", complexPattern),
			want:  []string{"1a2b3c4d-5e6f-7g8h-9i0j-k1l2m3n4o5p6abcd1234-ef56-gh78-ij90-klmn1234opqr"},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("anypoint credentials: %s", invalidPattern),
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
