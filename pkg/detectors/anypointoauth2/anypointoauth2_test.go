package anypointoauth2

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern   = "anypoint id: e3cd10a87f53b2dfa4b5fd606e7d9eca / secret: ACE9d7E606Df5B4AFD2B35f78A01DC3E"
	complexPattern = `
	# Secret Configuration File
	# Organization details
	ORG_NAME=my_organization
	ORG_ID=abcd1234-ef56-gh78-ij90-klmn1234opqr

	# Database credentials
	DB_USERNAME=iamnotadmin
	DB_PASSWORD=8f3b6d3e7c9a2f5e

	# OAuth tokens
	CLIENT_ID=e3cd10a87f53b2dfa4b5fd606e7d9eca
	CLIENT_SECRET=ACE9d7E606Df5B4AFD2B35f78A01DC3E

	# API keys
	API_KEY=sk-ant-api03-nothing-just-some-random-api-key-1234fghijklmnopAA
	SECRET_KEY=1a2b3c4d-5e6f-7g8h-9i0j-k1l2m3n4o5p6

	# Endpoints
	SERVICE_URL=https://api.example.com/v1/resource
	`
	invalidPattern = "anypoint id: k4lzc5ty98tnfu3a11y8gnv5vb1281as / secret: 8SBT9p4NXPYVS89EPtYV29SVT2SFcD8A"
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
			want:  []string{"e3cd10a87f53b2dfa4b5fd606e7d9eca:ACE9d7E606Df5B4AFD2B35f78A01DC3E"},
		},
		{
			name:  "valid pattern - complex",
			input: fmt.Sprintf("anypoint credentials: %s", complexPattern),
			want:  []string{"e3cd10a87f53b2dfa4b5fd606e7d9eca:ACE9d7E606Df5B4AFD2B35f78A01DC3E"},
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
