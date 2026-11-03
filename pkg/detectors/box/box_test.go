package box

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestBox_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid pattern",
			input: `
				[INFO] request received to fetch box data
				[INFO] sending API request to box API
				[DEBUG] using Key=Ogowv5cj5AJJjO5F3daNHbKJDdPud0CZ
				[DEBUG] request sent successfully
				[INFO] response received: 200 OK
				[DEBUG] fetch data from the database for ID Qje1HjJmgrNzOQpQZROEeYjmHbD2qdFF
				[INFO] data returned
			`,
			want: []string{"Ogowv5cj5AJJjO5F3daNHbKJDdPud0CZ"},
		},
		{
			name: "valid pattern - xml",
			input: `
				<com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
  					<scope>GLOBAL</scope>
  					<id>{box}</id>
  					<secret>{box AQAAABAAA Dxb2zNdFF2QTSMwrZJnoeD54Dc4zZAIW}</secret>
  					<description>configuration for production</description>
					<creationDate>2023-05-18T14:32:10Z</creationDate>
  					<owner>jenkins-admin</owner>
				</com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
			`,
			want: []string{"Dxb2zNdFF2QTSMwrZJnoeD54Dc4zZAIW"},
		},
		{
			name:  "company name in CSV",
			input: "company,tenant_id\nEXAMPLE ICEBOX COMPANY,0123456789abcdef0123456789abcdef\n",
			want:  nil,
		},
		{
			name:  "company name in Markdown",
			input: "| company | tenant_id |\n| EXAMPLE ICEBOX COMPANY | `0123456789abcdef0123456789abcdef` |\n",
			want:  nil,
		},
		{
			name:  "unrelated provider",
			input: "dropbox_token=Ogowv5cj5AJJjO5F3daNHbKJDdPud0CZ",
			want:  nil,
		},
		{
			name:  "snake case token label",
			input: "my_box_token=Ogowv5cj5AJJjO5F3daNHbKJDdPud0CZ",
			want:  []string{"Ogowv5cj5AJJjO5F3daNHbKJDdPud0CZ"},
		},
		{
			name:  "camel case token label",
			input: "boxToken=Ogowv5cj5AJJjO5F3daNHbKJDdPud0CZ",
			want:  []string{"Ogowv5cj5AJJjO5F3daNHbKJDdPud0CZ"},
		},
		{
			name:  "prefixed camel case token label",
			input: "myBoxToken=Ogowv5cj5AJJjO5F3daNHbKJDdPud0CZ",
			want:  []string{"Ogowv5cj5AJJjO5F3daNHbKJDdPud0CZ"},
		},
		{
			name:  "prefixed camel case key label",
			input: "prodBoxKey=Ogowv5cj5AJJjO5F3daNHbKJDdPud0CZ",
			want:  []string{"Ogowv5cj5AJJjO5F3daNHbKJDdPud0CZ"},
		},
		{
			name:  "Pascal case token label",
			input: "MyBoxToken=Ogowv5cj5AJJjO5F3daNHbKJDdPud0CZ",
			want:  []string{"Ogowv5cj5AJJjO5F3daNHbKJDdPud0CZ"},
		},
		{
			name:  "lowercase embedded keyword",
			input: "icebox=0123456789abcdef0123456789abcdef",
			want:  nil,
		},
		{
			name:  "uppercase embedded keyword",
			input: "DROPBOX_TOKEN=Ogowv5cj5AJJjO5F3daNHbKJDdPud0CZ",
			want:  nil,
		},
		{
			name:  "hexadecimal token with explicit Box context",
			input: "BOX_TOKEN=0123456789abcdef0123456789abcdef",
			want:  []string{"0123456789abcdef0123456789abcdef"},
		},
		{
			name: "invalid pattern",
			input: `
				[INFO] request received to fetch box data
				[INFO] sending API request to box API
				[DEBUG] using Key=Ogow-v5cj-5AJJ-jO5F-3daN-HbKJ-DdPu-d0CZ
				[DEBUG] request sent successfully
				[ERROR] response received: 401 UnAuthorized
				[INFO] nothing to return
			`,
			want: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
				t.Errorf("test %q failed: expected keywords %v to be found in the input", test.name, d.Keywords())
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			require.NoError(t, err)

			if len(results) != len(test.want) {
				t.Errorf("mismatch in result count: expected %d, got %d", len(test.want), len(results))
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

			requests := 0
			verifier := Scanner{client: &http.Client{Transport: common.FakeTransport{
				CreateResponse: func(req *http.Request) (*http.Response, error) {
					requests++
					require.Equal(t, "https://api.box.com/2.0/users/me", req.URL.String())
					return &http.Response{
						StatusCode: http.StatusUnauthorized,
						Body:       io.NopCloser(strings.NewReader("")),
						Header:     make(http.Header),
					}, nil
				},
			}}}
			verifiedResults, err := verifier.FromData(context.Background(), true, []byte(test.input))
			require.NoError(t, err)
			require.Len(t, verifiedResults, len(test.want))
			require.Equal(t, len(test.want), requests)
			for _, result := range verifiedResults {
				require.Contains(t, expected, string(result.Raw))
				require.False(t, result.Verified)
			}
		})
	}
}
