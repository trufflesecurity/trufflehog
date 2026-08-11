package jiratoken

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validTokenPattern    = "Z7VoIYJ0K4rFWLBfkhOsLAWX"
	invalidTokenPattern  = "Z7VoI?J0K4rF#LBfkhO&LAWX"
	validDomainPattern   = "hereisavalidsubdomain.atlassian.net"
	foreignDomainPattern = "hereisavalidsubdomain.heresalongdomain.com"
	cloudDomain          = "api.atlassian.com"
	invalidDomainPattern = "?y4r3fs1ewqec12v1e3tl.5Hcsrcehic89saXd.ro@"
	validEmailPattern    = "xfkf_bz7@grum.com"
	invalidEmailPattern  = "xfKF_BZq7/grum.com"
	keyword              = "jira"
)

func TestJiraToken_Pattern(t *testing.T) {
	d := Scanner{}
	d.SetCloudEndpoint(d.CloudEndpoint())
	d.UseCloudEndpoint(true)
	d.UseFoundEndpoints(true)
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword jira",
			input: fmt.Sprintf("%s %s          \n%s %s\n%s %s", keyword, validTokenPattern, keyword, validDomainPattern, keyword, validEmailPattern),
			// The tenant host found in the data is used on its own. The cloud endpoint must not shadow it,
			// or SecretParts["domain"] would stop being the host the analyzer needs.
			want: []string{validEmailPattern + ":" + validTokenPattern + ":" + validDomainPattern},
		},
		{
			// A domain that isn't Atlassian-owned can't answer the verification request, so it is dropped
			// and only the cloud endpoint remains.
			name:  "non-atlassian domain falls back to the cloud endpoint",
			input: fmt.Sprintf("%s %s          \n%s %s\n%s %s", keyword, validTokenPattern, keyword, foreignDomainPattern, keyword, validEmailPattern),
			want:  []string{validEmailPattern + ":" + validTokenPattern + ":" + cloudDomain},
		},
		{
			name:  "valid pattern - key out of prefix range",
			input: fmt.Sprintf("%s keyword is not close to the real key in the data\n = '%s' domain = '%s' email = '%s'", keyword, validTokenPattern, validDomainPattern, validEmailPattern),
			want:  []string{},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("%s key = '%s' domain = '%s' email = '%s'", keyword, invalidTokenPattern, invalidDomainPattern, invalidEmailPattern),
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

func TestIsAtlassianHost(t *testing.T) {
	tests := map[string]bool{
		"example.atlassian.net": true,
		"atlassian.net":         true,
		"api.atlassian.com":     true,
		"acme.jira.com":         true,
		"EXAMPLE.Atlassian.Net": true,
		"example.atlassian.net.": true,
		// Suffix lookalikes must not pass, or the filter would be trivially bypassed.
		"notatlassian.net":            false,
		"atlassian.net.evil.com":      false,
		"example.com":                 false,
		"hereisavalidsubdomain.co.uk": false,
	}

	for host, want := range tests {
		t.Run(host, func(t *testing.T) {
			if got := IsAtlassianHost(host); got != want {
				t.Errorf("IsAtlassianHost(%q) = %v, want %v", host, got, want)
			}
		})
	}
}

func TestWithCloudFallback(t *testing.T) {
	const cloud = "https://api.atlassian.com"

	tests := []struct {
		name      string
		endpoints []string
		haveFound bool
		want      []string
	}{
		{
			// EndpointSetter puts the cloud endpoint ahead of the found ones, so leaving it in would let
			// it win the break-on-verified and report the wrong domain.
			name:      "cloud dropped when the data carried a host",
			endpoints: []string{cloud, "https://tenant.atlassian.net"},
			haveFound: true,
			want:      []string{"https://tenant.atlassian.net"},
		},
		{
			name:      "cloud kept when nothing was found",
			endpoints: []string{cloud},
			haveFound: false,
			want:      []string{cloud},
		},
		{
			name:      "configured endpoint survives either way",
			endpoints: []string{"https://jira.example.com", cloud, "https://tenant.atlassian.net"},
			haveFound: true,
			want:      []string{"https://jira.example.com", "https://tenant.atlassian.net"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := WithCloudFallback(test.endpoints, cloud, test.haveFound)
			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("WithCloudFallback() diff: (-want +got)\n%s", diff)
			}
		})
	}
}

func TestEndpointHostAndURL(t *testing.T) {
	tests := []struct {
		endpoint string
		wantHost string
		wantURL  string
	}{
		{
			endpoint: "example.atlassian.net",
			wantHost: "example.atlassian.net",
			wantURL:  "https://example.atlassian.net/gateway/api/graphql",
		},
		{
			endpoint: "https://api.atlassian.com",
			wantHost: "api.atlassian.com",
			wantURL:  "https://api.atlassian.com/gateway/api/graphql",
		},
		{
			// A user-configured endpoint may carry a scheme, a port and a trailing slash.
			endpoint: "https://jira.example.com:8443/",
			wantHost: "jira.example.com:8443",
			wantURL:  "https://jira.example.com:8443/gateway/api/graphql",
		},
	}

	for _, test := range tests {
		t.Run(test.endpoint, func(t *testing.T) {
			if got := EndpointHost(test.endpoint); got != test.wantHost {
				t.Errorf("EndpointHost(%q) = %q, want %q", test.endpoint, got, test.wantHost)
			}
			if got := verificationURL(test.endpoint); got != test.wantURL {
				t.Errorf("verificationURL(%q) = %q, want %q", test.endpoint, got, test.wantURL)
			}
		})
	}
}

func TestJiraToken_Verify(t *testing.T) {
	tests := []struct {
		name         string
		statusCode   int
		body         string
		wantVerified bool
		wantErr      bool
	}{
		{
			name:         "authenticated user in body is verified",
			statusCode:   200,
			body:         `{"data":{"me":{"user":{"name":"Jira User"}}}}`,
			wantVerified: true,
		},
		{
			// A non-Atlassian host can happily return 200 with unrelated JSON, so the status code alone can't be trusted.
			name:         "200 without a jira user is not verified",
			statusCode:   200,
			body:         `{"method":"POST","host":"example.com"}`,
			wantVerified: false,
		},
		{
			name:         "unauthorized is not verified",
			statusCode:   401,
			body:         `{"code":401,"message":"Unauthorized"}`,
			wantVerified: false,
		},
		{
			name:         "forbidden is not verified",
			statusCode:   403,
			body:         `{"code":403,"message":"Forbidden"}`,
			wantVerified: false,
		},
		{
			// Atlassian never answers 202 here. It comes from unrelated hosts that accept the POST, and it
			// would repeat on every retry, so it has to be terminal rather than an indeterminate error.
			name:         "accepted is not verified and not an error",
			statusCode:   202,
			body:         `{"status":"accepted"}`,
			wantVerified: false,
		},
		{
			name:         "not found is not verified and not an error",
			statusCode:   404,
			body:         `{"code":404,"message":"Not Found"}`,
			wantVerified: false,
		},
		{
			name:         "rate limited is indeterminate",
			statusCode:   429,
			body:         `{"code":429,"message":"Too Many Requests"}`,
			wantVerified: false,
			wantErr:      true,
		},
		{
			name:         "server error is indeterminate",
			statusCode:   500,
			body:         `{"code":500,"message":"Internal Server Error"}`,
			wantVerified: false,
			wantErr:      true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := common.ConstantResponseHttpClient(test.statusCode, test.body)
			verified, err := VerifyJiraToken(context.Background(), client, "user@example.com", "example.atlassian.net", validTokenPattern)
			if (err != nil) != test.wantErr {
				t.Fatalf("got error = %v, wantErr %v", err, test.wantErr)
			}
			if verified != test.wantVerified {
				t.Errorf("got verified = %v, want %v", verified, test.wantVerified)
			}
		})
	}
}
