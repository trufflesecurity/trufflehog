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
	d.SetCloudEndpoints(d.CloudEndpoints()...)
	d.UseCloudEndpoints(true)
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
		"example.atlassian.net":  true,
		"atlassian.net":          true,
		"api.atlassian.com":      true,
		"acme.jira.com":          true,
		"EXAMPLE.Atlassian.Net":  true,
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

func TestFoundHosts(t *testing.T) {
	tests := []struct {
		name    string
		domains []string
		want    []string
	}{
		{
			name:    "non-atlassian domains are dropped",
			domains: []string{"tenant.atlassian.net", "hooks.example.com"},
			want:    []string{"tenant.atlassian.net"},
		},
		{
			name:    "nothing atlassian found",
			domains: []string{"hooks.example.com"},
			want:    []string{},
		},
		{
			// The cloud host is a normal Atlassian host when it shows up in the data.
			name:    "cloud host in the data is kept",
			domains: []string{CloudHost},
			want:    []string{CloudHost},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			domains := make(map[string]struct{}, len(test.domains))
			for _, d := range test.domains {
				domains[d] = struct{}{}
			}
			if diff := cmp.Diff(test.want, FoundHosts(domains)); diff != "" {
				t.Errorf("FoundHosts() diff: (-want +got)\n%s", diff)
			}
		})
	}
}

func TestVerificationHosts(t *testing.T) {
	const cloudEndpoint = "https://" + CloudHost

	tests := []struct {
		name      string
		endpoints []string
		found     []string
		want      []string
	}{
		{
			// EndpointSetter puts the cloud endpoint ahead of the found ones, so leaving it in would let it
			// win the break-on-verified and report a domain the analyzer cannot use.
			name:      "cloud dropped when the data named a host",
			endpoints: []string{cloudEndpoint, "tenant.atlassian.net"},
			found:     []string{"tenant.atlassian.net"},
			want:      []string{"tenant.atlassian.net"},
		},
		{
			name:      "cloud kept when the data named nothing",
			endpoints: []string{cloudEndpoint},
			found:     nil,
			want:      []string{CloudHost},
		},
		{
			// Dropping the cloud host here would leave no hosts at all and produce no results.
			name:      "cloud kept when the data named it",
			endpoints: []string{cloudEndpoint, CloudHost},
			found:     []string{CloudHost},
			want:      []string{CloudHost},
		},
		{
			name:      "configured endpoints are reduced to hosts and deduped",
			endpoints: []string{"https://jira.example.com:8443/", cloudEndpoint, "tenant.atlassian.net", "https://tenant.atlassian.net", ""},
			found:     []string{"tenant.atlassian.net"},
			want:      []string{"jira.example.com:8443", "tenant.atlassian.net"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if diff := cmp.Diff(test.want, VerificationHosts(test.endpoints, test.found)); diff != "" {
				t.Errorf("VerificationHosts() diff: (-want +got)\n%s", diff)
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
