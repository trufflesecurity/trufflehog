package okta

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
	validDomain         = "a254u0kjk-y64jh762weozo374t.okta.com"
	invalidDomain       = "a254u0kjk-y64jh762?eozo374t.okta.com"
	validToken          = "00JIBRGk12UbkjQaaw4L7VYy9EE8zAEEkIeqGNcSQm"
	invalidToken        = "00JIBRGk12UbkjQaaw4L7?Yy9EE8zAEEkIeqGNcSQm"
	validClientID       = "0oakDa9U4UqGWlG6g3Ot"
	invalidClientID     = "0obkDa9U4UqGWlG6g3Ot"
	validClientSecret   = "OhbVrpoiVgRV5IfLBcbfnoGMbJmTPSIAoCLrZ3aW"
	invalidClientSecret = "OhbVrpoiVgRV5IfLBcbfnoGMbJmTPSIAoCLrZ3a?"
	// Regression fixtures for a boundary bug where `\b` around a charset that includes
	// '-' either failed to match, or silently dropped a leading/trailing hyphen.
	leadingHyphenSecret40  = "-u8jzPde0IgxLd6GncfBAepfJBd0Kh8oOOL8dKLz"
	trailingHyphenSecret40 = "u8jzPde0IgxLd6GncfBAepfJBd0Kh8oOOL8dKLz-"
	leadingHyphenSecret41  = "-u8jzPde0IgxLd6GncfBAepfJBd0Kh8oOOL8dKLzd"
	trailingHyphenSecret41 = "u8jzPde0IgxLd6GncfBAepfJBd0Kh8oOOL8dKLzd-"
	keyword                = "okta"

	// One fixture per Okta tenant suffix, plus near-misses that must not match.
	previewDomain = "acmecorp.oktapreview.com"
	emeaDomain    = "acmecorp.okta-emea.com"
	govDomain     = "acmecorp.okta-gov.com"
	milDomain     = "acmecorp.okta.mil"
	// okta-dnssec.com is a CNAME target for custom-domain DNSSEC, not a tenant domain.
	dnssecDomain = "acmecorp.okta-dnssec.com"
	// Guards the word boundary after the "mil" suffix.
	militaryDomain = "acmecorp.okta.military"
)

func TestOkta_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword okta",
			input: fmt.Sprintf("%s token - '%s'\n%s token - '%s'\n", keyword, validDomain, keyword, validToken),
			want:  []string{validDomain + ":" + validToken},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("%s token - '%s'\n%s token - '%s'\n", keyword, invalidDomain, keyword, invalidToken),
			want:  []string{},
		},
		{
			name:  "valid pattern - oauth client credentials",
			input: fmt.Sprintf("%s domain - '%s'\n%s client_id - '%s'\nclient_secret: '%s'\n", keyword, validDomain, keyword, validClientID, validClientSecret),
			want:  []string{validDomain + ":" + validClientID + ":" + validClientSecret},
		},
		{
			name:  "invalid pattern - oauth client credentials",
			input: fmt.Sprintf("%s domain - '%s'\n%s client_id - '%s'\nclient_secret: '%s'\n", keyword, validDomain, keyword, invalidClientID, invalidClientSecret),
			want:  []string{},
		},
		{
			name:  "valid pattern - oauth client_secret (40 chars) starting with hyphen",
			input: fmt.Sprintf("%s domain - '%s'\n%s client_id - '%s'\nclient_secret: '%s'\n", keyword, validDomain, keyword, validClientID, leadingHyphenSecret40),
			want:  []string{validDomain + ":" + validClientID + ":" + leadingHyphenSecret40},
		},
		{
			name:  "valid pattern - oauth client_secret (40 chars) ending with hyphen",
			input: fmt.Sprintf("%s domain - '%s'\n%s client_id - '%s'\nclient_secret: '%s'\n", keyword, validDomain, keyword, validClientID, trailingHyphenSecret40),
			want:  []string{validDomain + ":" + validClientID + ":" + trailingHyphenSecret40},
		},
		{
			name:  "valid pattern - oauth client_secret (41 chars) starting with hyphen",
			input: fmt.Sprintf("%s domain - '%s'\n%s client_id - '%s'\nclient_secret: '%s'\n", keyword, validDomain, keyword, validClientID, leadingHyphenSecret41),
			want:  []string{validDomain + ":" + validClientID + ":" + leadingHyphenSecret41},
		},
		{
			name:  "valid pattern - oauth client_secret (41 chars) ending with hyphen",
			input: fmt.Sprintf("%s domain - '%s'\n%s client_id - '%s'\nclient_secret: '%s'\n", keyword, validDomain, keyword, validClientID, trailingHyphenSecret41),
			want:  []string{validDomain + ":" + validClientID + ":" + trailingHyphenSecret41},
		},
		{
			name:  "valid pattern - token with oktapreview.com domain",
			input: fmt.Sprintf("%s token - '%s'\n%s token - '%s'\n", keyword, previewDomain, keyword, validToken),
			want:  []string{previewDomain + ":" + validToken},
		},
		{
			name:  "valid pattern - token with okta-emea.com domain",
			input: fmt.Sprintf("%s token - '%s'\n%s token - '%s'\n", keyword, emeaDomain, keyword, validToken),
			want:  []string{emeaDomain + ":" + validToken},
		},
		{
			name:  "valid pattern - token with okta-gov.com domain",
			input: fmt.Sprintf("%s token - '%s'\n%s token - '%s'\n", keyword, govDomain, keyword, validToken),
			want:  []string{govDomain + ":" + validToken},
		},
		{
			name:  "valid pattern - token with okta.mil domain",
			input: fmt.Sprintf("%s token - '%s'\n%s token - '%s'\n", keyword, milDomain, keyword, validToken),
			want:  []string{milDomain + ":" + validToken},
		},
		{
			name:  "valid pattern - oauth client credentials with okta-gov.com domain",
			input: fmt.Sprintf("%s domain - '%s'\n%s client_id - '%s'\nclient_secret: '%s'\n", keyword, govDomain, keyword, validClientID, validClientSecret),
			want:  []string{govDomain + ":" + validClientID + ":" + validClientSecret},
		},
		{
			name:  "valid pattern - oauth client credentials with okta.mil domain",
			input: fmt.Sprintf("%s domain - '%s'\n%s client_id - '%s'\nclient_secret: '%s'\n", keyword, milDomain, keyword, validClientID, validClientSecret),
			want:  []string{milDomain + ":" + validClientID + ":" + validClientSecret},
		},
		{
			name:  "invalid pattern - okta-dnssec.com is not a tenant domain",
			input: fmt.Sprintf("%s token - '%s'\n%s token - '%s'\n", keyword, dnssecDomain, keyword, validToken),
			want:  []string{},
		},
		{
			name:  "invalid pattern - okta.mil suffix must end at a word boundary",
			input: fmt.Sprintf("%s token - '%s'\n%s token - '%s'\n", keyword, militaryDomain, keyword, validToken),
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

func TestOkta_OAuthVerification(t *testing.T) {
	tests := []struct {
		name         string
		statusCode   int
		body         string
		wantVerified bool
		wantErr      bool
	}{
		{
			name:         "200 OK with access token is verified",
			statusCode:   200,
			body:         `{"access_token":"eyJhbGciOiJIUzI1NiJ9...","token_type":"Bearer","expires_in":3600}`,
			wantVerified: true,
		},
		{
			name:         "400 unauthorized_client (valid secret, grant type not enabled) is verified",
			statusCode:   400,
			body:         `{"error":"unauthorized_client","error_description":"The client is not authorized to use the provided grant type."}`,
			wantVerified: true,
		},
		{
			name:         "400 invalid_client (wrong secret) is unverified",
			statusCode:   400,
			body:         `{"error":"invalid_client","error_description":"The client secret supplied for a confidential client is invalid."}`,
			wantVerified: false,
		},
		{
			name:         "400 invalid_client (nonexistent client id) is unverified",
			statusCode:   400,
			body:         `{"errorCode":"invalid_client","errorSummary":"Invalid value for 'client_id' parameter."}`,
			wantVerified: false,
		},
		{
			name:         "400 without recognized keyword (e.g. invalid_scope) returns verification error",
			statusCode:   400,
			body:         `{"error":"invalid_scope","error_description":"The authorization server resource does not have any configured default scopes."}`,
			wantVerified: false,
			wantErr:      true,
		},
		{
			name:         "401 is unverified",
			statusCode:   401,
			body:         ``,
			wantVerified: false,
		},
		{
			name:         "unexpected status code returns verification error",
			statusCode:   500,
			body:         ``,
			wantVerified: false,
			wantErr:      true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := Scanner{client: common.ConstantResponseHttpClient(test.statusCode, test.body)}
			data := []byte(fmt.Sprintf("%s domain - '%s'\n%s client_id - '%s'\nclient_secret: '%s'\n", keyword, validDomain, keyword, validClientID, validClientSecret))

			results, err := s.FromData(context.Background(), true, data)
			if err != nil {
				t.Fatalf("FromData() unexpected error = %v", err)
			}
			if len(results) != 1 {
				t.Fatalf("expected 1 result, got %d", len(results))
			}

			if results[0].Verified != test.wantVerified {
				t.Errorf("Verified = %v, want %v", results[0].Verified, test.wantVerified)
			}
			if gotErr := results[0].VerificationError() != nil; gotErr != test.wantErr {
				t.Errorf("verification error present = %v, want %v (err = %v)", gotErr, test.wantErr, results[0].VerificationError())
			}
		})
	}
}

// TestOkta_CleanResults is a regression test: the generic detectors.CleanResults
// collapses an entire result set down to results[:1] whenever nothing verifies, which
// would silently drop a real OAuth client_secret finding in favor of an unrelated
// unverified SSWS-token finding from the same chunk (or vice versa). Okta's custom
// CleanResults must instead keep one result per distinct secret identity (Redacted).
func TestOkta_CleanResults(t *testing.T) {
	s := Scanner{}

	t.Run("distinct unverified findings both survive", func(t *testing.T) {
		tokenResult := detectors.Result{Redacted: "domain:token-identity", Raw: []byte(validToken)}
		oauthResult := detectors.Result{Redacted: "domain:client-id-identity", Raw: []byte(validClientSecret)}

		cleaned := s.CleanResults([]detectors.Result{tokenResult, oauthResult}, true)
		if len(cleaned) != 2 {
			t.Fatalf("expected both distinct findings to survive cleaning, got %d: %+v", len(cleaned), cleaned)
		}
	})

	t.Run("verified duplicate wins over unverified duplicate with the same identity", func(t *testing.T) {
		unverifiedDup := detectors.Result{Redacted: "same-identity", Verified: false, Raw: []byte("a")}
		verifiedDup := detectors.Result{Redacted: "same-identity", Verified: true, Raw: []byte("b")}

		cleaned := s.CleanResults([]detectors.Result{unverifiedDup, verifiedDup}, true)
		if len(cleaned) != 1 || !cleaned[0].Verified {
			t.Fatalf("expected the single verified duplicate to win, got %+v", cleaned)
		}
	})
}

// TestOkta_FromData_DistinctRedacted confirms FromData itself assigns non-empty,
// distinct Redacted identities to the token and OAuth result shapes, which is what
// TestOkta_CleanResults relies on to avoid conflating unrelated findings.
func TestOkta_FromData_DistinctRedacted(t *testing.T) {
	d := Scanner{}
	data := []byte(fmt.Sprintf(
		"%s token - '%s'\n%s domain - '%s'\n%s client_id - '%s'\nclient_secret: '%s'\n",
		keyword, validToken, keyword, validDomain, keyword, validClientID, validClientSecret,
	))

	results, err := d.FromData(context.Background(), false, data)
	if err != nil {
		t.Fatalf("FromData() unexpected error = %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results (token + oauth), got %d: %+v", len(results), results)
	}

	seen := make(map[string]struct{}, len(results))
	for _, r := range results {
		if r.Redacted == "" {
			t.Errorf("result has empty Redacted identity: %+v", r)
		}
		seen[r.Redacted] = struct{}{}
	}
	if len(seen) != len(results) {
		t.Errorf("expected distinct Redacted identities per result, got %v", seen)
	}
}
