package square

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern   = "EAAAYmTgYL4kQ-65xyZ4zANgipYVJQFTrb=roK23I=iFebzL4rjYbUg10N6o1l--"
	invalidPattern = "EAAAYmTgYL4kQ-65xyZ4zANgipYVJQFT?b=roK23I=iFebzL4rjYbUg10N6o1l--"
	keyword        = "square"
)

func TestSquare_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword square",
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

func TestSquare_Verification(t *testing.T) {
	input := fmt.Sprintf("%s token = '%s'", keyword, validPattern)

	tests := []struct {
		name         string
		status       int
		body         string
		wantVerified bool
		wantErr      bool
		wantErrParts []string
	}{
		{
			name:         "200 is verified",
			status:       http.StatusOK,
			body:         `{"merchant":[]}`,
			wantVerified: true,
		},
		{
			name:   "401 is unverified",
			status: http.StatusUnauthorized,
			body:   `{"errors":[{"category":"AUTHENTICATION_ERROR","code":"UNAUTHORIZED","detail":"This request could not be authorized."}]}`,
		},
		{
			name:         "403 with INSUFFICIENT_SCOPES is verified",
			status:       http.StatusForbidden,
			body:         `{"errors":[{"category":"AUTHENTICATION_ERROR","code":"INSUFFICIENT_SCOPES","detail":"The merchant has not given your application sufficient permissions."}]}`,
			wantVerified: true,
		},
		{
			name:         "403 with HTML body is indeterminate",
			status:       http.StatusForbidden,
			body:         "<html>\n  <body>Blocked by corporate proxy</body>\n</html>",
			wantErr:      true,
			wantErrParts: []string{"403", "<html> <body>Blocked by corporate proxy</body> </html>"},
		},
		{
			name:         "403 with other Square code is indeterminate",
			status:       http.StatusForbidden,
			body:         `{"errors":[{"category":"AUTHENTICATION_ERROR","code":"FORBIDDEN","detail":"Forbidden"}]}`,
			wantErr:      true,
			wantErrParts: []string{"403", "FORBIDDEN"},
		},
		{
			name:         "403 with empty body is indeterminate",
			status:       http.StatusForbidden,
			wantErr:      true,
			wantErrParts: []string{"403", "<empty body>"},
		},
		{
			name:         "429 is indeterminate",
			status:       http.StatusTooManyRequests,
			body:         `{"errors":[{"category":"RATE_LIMIT_ERROR","code":"RATE_LIMITED"}]}`,
			wantErr:      true,
			wantErrParts: []string{"429", "RATE_LIMITED"},
		},
		{
			name:         "500 with large body is truncated",
			status:       http.StatusInternalServerError,
			body:         strings.Repeat("x", 10000),
			wantErr:      true,
			wantErrParts: []string{"500", strings.Repeat("x", maxErrorBodySize) + "..."},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := Scanner{client: common.ConstantResponseHttpClient(test.status, test.body)}

			results, err := s.FromData(context.Background(), true, []byte(input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(results) != 1 {
				t.Fatalf("expected 1 result, got %d", len(results))
			}

			r := results[0]
			if r.Verified != test.wantVerified {
				t.Errorf("Verified = %v, want %v", r.Verified, test.wantVerified)
			}

			verificationErr := r.VerificationError()
			if (verificationErr != nil) != test.wantErr {
				t.Fatalf("VerificationError = %v, wantErr %v", verificationErr, test.wantErr)
			}
			if verificationErr == nil {
				return
			}

			msg := verificationErr.Error()
			for _, part := range test.wantErrParts {
				if !strings.Contains(msg, part) {
					t.Errorf("VerificationError %q does not contain %q", msg, part)
				}
			}
			if strings.Contains(msg, validPattern) {
				t.Errorf("VerificationError leaks the token: %q", msg)
			}
			if len(msg) > maxErrorBodySize+64 {
				t.Errorf("VerificationError not truncated: %d bytes", len(msg))
			}
		})
	}
}
