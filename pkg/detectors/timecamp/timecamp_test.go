package timecamp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern   = "66mtci6qdo8ccczw48j5lpt2uw"
	invalidPattern = "66mt?i6qdo8ccczw48j5lpt2uw"
	keyword        = "timecamp"
)

func TestTimeCamp_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword timecamp",
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

func TestTimeCamp_Verification(t *testing.T) {
	tests := []struct {
		name         string
		client       *http.Client
		wantVerified bool
		wantErr      string
	}{
		{
			name:         "verified",
			client:       common.ConstantResponseHttpClient(http.StatusOK, "{}"),
			wantVerified: true,
		},
		{
			name:   "unauthorized is unverified",
			client: common.ConstantResponseHttpClient(http.StatusUnauthorized, "{}"),
		},
		{
			name:   "forbidden is unverified",
			client: common.ConstantResponseHttpClient(http.StatusForbidden, "{}"),
		},
		{
			name:    "unexpected status is verification error",
			client:  common.ConstantResponseHttpClient(http.StatusInternalServerError, "{}"),
			wantErr: "unexpected HTTP response status 500",
		},
		{
			name: "request failure is verification error",
			client: &http.Client{
				Transport: common.FakeTransport{
					CreateResponse: func(*http.Request) (*http.Response, error) {
						return nil, errors.New("network down")
					},
				},
			},
			wantErr: "Get \"https://app.timecamp.com/third_party/api/user?format=json\": network down",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotVerified, gotErr := verifyTimeCamp(context.Background(), test.client, validPattern)
			if gotVerified != test.wantVerified {
				t.Fatalf("verified = %v, want %v", gotVerified, test.wantVerified)
			}

			if gotErr == nil && test.wantErr != "" {
				t.Fatalf("expected verification error %q", test.wantErr)
			}
			if gotErr != nil && test.wantErr == "" {
				t.Fatalf("unexpected verification error: %v", gotErr)
			}
			if gotErr != nil && gotErr.Error() != test.wantErr {
				t.Fatalf("verification error = %q, want %q", gotErr.Error(), test.wantErr)
			}
		})
	}
}

func TestTimeCamp_FromDataSetsVerificationError(t *testing.T) {
	d := Scanner{client: common.ConstantResponseHttpClient(http.StatusInternalServerError, "{}")}

	results, err := d.FromData(context.Background(), true, []byte(fmt.Sprintf("%s token = '%s'", keyword, validPattern)))
	if err != nil {
		t.Fatalf("FromData() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("results length = %d, want 1", len(results))
	}
	if results[0].Verified {
		t.Fatal("expected result to be unverified")
	}
	if results[0].VerificationError() == nil {
		t.Fatal("expected verification error")
	}
	if got, want := results[0].VerificationError().Error(), "unexpected HTTP response status 500"; got != want {
		t.Fatalf("verification error = %q, want %q", got, want)
	}
}
