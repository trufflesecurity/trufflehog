package bitbucketdatacenter

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/h2non/gock.v1"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

func TestBitbucketDataCenter_Pattern(t *testing.T) {
	d := Scanner{}
	d.UseCloudEndpoint(true)
	d.UseFoundEndpoints(true)

	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "invalid - pat only no url",
			input: `
				BBDC-MTM5NDkzNDI3MTgzOrTObCIIEXN0tpQYAc4bhG+RUqwz
			`,
			want: nil,
		},
		{
			name: "invalid - pat and unrelated url",
			input: `
				BBDC-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
				https://example.com/api
			`,
			want: nil,
		},
		{
			name: "valid - single pat single url",
			input: `
				atlassian bitbucket running at https://git.company.com:7990/projects/PROJ/repos/app
				BBDC-MTk4MDE0MzAyMDIzOvvP+lDf5edYvDgggvyzpmiXkF0A
			`,
			want: []string{
				"BBDC-MTk4MDE0MzAyMDIzOvvP+lDf5edYvDgggvyzpmiXkF0A:https://git.company.com:7990",
			},
		},
		{
			name: "valid - multiple pats single url",
			input: `
				bitbucket server at https://git.company.com:7990/scm/proj/repo.git

				BBDC-1111111111111111111111111111111111111111
				BBDC-2222222222222222222222222222222222222222
			`,
			want: []string{
				"BBDC-1111111111111111111111111111111111111111:https://git.company.com:7990",
				"BBDC-2222222222222222222222222222222222222222:https://git.company.com:7990",
			},
		},
		{
			name: "valid - single pat multiple urls",
			input: `
				atlassian bitbucket instance:
				BBDC-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
				bitbucket = https://git.company.com:7990/scm/proj/repo.git
				bitbucket = https://git.company2.com:7990/scm/proj/repo.git
			`,
			want: []string{
				"BBDC-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:https://git.company.com:7990",
				"BBDC-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:https://git.company2.com:7990",
			},
		},
		{
			name: "invalid - short pat",
			input: `
				BBDC-1234
				https://git.company.com:7990
			`,
			want: nil,
		},
		{
			name: "invalid - uppercase pat",
			input: `
				BBDC-MTM5NDKZNDI3MTgzORTOBCCIIEXN0TPQYAC4BHG
				https://git.company.com:7990
			`,
			want: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
				t.Errorf(
					"test %q failed: expected keywords %v to be found",
					test.name,
					d.Keywords(),
				)
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			require.NoError(t, err)

			actual := make(map[string]struct{})
			for _, r := range results {
				actual[string(r.RawV2)] = struct{}{}
			}

			expected := make(map[string]struct{})
			for _, v := range test.want {
				expected[v] = struct{}{}
			}

			if diff := cmp.Diff(expected, actual); diff != "" {
				t.Errorf("%s diff (-want +got):\n%s", test.name, diff)
			}
		})
	}
}

func TestBitbucketDataCenterPAT_FromData(t *testing.T) {
	client := common.SaneHttpClient()

	d := Scanner{client: client}
	testEndpoint := "https://git.company.com"
	testToken := "BBDC-OTE2MTAxMzgwNTgxOs8VegSPPzv+A9lGK3bbnwOFCkhj"
	_ = d.SetConfiguredEndpoints(testEndpoint)
	d.UseFoundEndpoints(false)

	defer gock.Off()
	defer gock.RestoreClient(client)
	gock.InterceptClient(client)

	tests := []struct {
		name                string
		setup               func()
		data                string
		verify              bool
		wantResults         int
		wantVerified        bool
		wantVerificationErr bool
	}{
		{
			name: "found, verified with confiured endpoint",
			setup: func() {
				gock.New(testEndpoint).
					Get("/rest/api/1.0/projects").
					MatchHeader("Authorization", fmt.Sprintf("Bearer %s", testToken)).
					Reply(http.StatusOK).
					JSON(map[string]any{
						"size":       0,
						"limit":      1,
						"isLastPage": true,
						"values":     "",
						"start":      0,
					})
			},
			data:         fmt.Sprintf("bitbucket token: %s", testToken),
			verify:       true,
			wantResults:  1,
			wantVerified: true,
		},
		{
			name: "found, unverified (401)",
			setup: func() {
				gock.New(testEndpoint).
					Get("/rest/api/1.0/projects").
					MatchHeader("Authorization", fmt.Sprintf("Bearer %s", testToken)).
					Reply(http.StatusUnauthorized)
			},
			data:         fmt.Sprintf("bitbucket token: %s", testToken),
			verify:       true,
			wantResults:  1,
			wantVerified: false,
		},
		{
			name:        "not found",
			setup:       func() {},
			data:        "bitbucket config: nothing here",
			verify:      true,
			wantResults: 0,
		},
		{
			name: "found, verification error on unexpected status",
			setup: func() {
				gock.New(testEndpoint).
					Get("/rest/api/1.0/projects").
					MatchHeader("Authorization", fmt.Sprintf("Bearer %s", testToken)).
					Reply(http.StatusInternalServerError)
			},
			data:                fmt.Sprintf("bitbucket token: %s", testToken),
			verify:              true,
			wantResults:         1,
			wantVerified:        false,
			wantVerificationErr: true,
		},
		{
			name: "found, verification error on timeout",
			setup: func() {
				gock.New(testEndpoint).
					Get("/rest/api/1.0/projects").
					MatchHeader("Authorization", fmt.Sprintf("Bearer %s", testToken)).
					Reply(http.StatusOK).
					Delay(2 * time.Second)
			},
			data:                fmt.Sprintf("bitbucket token: %s", testToken),
			verify:              true,
			wantResults:         1,
			wantVerified:        false,
			wantVerificationErr: true,
		},
		{
			name:         "found, no verify",
			setup:        func() {},
			data:         fmt.Sprintf("bitbucket token: %s", testToken),
			verify:       false,
			wantResults:  1,
			wantVerified: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gock.Flush()
			tt.setup()

			ctx := context.Background()
			if tt.wantVerificationErr {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 100*time.Millisecond)
				defer cancel()
			}

			results, err := d.FromData(ctx, tt.verify, []byte(tt.data))
			require.NoError(t, err)
			require.Len(t, results, tt.wantResults)

			for _, result := range results {
				assert.Equal(t, detector_typepb.DetectorType_BitbucketDataCenter, result.DetectorType)
				assert.NotEmpty(t, result.Raw)
				assert.Equal(t, tt.wantVerified, result.Verified)
				assert.Equal(t, tt.wantVerificationErr, result.VerificationError() != nil)
			}
		})
	}
}

func TestBitbucketDataCenterPAT_FromData_WithoutConfiguredEndpoint(t *testing.T) {
	client := common.SaneHttpClient()

	d := Scanner{client: client}
	testEndpoint := "https://git.company.com"
	testToken := "BBDC-OTE2MTAxMzgwNTgxOs8VegSPPzv+A9lGK3bbnwOFCkhj"
	d.UseFoundEndpoints(true)

	defer gock.Off()
	defer gock.RestoreClient(client)
	gock.InterceptClient(client)

	tests := []struct {
		name                string
		setup               func()
		data                string
		verify              bool
		wantResults         int
		wantVerified        bool
		wantVerificationErr bool
	}{
		{
			name: "found, verified with confiured endpoint",
			setup: func() {
				gock.New(testEndpoint).
					Get("/rest/api/1.0/projects").
					MatchHeader("Authorization", fmt.Sprintf("Bearer %s", testToken)).
					Reply(http.StatusOK).
					JSON(map[string]any{
						"size":       0,
						"limit":      1,
						"isLastPage": true,
						"values":     "",
						"start":      0,
					})
			},
			data:         fmt.Sprintf("bitbucket url %s token: %s", testEndpoint, testToken),
			verify:       true,
			wantResults:  1,
			wantVerified: true,
		},
		{
			name: "found, unverified (401)",
			setup: func() {
				gock.New(testEndpoint).
					Get("/rest/api/1.0/projects").
					MatchHeader("Authorization", fmt.Sprintf("Bearer %s", testToken)).
					Reply(http.StatusUnauthorized)
			},
			data:         fmt.Sprintf("bitbucket url %s token: %s", testEndpoint, testToken),
			verify:       true,
			wantResults:  1,
			wantVerified: false,
		},
		{
			name:        "not found",
			setup:       func() {},
			data:        "bitbucket config: nothing here",
			verify:      true,
			wantResults: 0,
		},
		{
			name: "found, verification error on unexpected status",
			setup: func() {
				gock.New(testEndpoint).
					Get("/rest/api/1.0/projects").
					MatchHeader("Authorization", fmt.Sprintf("Bearer %s", testToken)).
					Reply(http.StatusInternalServerError)
			},
			data:                fmt.Sprintf("bitbucket url %s token: %s", testEndpoint, testToken),
			verify:              true,
			wantResults:         1,
			wantVerified:        false,
			wantVerificationErr: true,
		},
		{
			name: "found, verification error on timeout",
			setup: func() {
				gock.New(testEndpoint).
					Get("/rest/api/1.0/projects").
					MatchHeader("Authorization", fmt.Sprintf("Bearer %s", testToken)).
					Reply(http.StatusOK).
					Delay(2 * time.Second)
			},
			data:                fmt.Sprintf("bitbucket url %s token: %s", testEndpoint, testToken),
			verify:              true,
			wantResults:         1,
			wantVerified:        false,
			wantVerificationErr: true,
		},
		{
			name:         "found, no verify",
			setup:        func() {},
			data:         fmt.Sprintf("bitbucket url %s token: %s", testEndpoint, testToken),
			verify:       false,
			wantResults:  1,
			wantVerified: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gock.Flush()
			tt.setup()

			ctx := context.Background()
			if tt.wantVerificationErr {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 100*time.Millisecond)
				defer cancel()
			}

			results, err := d.FromData(ctx, tt.verify, []byte(tt.data))
			require.NoError(t, err)
			require.Len(t, results, tt.wantResults)

			for _, result := range results {
				assert.Equal(t, detector_typepb.DetectorType_BitbucketDataCenter, result.DetectorType)
				assert.NotEmpty(t, result.Raw)
				assert.Equal(t, tt.wantVerified, result.Verified)
				assert.Equal(t, tt.wantVerificationErr, result.VerificationError() != nil)
			}
		})
	}
}
