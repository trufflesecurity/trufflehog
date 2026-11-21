package dynatrace

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

const (
	sampleToken = "dt0s01.ST2EY72KQINMH574WMNVI7YN.G3DFPBEJYMODIDAEX454M7YWBUVEFOWKPRVMWFASS64NFH52PX6BNDVFFM572RZM"
	otherSampleToken  = "dt0s02.UZCK6ENL.2YQ2A3DZUEISRJSUU5544J3SC3TMPXSEEMNA5HK7RW54SJ6XKLYGMWJNKL7B2DNH"
)

const (
	prodHost   = "exampletenant.live.dynatrace.com"
	sprintHost = "anothertenant.sprint.dynatracelabs.com"
)

func TestDynatrace_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "token only",
			input: "DT_API_TOKEN=" + sampleToken,
			want:  []string{sampleToken},
		},
		{
			name:  "token JSON-embedded with quotes",
			input: `{"DTaccesstoken":"` + otherSampleToken + `","create_dashboards":true}`,
			want:  []string{otherSampleToken},
		},
		{
			name:  "token and tenant as query params on one URL",
			input: `"url":"https://` + sprintHost + `/api/v1/events/?Api-Token=` + sampleToken + `&relativeTime=day"`,
			want:  []string{"token:" + sampleToken + " tenant:" + sprintHost},
		},
		{
			name:  "two tokens and two tenants produce all pairings",
			input: "env_a=" + prodHost + " a=" + sampleToken + " b=" + otherSampleToken + " env_b=" + sprintHost,
			want: []string{
				"token:" + sampleToken + " tenant:" + prodHost,
				"token:" + sampleToken + " tenant:" + sprintHost,
				"token:" + otherSampleToken + " tenant:" + prodHost,
				"token:" + otherSampleToken + " tenant:" + sprintHost,
			},
		},
		{
			name:  "two-segment oauth client id is not a token",
			input: `"dt_oauth_client_id":"dt0s02.6QB7K3BS"`,
			want:  nil,
		},
		{
			name:  "truncated secret",
			input: "token=dt0c01.ST2EY72KQINMH574WMNVI7YN.TOOSHORT",
			want:  nil,
		},
		{
			name:  "lowercase in secret segment is invalid",
			input: "token=dt0c01.ST2EY72KQINMH574WMNVI7YN.aBCVTHLNCRIZHUU4JCS62NLFSFOEKNFZXXXXSUVJAMJDNUUXL4W6N3RP",
			want:  nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if matched := ahoCorasickCore.FindDetectorMatches([]byte(test.input)); len(matched) == 0 {
				t.Fatalf("expected keywords %v to be found in the input", d.Keywords())
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			require.NoError(t, err)

			if len(results) != len(test.want) {
				t.Fatalf("mismatch in result count: expected %d, got %d", len(test.want), len(results))
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

func TestDynatrace_HostNormalization(t *testing.T) {
	tests := map[string]string{
		"exampleprod.live.dynatrace.com":           "exampleprod.live.dynatrace.com",
		"exampleprod.apps.dynatrace.com":           "exampleprod.live.dynatrace.com",
		"exampledev.dev.dynatracelabs.com":         "exampledev.dev.dynatracelabs.com",
		"exampledev.dev.apps.dynatracelabs.com":    "exampledev.dev.dynatracelabs.com",
		"examplespr.sprint.dynatracelabs.com":      "examplespr.sprint.dynatracelabs.com",
		"examplespr.sprint.apps.dynatracelabs.com": "examplespr.sprint.dynatracelabs.com",
	}
	for in, want := range tests {
		if got := tenantToAPIHost(in); got != want {
			t.Errorf("tenantToAPIHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDynatrace_Redact(t *testing.T) {
	secret := "G3DFPBEJYMODIDAEX454M7YWBUVEFOWKPRVMWFASS64NFH52PX6BNDVFFM572RZM"

	redacted := redact(sampleToken)
	require.Equal(t, "dt0s01.ST2EY72KQINMH574WMNVI7YN.********", redacted)
	require.NotContains(t, redacted, secret, "redacted form must not leak the secret segment")

	require.Equal(t, "dt0s02.6QB7K3BS", redact("dt0s02.6QB7K3BS"))
}

func TestDynatrace_Verification(t *testing.T) {
	input := "tenant=" + prodHost + " token=" + sampleToken

	tests := []struct {
		name         string
		client       *http.Client
		wantVerified bool
		wantErr      bool
	}{
		{name: "200 verified", client: common.ConstantResponseHttpClient(http.StatusOK, `{"id":"dt0s01.ST2EY72KQINMH574WMNVI7YN","enabled":true}`), wantVerified: true},
		{name: "403 valid but missing scope", client: common.ConstantResponseHttpClient(http.StatusForbidden, `{"error":{"code":403}}`), wantVerified: true},
		{name: "401 invalid", client: common.ConstantResponseHttpClient(http.StatusUnauthorized, `{"error":{"code":401}}`), wantVerified: false},
		{name: "unexpected status is a verification error", client: common.ConstantResponseHttpClient(http.StatusInternalServerError, ``), wantVerified: false, wantErr: true},
		{name: "unreachable endpoint is a verification error", client: errorClient(errors.New("simulated endpoint unreachable")), wantVerified: false, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := Scanner{client: tt.client}.FromData(context.Background(), true, []byte(input))
			require.NoError(t, err)
			require.Len(t, results, 1)
			require.Equal(t, tt.wantVerified, results[0].Verified)
			require.Equal(t, tt.wantErr, results[0].VerificationError() != nil)
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func errorClient(err error) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, err
	})}
}
