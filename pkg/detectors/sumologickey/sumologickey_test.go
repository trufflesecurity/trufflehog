package sumologickey

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestSumoLogicKey_Pattern(t *testing.T) {
	d := Scanner{}
	d.UseFoundEndpoints(true)
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "typical pattern",
			input: `sumologic:
  accessId: suDkVYKjXZAwsz
  accessKey: Khk3i2ugMxMgkb8bIA2auj4I8juZ3HiimDNssjzYdGqfizPZcxHK70a0LckgRSCL
  clusterName: Kubernetes_cluster-2024-10-25T21:34:23.096Z`,
			want: []string{`{"accessId":"suDkVYKjXZAwsz","accessKey":"Khk3i2ugMxMgkb8bIA2auj4I8juZ3HiimDNssjzYdGqfizPZcxHK70a0LckgRSCL"}`},
		},
		{
			name: "pattern with url",
			input: `sumologic:
  baseUrl: api.us2.sumologic.com
  accessId: suDkVYKjXZAwsz
  accessKey: Khk3i2ugMxMgkb8bIA2auj4I8juZ3HiimDNssjzYdGqfizPZcxHK70a0LckgRSCL
  clusterName: Kubernetes_cluster-2024-10-25T21:34:23.096Z`,
			want: []string{`{"accessId":"suDkVYKjXZAwsz","accessKey":"Khk3i2ugMxMgkb8bIA2auj4I8juZ3HiimDNssjzYdGqfizPZcxHK70a0LckgRSCL","url":"api.us2.sumologic.com"}`},
		},
		{
			name: "finds all matches",
			input: `sumoId1 = 'suaRYt6iLL8cxl'
sumoKey1 = 'CzrMhR8zzy1eH1F0XlY1tu5ywqa2yaSFoWGg2cqE43XkfnUVCytnPQfv1enUYrzv'
sumoId2 = 'suDkVYKjXZBwsz'
sumoKey2 = 'Khk3i2ugMxMgkb8bIA2auj4I8juZ3HiimDNssjzYdGqfizPZcxHK21a0LckgRSCL'`,
			want: []string{"CzrMhR8zzy1eH1F0XlY1tu5ywqa2yaSFoWGg2cqE43XkfnUVCytnPQfv1enUYrzv", "Khk3i2ugMxMgkb8bIA2auj4I8juZ3HiimDNssjzYdGqfizPZcxHK21a0LckgRSCL"},
		},
		{
			name:  "invalid pattern",
			input: "sumoId = 'doDkVYKjXZAwsz'",
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

// TestSumoLogicKey_Pattern_CloudAndFoundEnabled mirrors production wiring
// (defaults.go enables both cloud and found endpoints together). A single
// found regional host must still be reported confidently even though
// Endpoints() also includes the always-present cloud default alongside it.
// TestVerifyMatch_NormalizesEndpointScheme guards against double-prefixing
// endpoints that already carry a scheme. --verifier-endpoint values are
// required to be full https:// URLs (repo-wide convention), while cloud and
// found endpoints are bare hosts; verifyMatch must handle both without
// producing "https://https://...".
func TestVerifyMatch_NormalizesEndpointScheme(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		wantURL  string
	}{
		{"bare host (cloud/found)", "api.sumologic.com", "https://api.sumologic.com/api/v1/users"},
		{"configured full URL", "https://custom.sumologic.example.com", "https://custom.sumologic.example.com/api/v1/users"},
		{"configured URL with trailing slash", "https://custom.sumologic.example.com/", "https://custom.sumologic.example.com/api/v1/users"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedURL string
			client := &http.Client{
				Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					capturedURL = req.URL.String()
					return &http.Response{StatusCode: http.StatusUnauthorized, Body: io.NopCloser(strings.NewReader(""))}, nil
				}),
			}

			_, err := verifyMatch(context.Background(), client, tt.endpoint, "id", "key")
			assert.NoError(t, err)
			assert.Equal(t, tt.wantURL, capturedURL)
			assert.NotContains(t, capturedURL, "https://https://")
		})
	}
}

func TestSumoLogicKey_Pattern_CloudAndFoundEnabled(t *testing.T) {
	d := Scanner{}
	d.UseFoundEndpoints(true)
	d.UseCloudEndpoint(true)
	d.SetCloudEndpoints(d.CloudEndpoints()...)

	input := `sumologic:
  baseUrl: api.us2.sumologic.com
  accessId: suDkVYKjXZAwsz
  accessKey: Khk3i2ugMxMgkb8bIA2auj4I8juZ3HiimDNssjzYdGqfizPZcxHK70a0LckgRSCL
  clusterName: Kubernetes_cluster-2024-10-25T21:34:23.096Z`

	results, err := d.FromData(context.Background(), false, []byte(input))
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	want := `{"accessId":"suDkVYKjXZAwsz","accessKey":"Khk3i2ugMxMgkb8bIA2auj4I8juZ3HiimDNssjzYdGqfizPZcxHK70a0LckgRSCL","url":"api.us2.sumologic.com"}`
	if got := string(results[0].RawV2); got != want {
		t.Errorf("RawV2 = %q, want %q", got, want)
	}
}

// TestSumoLogicKey_Pattern_ConfiguredMatchesFound covers the case where the
// same host arrives via two sources: --verifier-endpoint (configured) and
// text extraction (found). Endpoints() must dedupe these to one entry, or
// confidentEndpoint sees two occurrences of the same host and wrongly treats
// it as ambiguous, dropping the url from RawV2 even though there's exactly
// one distinct region.
func TestSumoLogicKey_Pattern_ConfiguredMatchesFound(t *testing.T) {
	d := Scanner{}
	assert.NoError(t, d.SetConfiguredEndpoints("api.us2.sumologic.com"))
	d.UseFoundEndpoints(true)

	input := `sumologic:
  baseUrl: api.us2.sumologic.com
  accessId: suDkVYKjXZAwsz
  accessKey: Khk3i2ugMxMgkb8bIA2auj4I8juZ3HiimDNssjzYdGqfizPZcxHK70a0LckgRSCL`

	results, err := d.FromData(context.Background(), false, []byte(input))
	assert.NoError(t, err)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	want := `{"accessId":"suDkVYKjXZAwsz","accessKey":"Khk3i2ugMxMgkb8bIA2auj4I8juZ3HiimDNssjzYdGqfizPZcxHK70a0LckgRSCL","url":"api.us2.sumologic.com"}`
	assert.Equal(t, want, string(results[0].RawV2))
}
