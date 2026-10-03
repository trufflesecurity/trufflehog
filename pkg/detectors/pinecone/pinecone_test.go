package pinecone

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	// 6-char label, 63-char secret (75 chars total)
	validKeyLong = "pcsk_T5Afk6_5qU9s3iLVFmaSaJtMat7gTHaT9fXa7ykiBk7iz4uUMuLGLemkdutTgwJevYhqtn"
	// 5-char label, 63-char secret (74 chars total)
	validKeyShort  = "pcsk_wtQV4_J9qqVGjiMW81LJ9H59iajZMWMedenyLnGVR3vbCWq6V3oaEvcQYwPFQpupFUth1"
	invalidKeyNoID = "pcsk__5qU9s3iLVFmaSaJtMat7gTHaT9fXa7ykiBk7iz4uUMuLGLemkdutTgwJevYhqtn"
	invalidPrefix  = "pineconeT5Afk6_5qU9s3iLVFmaSaJtMat7gTHaT9fXa7ykiBk7iz4uUMuLGLemkdutTgwJevYhqtn"
	keyword        = "pinecone"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestPinecone_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - env var assignment",
			input: keyword + "_API_KEY=" + validKeyLong,
			want:  []string{validKeyLong},
		},
		{
			name:  "valid pattern - short label",
			input: "export PINECONE_API_KEY=" + validKeyShort,
			want:  []string{validKeyShort},
		},
		{
			name: "valid pattern - config file",
			input: `
				pinecone:
				  api_key: "` + validKeyLong + `"
				  environment: us-east-1-aws
			`,
			want: []string{validKeyLong},
		},
		{
			name:  "valid pattern - multiple distinct keys",
			input: "primary=" + validKeyLong + " secondary=" + validKeyShort,
			want:  []string{validKeyLong, validKeyShort},
		},
		{
			name:  "invalid pattern - missing key_id",
			input: invalidKeyNoID,
			want:  []string{},
		},
		{
			name:  "invalid pattern - wrong prefix",
			input: invalidPrefix,
			want:  []string{},
		},
		{
			name:  "invalid pattern - secret too short",
			input: "pcsk_abcd1_tooShort",
			want:  []string{},
		},
		{
			name:  "invalid pattern - label too short (4 chars)",
			input: "pcsk_abcd_5qU9s3iLVFmaSaJtMat7gTHaT9fXa7ykiBk7iz4uUMuLGLemkdutTgwJevYhqtn",
			want:  []string{},
		},
		{
			name:  "invalid pattern - secret has trailing alphanumeric",
			input: validKeyLong + "EXTRA",
			want:  []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 && len(test.want) > 0 {
				t.Errorf("keywords '%v' not matched by: %s", d.Keywords(), test.input)
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			if err != nil {
				t.Errorf("error = %v", err)
				return
			}

			if len(results) != len(test.want) {
				t.Errorf("expected %d results, got %d", len(test.want), len(results))
				for _, r := range results {
					t.Logf("got: %s", string(r.Raw))
				}
				return
			}

			actual := make(map[string]struct{}, len(results))
			for _, r := range results {
				actual[string(r.Raw)] = struct{}{}
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

func TestPinecone_ExtractProjectID(t *testing.T) {
	tests := []struct {
		name string
		host string
		want string
	}{
		{
			name: "serverless host",
			host: "my-index-abc1234.svc.us-east1-aws.pinecone.io",
			want: "abc1234",
		},
		{
			name: "hyphenated index name",
			host: "my-cool-index-xyz9876.svc.us-west-2.pinecone.io",
			want: "xyz9876",
		},
		{
			name: "missing .svc. segment",
			host: "my-index.pinecone.io",
			want: "",
		},
		{
			name: "missing hyphen before .svc.",
			host: "abc.svc.us-east1.pinecone.io",
			want: "",
		},
		{
			name: "empty host",
			host: "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractProjectID(tt.host)
			if got != tt.want {
				t.Errorf("extractProjectID(%q) = %q, want %q", tt.host, got, tt.want)
			}
		})
	}
}

func TestPinecone_VerifyMatchSuccess(t *testing.T) {
	scanner := Scanner{client: &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.Method != http.MethodGet {
				t.Fatalf("expected GET request, got %s", req.Method)
			}
			if req.URL.String() != "https://api.pinecone.io/indexes" {
				t.Fatalf("unexpected URL %s", req.URL.String())
			}
			if got := req.Header.Get("Api-Key"); got != validKeyLong {
				t.Fatalf("unexpected api key header %q", got)
			}
			if got := req.Header.Get("X-Pinecone-Api-Version"); got != "2025-10" {
				t.Fatalf("unexpected api version header %q", got)
			}

			body := `{"indexes":[{"name":"example-index","host":"example-index-abc1234.svc.us-east1-aws.pinecone.io","spec":{"serverless":{"cloud":"aws","region":"us-east-1"}}}]}`
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(body)),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		}),
	}}

	verified, extraData, err := scanner.verifyMatch(context.Background(), scanner.client, validKeyLong)
	if err != nil {
		t.Fatalf("verifyMatch returned error: %v", err)
	}
	if !verified {
		t.Fatal("expected token to verify successfully")
	}
	if extraData["total_indexes"] != "1" {
		t.Fatalf("expected total_indexes=1, got %q", extraData["total_indexes"])
	}
	if extraData["project_id"] != "abc1234" {
		t.Fatalf("expected project_id=abc1234, got %q", extraData["project_id"])
	}
	if extraData["index_0_name"] != "example-index" {
		t.Fatalf("expected index_0_name to be populated, got %q", extraData["index_0_name"])
	}
}

func TestPinecone_VerifyMatchRejectsMissingIndexesKey(t *testing.T) {
	scanner := Scanner{client: &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"projects":[]}`)),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		}),
	}}

	verified, extraData, err := scanner.verifyMatch(context.Background(), scanner.client, validKeyLong)
	if err == nil {
		t.Fatal("expected an error for malformed 200 response")
	}
	if !strings.Contains(err.Error(), "unexpected response body structure") {
		t.Fatalf("unexpected error: %v", err)
	}
	if verified {
		t.Fatal("expected malformed 200 response to remain unverified")
	}
	if extraData != nil {
		t.Fatalf("expected no extra data, got %#v", extraData)
	}
}

func TestPinecone_VerifyMatchRejectsInvalidIndexesPayload(t *testing.T) {
	scanner := Scanner{client: &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"indexes":{}}`)),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		}),
	}}

	verified, extraData, err := scanner.verifyMatch(context.Background(), scanner.client, validKeyLong)
	if err == nil {
		t.Fatal("expected a decode error for invalid indexes payload")
	}
	if !strings.Contains(err.Error(), "failed to decode 200 response") {
		t.Fatalf("unexpected error: %v", err)
	}
	if verified {
		t.Fatal("expected invalid indexes payload to remain unverified")
	}
	if extraData != nil {
		t.Fatalf("expected no extra data, got %#v", extraData)
	}
}

func TestPinecone_FromDataPreservesMetadataOnVerificationError(t *testing.T) {
	scanner := Scanner{
		client: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"indexes":{}}`)),
					Header:     make(http.Header),
					Request:    req,
				}, nil
			}),
		},
	}

	results, err := scanner.FromData(context.Background(), true, []byte(validKeyLong))
	if err != nil {
		t.Fatalf("FromData returned error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected one result, got %d", len(results))
	}
	if results[0].Verified {
		t.Fatal("expected malformed verification response to keep result unverified")
	}
	if results[0].VerificationError() == nil {
		t.Fatal("expected malformed verification response to set a verification error")
	}
	if got := results[0].ExtraData["key_id"]; got != "T5Afk6" {
		t.Fatalf("expected key_id=T5Afk6, got %q", got)
	}
	if got := results[0].SecretParts["key"]; got != validKeyLong {
		t.Fatalf("expected secret key part to be preserved, got %q", got)
	}
}
