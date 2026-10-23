package orcarouter

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

// testKey is a synthetic credential; it is never valid against OrcaRouter.
const testKey = "sk-orca-test0123456789abcdef"

func TestOrcaRouter_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "API key",
			input: `ORCAROUTER_API_KEY="` + testKey + `"`,
			want:  []string{testKey},
		},
		{
			name:  "API key without quotes",
			input: "export ORCAROUTER_API_KEY=" + testKey + "\n",
			want:  []string{testKey},
		},
		{
			name:  "placeholder is not a key",
			input: `ORCAROUTER_API_KEY="sk-orca-your-key-here"`,
			want:  []string{},
		},
		{
			name:  "other vendor key prefix is ignored",
			input: `OPENROUTER_API_KEY="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"`,
			want:  []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			detectorMatches := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(detectorMatches) == 0 && strings.Contains(test.input, keyPrefix) {
				t.Errorf("keywords '%v' not matched by: %s", d.Keywords(), test.input)
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			if err != nil {
				t.Fatalf("error = %v", err)
			}

			if len(results) != len(test.want) {
				t.Fatalf("expected %d results, got %d", len(test.want), len(results))
			}

			for i, result := range results {
				if string(result.Raw) != test.want[i] {
					t.Errorf("raw diff (-want +got):\n%s", cmp.Diff(test.want[i], string(result.Raw)))
				}
			}
		})
	}
}

func TestFromData_DeduplicatesAndRedacts(t *testing.T) {
	d := Scanner{}
	data := fmt.Sprintf(`key one: %[1]s
key one again: %[1]s
key two: %[2]s`, testKey, "sk-orca-ffffffffffffffffffffffffffffffff")

	results, err := d.FromData(context.Background(), false, []byte(data))
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected duplicate keys to collapse to 2 results, got %d", len(results))
	}

	for _, result := range results {
		raw := string(result.Raw)
		if result.Redacted == raw {
			t.Errorf("redacted value exposes the full secret")
		}
		if !strings.Contains(result.Redacted, "...") {
			t.Errorf("expected redacted value to elide the middle, got %q", result.Redacted)
		}
		if strings.Contains(result.Redacted, raw[12:len(raw)-4]) {
			t.Errorf("redacted value exposes the middle of the secret")
		}
		if result.DetectorType != detector_typepb.DetectorType_OrcaRouter {
			t.Errorf("unexpected detector type %v", result.DetectorType)
		}
		if _, ok := result.SecretParts["key"]; !ok {
			t.Errorf("expected secret parts to carry the key")
		}
	}
}

func TestScanner_TypeVersionDescription(t *testing.T) {
	d := Scanner{}
	if d.Type() != detector_typepb.DetectorType_OrcaRouter {
		t.Errorf("unexpected type %v", d.Type())
	}
	if d.Version() != 1 {
		t.Errorf("unexpected version %d", d.Version())
	}
	if !strings.Contains(strings.ToLower(d.Description()), "orcarouter") {
		t.Errorf("description should name OrcaRouter")
	}
	if diff := cmp.Diff([]string{"sk-orca-"}, d.Keywords()); diff != "" {
		t.Errorf("keywords diff (-want +got):\n%s", diff)
	}
}

func TestDetectorTypeEnumeration(t *testing.T) {
	// The detector type is part of the public result schema, so pin both the
	// registered name and the enum number that the proto declares.
	if got := detector_typepb.DetectorType_OrcaRouter.String(); got != "OrcaRouter" {
		t.Errorf("detector type name = %q, want OrcaRouter", got)
	}
	if got := int32(detector_typepb.DetectorType_OrcaRouter); got != 1075 {
		t.Errorf("detector type number = %d, want 1075", got)
	}
	if got := detector_typepb.DetectorType_name[1075]; got != "OrcaRouter" {
		t.Errorf("detector type registry name = %q, want OrcaRouter", got)
	}
}

func catalogServer(t *testing.T, status int, body string) (*httptest.Server, *Scanner) {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != modelsPath {
			t.Errorf("unexpected verification path %q, want %q", r.URL.Path, modelsPath)
		}
		if r.Method != http.MethodGet {
			t.Errorf("unexpected verification method %q, want GET", r.Method)
		}
		if auth := r.Header.Get("Authorization"); !strings.HasPrefix(auth, "Bearer sk-orca-") {
			t.Errorf("expected bearer credential on the catalog request")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)

	return server, &Scanner{client: server.Client(), apiBase: server.URL}
}

func TestScanner_VerifySuccess(t *testing.T) {
	_, scanner := catalogServer(t, http.StatusOK, catalogFixture)

	results, err := scanner.FromData(context.Background(), true, []byte("key="+testKey))
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	result := results[0]
	if !result.Verified {
		t.Fatalf("expected the key to be verified, extra data: %v", result.ExtraData)
	}
	want := map[string]string{
		"model_count":            "9",
		"chat_model_count":       "4",
		"vision_model_count":     "2",
		"embedding_model_count":  "1",
		"image_generation_count": "1",
		"video_generation_count": "1",
		"rerank_model_count":     "1",
	}
	if diff := cmp.Diff(want, result.ExtraData); diff != "" {
		t.Errorf("extra data diff (-want +got):\n%s", diff)
	}
	for _, value := range result.ExtraData {
		if strings.Contains(value, testKey) {
			t.Errorf("extra data must never contain the credential")
		}
	}
}

func TestScanner_VerifyStatusHandling(t *testing.T) {
	tests := []struct {
		name         string
		status       int
		body         string
		wantVerified bool
		wantErr      string
	}{
		{
			name:         "valid key",
			status:       http.StatusOK,
			body:         catalogFixture,
			wantVerified: true,
		},
		{
			name:   "revoked key is unverified",
			status: http.StatusUnauthorized,
			body:   `{"error":{"message":"invalid api key"}}`,
		},
		{
			name:   "disabled key is unverified",
			status: http.StatusForbidden,
			body:   `{"error":{"message":"forbidden"}}`,
		},
		{
			name:    "rate limited is a verification error",
			status:  http.StatusTooManyRequests,
			wantErr: "rate limited",
		},
		{
			name:    "server error is a verification error",
			status:  http.StatusInternalServerError,
			wantErr: "unexpected HTTP response status 500",
		},
		{
			name:    "malformed catalog is a verification error",
			status:  http.StatusOK,
			body:    `{"data": "not-a-list"}`,
			wantErr: "decoding orcarouter model catalog",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, scanner := catalogServer(t, test.status, test.body)

			verified, extraData, err := scanner.verifyToken(context.Background(), testKey)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("expected error containing %q, got %v", test.wantErr, err)
				}
				if verified {
					t.Errorf("failed verification must not report the key as verified")
				}
				if strings.Contains(err.Error(), testKey) {
					t.Errorf("verification error leaks the credential")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if verified != test.wantVerified {
				t.Fatalf("verified = %v, want %v", verified, test.wantVerified)
			}
			if !test.wantVerified && len(extraData) != 0 {
				t.Errorf("unverified keys must not report extra data, got %v", extraData)
			}
		})
	}
}

func TestScanner_VerifyNetworkFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	scanner := &Scanner{client: server.Client(), apiBase: server.URL}
	server.Close()

	verified, extraData, err := scanner.verifyToken(context.Background(), testKey)
	if err == nil {
		t.Fatalf("expected a transport error")
	}
	if verified || len(extraData) != 0 {
		t.Errorf("transport failures must not produce a verified result")
	}
	if strings.Contains(err.Error(), testKey) {
		t.Errorf("transport error leaks the credential")
	}
}

func TestScanner_VerifyUsesConfiguredOrigin(t *testing.T) {
	var gotHost string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		w.Header().Set("Content-Type", "application/json")
		_, _ = ioWriteString(w, catalogFixture)
	}))
	t.Cleanup(server.Close)

	scanner := &Scanner{client: server.Client(), apiBase: server.URL + "/"}
	if _, _, err := scanner.verifyToken(context.Background(), testKey); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotHost == "" {
		t.Fatalf("expected the configured origin to receive the request")
	}

	if DefaultAPIBase != "https://api.orcarouter.ai/v1" {
		t.Errorf("default API origin drifted from the documented endpoint: %q", DefaultAPIBase)
	}
	if strings.HasSuffix(DefaultAPIBase, "/") {
		t.Errorf("default API origin must not end with a slash")
	}
}

// ioWriteString keeps the handler above readable without pulling fmt into the test.
func ioWriteString(w http.ResponseWriter, s string) (int, error) { return w.Write([]byte(s)) }

func TestCatalogResponseDoesNotRequireAuthenticationToParse(t *testing.T) {
	// Guard the decoder against the real payload shape: object, created,
	// owned_by and pricing are all present and must not break decoding.
	payload := `{"data":[{"id":"orcarouter/pod","object":"model","created":0,"owned_by":"orcarouter","pricing":{"prompt":"0"},"context_length":128000,"architecture":{"modality":"text->text","input_modalities":["text"],"output_modalities":["text"]},"supported_endpoint_types":["openai","openai-response","anthropic","gemini"],"supported_parameters":["temperature"]}]}`

	var catalog Catalog
	if err := json.Unmarshal([]byte(payload), &catalog); err != nil {
		t.Fatalf("failed to decode representative payload: %v", err)
	}
	if len(catalog.Data) != 1 || catalog.Data[0].ID != "orcarouter/pod" {
		t.Fatalf("unexpected catalog decode: %+v", catalog.Data)
	}
	if len(catalog.Filter(CapabilityChat)) != 1 {
		t.Errorf("router alias with multiple text endpoint types must be chat capable")
	}
}
