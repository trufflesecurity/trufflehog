package lambdacloud

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

const (
	testHex   = "0123456789ab4def8123456789abcdef"
	testAlnum = "AbCdEfGhIjKlMnOpQrStUvWxYz012345"
	testToken = "secret_customer_" + testHex + "." + testAlnum
)

func TestLambdaCloud_Pattern(t *testing.T) {
	secondToken := "secret_other_" + testHex + "." + testAlnum
	type patternTest struct {
		name  string
		input string
		want  []string
	}
	tests := []patternTest{
		{name: "standalone", input: testToken, want: []string{testToken}},
		{name: "key beyond first prefilter window", input: strings.Repeat("padding\n", 200) + testToken + " # trufflehog:ignore", want: []string{testToken}},
		{name: "environment assignment", input: "LAMBDA_API_KEY=" + testToken, want: []string{testToken}},
		{name: "JSON", input: `{"api_key":"` + testToken + `"}`, want: []string{testToken}},
		{name: "YAML", input: "api_key: '" + testToken + "'", want: []string{testToken}},
		{name: "Bearer header", input: "Authorization: Bearer " + testToken, want: []string{testToken}},
		{name: "legacy curl", input: "curl --user '" + testToken + ":' https://cloud.lambda.ai/api/v1/instances", want: []string{testToken}},
		{name: "backticks", input: "`" + testToken + "`", want: []string{testToken}},
		{name: "duplicates", input: testToken + "\n" + testToken, want: []string{testToken}},
		{name: "multiple keys", input: testToken + "," + secondToken, want: []string{testToken, secondToken}},
		{name: "multiple keys separated by quotes", input: `"` + testToken + `","` + secondToken + `"`, want: []string{testToken, secondToken}},
		{name: "malformed earlier prefix", input: "secret_bad," + testToken, want: []string{testToken}},
		{name: "assignment with earlier prefix", input: "secret_bad=" + testToken, want: []string{testToken}},
		{name: "one-character name", input: "secret_a_" + testHex + "." + testAlnum, want: []string{"secret_a_" + testHex + "." + testAlnum}},
		{name: "64-character name", input: "secret_" + strings.Repeat("a", 64) + "_" + testHex + "." + testAlnum, want: []string{"secret_" + strings.Repeat("a", 64) + "_" + testHex + "." + testAlnum}},
		{name: "65-character name", input: "secret_" + strings.Repeat("a", 65) + "_" + testHex + "." + testAlnum},
		{name: "name starts with hyphen", input: "secret_-customer_" + testHex + "." + testAlnum},
		{name: "underscore in name", input: "secret_customer_team_" + testHex + "." + testAlnum},
		{name: "uppercase in name", input: "secret_Customer_" + testHex + "." + testAlnum},
		{name: "dot in name", input: "secret_customer.example_" + testHex + "." + testAlnum},
		{name: "space in name", input: "secret_customer team_" + testHex + "." + testAlnum},
		{name: "non-ASCII name", input: "secret_clienté_" + testHex + "." + testAlnum},
		{name: "uppercase hex", input: "secret_customer_" + strings.ToUpper(testHex) + "." + testAlnum},
		{name: "wrong UUID version", input: "secret_customer_" + testHex[:12] + "5" + testHex[13:] + "." + testAlnum},
		{name: "wrong UUID variant", input: "secret_customer_" + testHex[:16] + "c" + testHex[17:] + "." + testAlnum},
		{name: "non UUIDv4 hex", input: "secret_customer_0123456789abcdef0123456789abcdef." + testAlnum},
		{name: "empty", input: ""},
		{name: "generic secret", input: "secret_customer_value"},
		{name: "AWS Lambda", input: "aws_lambda_function: { source_code_hash: '" + testHex + testHex + "' }"},
		{name: "embedded prefix", input: "other_" + testToken},
		{name: "literal escaped newline before prefix", input: `\n` + testToken},
		{name: "Markdown underscore wrapper", input: "__" + testToken + "__"},
		{name: "uppercase prefix", input: "SECRET_customer_" + testHex + "." + testAlnum},
		{name: "empty customer name", input: "secret__" + testHex + "." + testAlnum},
		{name: "missing name separator", input: "secret_customer" + testHex + "." + testAlnum},
		{name: "short hex", input: "secret_customer_" + testHex[:31] + "." + testAlnum},
		{name: "long hex", input: "secret_customer_" + testHex + "0." + testAlnum},
		{name: "non-hex character", input: "secret_customer_g" + testHex[1:] + "." + testAlnum},
		{name: "missing alphanumeric suffix", input: "secret_customer_" + testHex},
		{name: "short alphanumeric suffix", input: testToken[:len(testToken)-1]},
		{name: "long alphanumeric suffix", input: testToken + "A"},
		{name: "underscore after suffix is a delimiter", input: testToken + "_extra", want: []string{testToken}},
		{name: "period after suffix is a delimiter", input: testToken + ".", want: []string{testToken}},
		{name: "invalid suffix character", input: "secret_customer_" + testHex + "." + testAlnum[:31] + "-"},
		{name: "dot is literal", input: "secret_customer_" + testHex + "X" + testAlnum},
		{name: "name does not cross a newline", input: "secret_customer\nother_" + testHex + "." + testAlnum},
		{name: "name does not cross a quote", input: `secret_customer"other_` + testHex + "." + testAlnum},
	}
	for _, name := range []string{"a", "customer-prod", "customer123", "0customer", "customer-"} {
		token := "secret_" + name + "_" + testHex + "." + testAlnum
		tests = append(tests, patternTest{name: "customer name " + name, input: token, want: []string{token}})
	}
	for _, variant := range []string{"8", "9", "a", "b"} {
		token := "secret_customer_" + testHex[:16] + variant + testHex[17:] + "." + testAlnum
		tests = append(tests, patternTest{name: "UUID variant " + variant, input: token, want: []string{token}})
	}

	s := Scanner{}
	core := ahocorasick.NewAhoCorasickCore([]detectors.Detector{s})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if len(tt.want) > 0 && len(core.FindDetectorMatches([]byte(tt.input))) == 0 {
				t.Fatal("keyword prefilter missed the credential")
			}
			results, err := s.FromData(context.Background(), false, []byte(tt.input))
			if err != nil {
				t.Fatal(err)
			}
			if len(results) != len(tt.want) {
				t.Fatalf("got %d results, want %d", len(results), len(tt.want))
			}
			for i, result := range results {
				if string(result.Raw) != tt.want[i] || result.SecretParts["key"] != tt.want[i] {
					t.Errorf("incorrect extraction: %q", result.Raw)
				}
				if result.DetectorType != detector_typepb.DetectorType_LambdaCloud || result.Verified || result.VerificationError() != nil {
					t.Error("incorrect unverified result metadata")
				}
			}

			found := make(map[string]struct{})
			for _, detectorMatch := range core.FindDetectorMatches([]byte(tt.input)) {
				for _, span := range detectorMatch.Matches() {
					spanResults, err := detectorMatch.FromData(context.Background(), false, span)
					if err != nil {
						t.Fatal(err)
					}
					for _, result := range spanResults {
						if result.HasChunkOffset() {
							t.Error("detector must let the engine locate the key in the full chunk")
						}
						found[string(result.Raw)] = struct{}{}
					}
				}
			}
			if len(found) != len(tt.want) {
				t.Fatalf("prefiltered scan found %d keys, want %d", len(found), len(tt.want))
			}
			for _, want := range tt.want {
				if _, ok := found[want]; !ok {
					t.Error("prefiltered scan missed expected key")
				}
			}
		})
	}
}

func TestLambdaCloud_FromData(t *testing.T) {
	for _, verify := range []bool{false, true} {
		t.Run(map[bool]string{false: "no verification", true: "verify once per unique key"}[verify], func(t *testing.T) {
			calls := 0
			s := Scanner{
				client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					calls++
					if req.Header.Get("Authorization") != "Bearer "+testToken {
						t.Error("verification did not use the complete extracted credential")
					}
					return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(testIdentityJSON))}, nil
				})},
			}
			results, err := s.FromData(context.Background(), verify, []byte(testToken+"\n"+testToken))
			if err != nil || len(results) != 1 || results[0].Verified != verify || results[0].VerificationError() != nil {
				t.Fatalf("unexpected detector result: count=%d, error=%v", len(results), err)
			}
			if (verify && calls != 1) || (!verify && calls != 0) {
				t.Errorf("unexpected request count: %d", calls)
			}
			if verify && (results[0].ExtraData["identity_id"] != "test-identity" || results[0].ExtraData["account_id"] != "test-account" || results[0].ExtraData["email"] != "test@example.com") {
				t.Error("verified finding is missing identity metadata")
			}
			if !verify && len(results[0].ExtraData) != 0 {
				t.Error("unverified finding has identity metadata")
			}
		})
	}
}

func TestLambdaCloud_VerificationResults(t *testing.T) {
	for _, tt := range []struct {
		name     string
		status   int
		body     string
		verified bool
		wantErr  bool
	}{
		{name: "verified", status: http.StatusOK, body: testIdentityJSON, verified: true},
		{name: "invalid", status: http.StatusUnauthorized, body: `{"error":{"code":"global/invalid-api-key"}}`},
		{name: "indeterminate", status: http.StatusTooManyRequests, wantErr: true},
		{name: "malformed JSON", status: http.StatusOK, body: `{"data":`, wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := Scanner{client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.Method != http.MethodGet || req.URL.String() != "https://cloud.lambda.ai/api/v1/identity" || req.Header.Get("Authorization") != "Bearer "+testToken {
					t.Fatal("incorrect identity verification request")
				}
				return &http.Response{StatusCode: tt.status, Body: io.NopCloser(strings.NewReader(tt.body))}, nil
			})}}
			results, err := s.FromData(context.Background(), true, []byte(testToken))
			if err != nil || len(results) != 1 {
				t.Fatalf("expected one finding: count=%d, error=%v", len(results), err)
			}
			result := results[0]
			if result.Verified != tt.verified || (result.VerificationError() != nil) != tt.wantErr {
				t.Fatalf("unexpected verification result: verified=%v, error=%v", result.Verified, result.VerificationError())
			}
			if !tt.verified && len(result.ExtraData) != 0 {
				t.Error("unverified finding has identity metadata")
			}
		})
	}
}

func TestLambdaCloud_VerificationErrorRedaction(t *testing.T) {
	s := Scanner{
		client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("transport error containing " + testToken)
		})},
	}
	results, err := s.FromData(context.Background(), true, []byte(testToken))
	if err != nil || len(results) != 1 || results[0].Verified || results[0].VerificationError() == nil {
		t.Fatal("transport error should retain an indeterminate finding")
	}
	if strings.Contains(results[0].VerificationError().Error(), testToken) {
		t.Error("verification error contains the credential")
	}
}

func TestLambdaCloud_ConcurrentUse(t *testing.T) {
	s := Scanner{
		client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(testIdentityJSON))}, nil
		})},
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results, err := s.FromData(context.Background(), true, []byte(testToken))
			if err != nil || len(results) != 1 || !results[0].Verified {
				t.Error("concurrent verification failed")
			}
		}()
	}
	wg.Wait()
}

const testIdentityJSON = `{"data":{"id":"test-identity","account_id":"test-account","identity_type":"user","email":"test@example.com","is_verified":true,"created_at":"2025-08-26T14:42:00Z","first_name":"Test","last_name":"User"}}`

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type trackedBody struct {
	io.Reader
	closed bool
}

func (b *trackedBody) Close() error {
	b.closed = true
	return nil
}

func TestLambdaCloud_VerifyToken(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		body     string
		verified bool
		wantErr  bool
		metadata map[string]string
	}{
		{name: "user identity", status: 200, body: testIdentityJSON, verified: true, metadata: map[string]string{"identity_id": "test-identity", "account_id": "test-account", "identity_type": "user", "email": "test@example.com"}},
		{name: "minimal identity", status: 200, body: `{"data":{"id":"test-identity","account_id":"test-account"}}`, verified: true, metadata: map[string]string{"identity_id": "test-identity", "account_id": "test-account"}},
		{name: "service identity with null personal fields", status: 200, body: `{"data":{"id":"test-identity","account_id":"test-account","identity_type":"service","email":null,"first_name":null,"last_name":null,"created_at":null}}`, verified: true, metadata: map[string]string{"identity_id": "test-identity", "account_id": "test-account", "identity_type": "service"}},
		{name: "unknown identity type", status: 200, body: `{"data":{"id":"test-identity","account_id":"test-account","identity_type":"future-type","new_field":{}}}`, verified: true, metadata: map[string]string{"identity_id": "test-identity", "account_id": "test-account", "identity_type": "future-type"}},
		{name: "false identity flag does not invalidate key", status: 200, body: `{"data":{"id":"test-identity","account_id":"test-account","is_verified":false}}`, verified: true, metadata: map[string]string{"identity_id": "test-identity", "account_id": "test-account"}},
		{name: "null optional fields", status: 200, body: `{"data":{"id":"test-identity","account_id":"test-account","identity_type":null,"email":null,"is_verified":null}}`, verified: true, metadata: map[string]string{"identity_id": "test-identity", "account_id": "test-account"}},
		{name: "invalid key", status: 401, body: `{"error":{"code":"global/invalid-api-key"}}`},
		{name: "revoked key", status: 401, body: `{"error":{"code":"global/invalid-api-key","message":"API key was invalid, expired, or deleted."}}`},
		{name: "unknown authentication error", status: 401, body: `{"error":{"code":"global/unknown"}}`},
		{name: "missing authentication code", status: 401, body: `{"error":{}}`},
		{name: "non-Lambda unauthorized response", status: 401, body: `<html>Unauthorized</html>`},
		{name: "inactive account", status: 403, body: `{"error":{"code":"global/account-inactive"}}`, wantErr: true},
		{name: "forbidden", status: 403, body: `{"error":{"code":"global/forbidden"}}`, wantErr: true},
		{name: "rate limited", status: 429, body: `{"error":{"code":"global/rate-limited"}}`, wantErr: true},
		{name: "server failure", status: 500, body: `{}`, wantErr: true},
		{name: "missing endpoint", status: 404, body: `{}`, wantErr: true},
		{name: "bad request", status: 400, body: `{}`, wantErr: true},
		{name: "unexpected success status", status: 204, wantErr: true},
		{name: "HTML success", status: 200, body: `<html>Login</html>`, wantErr: true},
		{name: "missing data", status: 200, body: `{}`, wantErr: true},
		{name: "null response", status: 200, body: `null`, wantErr: true},
		{name: "null data", status: 200, body: `{"data":null}`, wantErr: true},
		{name: "empty identity", status: 200, body: `{"data":{}}`, wantErr: true},
		{name: "missing identity ID", status: 200, body: `{"data":{"account_id":"test-account"}}`, wantErr: true},
		{name: "missing account ID", status: 200, body: `{"data":{"id":"test-identity"}}`, wantErr: true},
		{name: "empty identity ID", status: 200, body: `{"data":{"id":"","account_id":"test-account"}}`, wantErr: true},
		{name: "empty account ID", status: 200, body: `{"data":{"id":"test-identity","account_id":""}}`, wantErr: true},
		{name: "array data", status: 200, body: `{"data":[]}`, wantErr: true},
		{name: "string data", status: 200, body: `{"data":"unexpected"}`, wantErr: true},
		{name: "wrong ID type", status: 200, body: `{"data":{"id":123,"account_id":"test-account"}}`, wantErr: true},
		{name: "truncated JSON", status: 200, body: `{"data":[`, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			body := &trackedBody{Reader: strings.NewReader(tt.body)}
			client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.Method != http.MethodGet || req.URL.String() != "https://cloud.lambda.ai/api/v1/identity" {
					t.Fatalf("unexpected verification request: %s %s", req.Method, req.URL)
				}
				if req.Header.Get("Authorization") != "Bearer synthetic-test-token" {
					t.Error("missing Bearer authentication")
				}
				if req.Header.Get("Accept") != "application/json" {
					t.Error("missing JSON accept header")
				}
				if req.Body != nil {
					t.Error("verification request should have no body")
				}
				return &http.Response{StatusCode: tt.status, Body: body, Header: make(http.Header)}, nil
			})}
			verified, metadata, err := verifyToken(context.Background(), client, "synthetic-test-token")
			if verified != tt.verified || (err != nil) != tt.wantErr {
				t.Errorf("verifyToken() = (%v, %v), want (%v, error=%v)", verified, err, tt.verified, tt.wantErr)
			}
			if !body.closed {
				t.Error("response body was not closed")
			}
			if diff := cmp.Diff(tt.metadata, metadata); diff != "" {
				t.Errorf("metadata diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestLambdaCloud_VerifyTokenTransportError(t *testing.T) {
	for _, transportErr := range []error{context.DeadlineExceeded, context.Canceled, errors.New("connection failed")} {
		t.Run(transportErr.Error(), func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return nil, transportErr
			})}
			verified, _, err := verifyToken(context.Background(), client, "synthetic-test-token")
			if verified || !errors.Is(err, transportErr) {
				t.Errorf("verifyToken() = (%v, %v), want transport failure", verified, err)
			}
		})
	}
}

func TestLambdaCloud_VerifyTokenContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Context() != ctx {
			t.Error("verification request lost the caller's context")
		}
		return nil, req.Context().Err()
	})}
	verified, _, err := verifyToken(ctx, client, "synthetic-test-token")
	if verified || !errors.Is(err, context.Canceled) {
		t.Errorf("verifyToken() = (%v, %v), want cancellation", verified, err)
	}
}
