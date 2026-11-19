package solana

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	// The example keypair from trufflehog issue #4887, published there by
	// the reporter. Not a live secret: it was posted publicly in the issue.
	exampleKeypair = `[174,47,154,16,202,193,206,113,199,190,53,133,169,175,31,56,222,53,138,189,224,216,117,173,10,149,53,45,73,251,237,246,15,185,186,82,177,240,148,69,241,227,167,80,141,89,240,121,121,35,172,247,68,251,226,218,48,63,176,109,168,89,238,135]`
	// The address the issue states for the example keypair.
	exampleAddress = "24PNhTaNtomHhoy3fTRaMhAFCRj4uHqhZEEoWrKDbR5p"
)

func exampleValues(t *testing.T) []int {
	t.Helper()
	var values []int
	if err := json.Unmarshal([]byte(exampleKeypair), &values); err != nil {
		t.Fatalf("example keypair should parse: %v", err)
	}
	return values
}

func marshalValues(t *testing.T, values []int) string {
	t.Helper()
	out, err := json.Marshal(values)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(out)
}

func TestSolana_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	values := exampleValues(t)
	pretty, err := json.MarshalIndent(values, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent: %v", err)
	}
	short := marshalValues(t, values[:32])
	long := marshalValues(t, append(append([]int{}, values...), 0))
	overRange := append(append([]int{}, values...), 0)
	overRange[0] = 256
	underRange := append(append([]int{}, values...), 0)
	underRange[0] = -1

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - compact keypair file",
			input: exampleKeypair,
			want:  []string{exampleKeypair},
		},
		{
			name:  "valid pattern - pretty-printed keypair file",
			input: string(pretty),
			want:  []string{string(pretty)},
		},
		{
			name:  "valid pattern - keypair embedded in surrounding text",
			input: "wallet file contents:\n" + exampleKeypair + "\nend of file",
			want:  []string{exampleKeypair},
		},
		{
			name:  "invalid pattern - 32-byte array",
			input: short,
			want:  nil,
		},
		{
			name:  "invalid pattern - 65-byte array",
			input: long,
			want:  nil,
		},
		{
			name:  "invalid pattern - value above 255",
			input: marshalValues(t, overRange),
			want:  nil,
		},
		{
			name:  "invalid pattern - negative value",
			input: marshalValues(t, underRange),
			want:  nil,
		},
		{
			name:  "invalid pattern - float value",
			input: strings.Replace(exampleKeypair, "174", "174.5", 1),
			want:  nil,
		},
		{
			name:  "valid pattern - keypair nested inside another array",
			input: "[" + exampleKeypair + "]",
			want:  []string{exampleKeypair},
		},
		{
			name:  "invalid pattern - nested short array",
			input: `[[1,2,3]]`,
			want:  nil,
		},
		{
			name:  "invalid pattern - empty array",
			input: `[]`,
			want:  nil,
		},
		{
			name:  "invalid pattern - non-JSON file",
			input: "this is a plain text file with no secrets in it",
			want:  nil,
		},
		{
			name:  "invalid pattern - JSON object, not an array",
			input: `{"keypair": "not a real keypair"}`,
			want:  nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(test.want) > 0 && len(matchedDetectors) == 0 {
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
				actual[string(r.Raw)] = struct{}{}
				if r.SecretParts["key"] != string(r.Raw) {
					t.Errorf("SecretParts[key] = %q, want %q", r.SecretParts["key"], r.Raw)
				}
				if r.SecretParts["public_key"] != exampleAddress {
					t.Errorf("SecretParts[public_key] = %q, want %q", r.SecretParts["public_key"], exampleAddress)
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

func TestSolana_AddressDerivation(t *testing.T) {
	// The address derived from bytes 32-63 of the example keypair must be
	// the address stated in the issue.
	keypair, ok := parseKeypair([]byte(exampleKeypair))
	if !ok {
		t.Fatal("example keypair should parse")
	}
	if got := base58Encode(keypair[32:]); got != exampleAddress {
		t.Errorf("derived address = %q, want %q", got, exampleAddress)
	}
}

func TestSolana_Base58Encode(t *testing.T) {
	tests := []struct {
		input []byte
		want  string
	}{
		{input: []byte{}, want: ""},
		{input: []byte{0}, want: "1"},
		{input: []byte{0, 0, 1}, want: "112"},
		{input: []byte("hello world"), want: "StV1DL6CwTryKyV"},
	}
	for _, test := range tests {
		if got := base58Encode(test.input); got != test.want {
			t.Errorf("base58Encode(%v) = %q, want %q", test.input, got, test.want)
		}
	}
}

// rpcServer returns an httptest server that replies to every verification
// request with the given status and body, and a count of the requests it
// received. It fails the test unless each request is a JSON-RPC
// getAccountInfo call for the example address.
func rpcServer(t *testing.T, status int, body string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method %s, want POST", r.Method)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("reading request body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var req rpcRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			t.Errorf("request body is not valid JSON-RPC: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if req.Method != "getAccountInfo" {
			t.Errorf("RPC method = %q, want %q", req.Method, "getAccountInfo")
		}
		if len(req.Params) == 0 || req.Params[0] != exampleAddress {
			t.Errorf("RPC params = %v, want first param %q", req.Params, exampleAddress)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	return ts, &hits
}

func TestSolana_VerifyKeypairResponses(t *testing.T) {
	tests := []struct {
		name         string
		status       int
		body         string
		wantVerified bool
		wantErr      bool
	}{
		{
			name:         "funded account verifies",
			status:       http.StatusOK,
			body:         `{"jsonrpc":"2.0","result":{"context":{"slot":1},"value":{"lamports":12345,"owner":"11111111111111111111111111111111","executable":false,"rentEpoch":0}},"id":1}`,
			wantVerified: true,
			wantErr:      false,
		},
		{
			name:         "missing account determinately unverified",
			status:       http.StatusOK,
			body:         `{"jsonrpc":"2.0","result":{"context":{"slot":1},"value":null},"id":1}`,
			wantVerified: false,
			wantErr:      false,
		},
		{
			name:         "zero-lamport account unverified",
			status:       http.StatusOK,
			body:         `{"jsonrpc":"2.0","result":{"context":{"slot":1},"value":{"lamports":0,"owner":"11111111111111111111111111111111","executable":false,"rentEpoch":0}},"id":1}`,
			wantVerified: false,
			wantErr:      false,
		},
		{
			name:         "RPC error indeterminate",
			status:       http.StatusOK,
			body:         `{"jsonrpc":"2.0","error":{"code":-32602,"message":"Invalid param: could not parse pubkey"},"id":1}`,
			wantVerified: false,
			wantErr:      true,
		},
		{
			name:         "HTTP 500 indeterminate",
			status:       http.StatusInternalServerError,
			body:         `{"error":"internal"}`,
			wantVerified: false,
			wantErr:      true,
		},
		{
			name:         "malformed JSON indeterminate",
			status:       http.StatusOK,
			body:         `not json`,
			wantVerified: false,
			wantErr:      true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ts, _ := rpcServer(t, test.status, test.body)
			defer ts.Close()

			verified, lamports, err := verifyKeypair(context.Background(), ts.Client(), ts.URL, exampleAddress)
			if verified != test.wantVerified {
				t.Errorf("verified = %v, want %v", verified, test.wantVerified)
			}
			if (err != nil) != test.wantErr {
				t.Errorf("err = %v, wantErr = %v", err, test.wantErr)
			}
			if test.wantVerified && lamports != 12345 {
				t.Errorf("lamports = %d, want 12345", lamports)
			}
		})
	}
}

// fromDataWithEndpoints runs FromData with verification routed only at the
// given test servers.
func fromDataWithEndpoints(t *testing.T, input string, endpoints ...string) []detectors.Result {
	t.Helper()
	d := Scanner{}
	if err := d.SetConfiguredEndpoints(endpoints...); err != nil {
		t.Fatalf("SetConfiguredEndpoints: %v", err)
	}
	results, err := d.FromData(context.Background(), true, []byte(input))
	if err != nil {
		t.Fatalf("FromData: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	return results
}

func TestSolana_FromDataVerify(t *testing.T) {
	fundedBody := `{"jsonrpc":"2.0","result":{"context":{"slot":1},"value":{"lamports":5000,"owner":"11111111111111111111111111111111","executable":false,"rentEpoch":0}},"id":1}`
	funded, _ := rpcServer(t, http.StatusOK, fundedBody)
	defer funded.Close()

	r := fromDataWithEndpoints(t, exampleKeypair, funded.URL)[0]
	if !r.Verified {
		t.Errorf("expected funded keypair to verify")
	}
	if r.ExtraData["lamports"] != "5000" {
		t.Errorf("ExtraData[lamports] = %q, want %q", r.ExtraData["lamports"], "5000")
	}
	if r.ExtraData["public_key"] != exampleAddress {
		t.Errorf("ExtraData[public_key] = %q, want %q", r.ExtraData["public_key"], exampleAddress)
	}
	if r.VerificationError() != nil {
		t.Errorf("expected no verification error after successful verify, got %v", r.VerificationError())
	}
	if r.DetectorType.String() != "Solana" {
		t.Errorf("expected DetectorType Solana, got %s", r.DetectorType.String())
	}

	missingBody := `{"jsonrpc":"2.0","result":{"context":{"slot":1},"value":null},"id":1}`
	missing, _ := rpcServer(t, http.StatusOK, missingBody)
	defer missing.Close()

	r = fromDataWithEndpoints(t, exampleKeypair, missing.URL)[0]
	if r.Verified {
		t.Errorf("missing account should not verify")
	}
	if r.VerificationError() != nil {
		t.Errorf("expected no verification error for a determinate miss, got %v", r.VerificationError())
	}
}

func TestSolana_DuplicateKeypairVerifiesOnce(t *testing.T) {
	fundedBody := `{"jsonrpc":"2.0","result":{"context":{"slot":1},"value":{"lamports":5000,"owner":"11111111111111111111111111111111","executable":false,"rentEpoch":0}},"id":1}`
	ts, hits := rpcServer(t, http.StatusOK, fundedBody)
	defer ts.Close()

	d := Scanner{}
	if err := d.SetConfiguredEndpoints(ts.URL); err != nil {
		t.Fatalf("SetConfiguredEndpoints: %v", err)
	}
	results, err := d.FromData(context.Background(), true, []byte(exampleKeypair+"\n"+exampleKeypair))
	if err != nil {
		t.Fatalf("FromData: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if !results[0].Verified {
		t.Errorf("expected keypair to verify")
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("verification requests = %d, want 1", got)
	}
}

func TestSolana_TransientFailureKeepsVerificationError(t *testing.T) {
	ts, _ := rpcServer(t, http.StatusTooManyRequests, `{"error":"slow down"}`)
	defer ts.Close()

	r := fromDataWithEndpoints(t, exampleKeypair, ts.URL)[0]
	if r.Verified {
		t.Errorf("result should not verify on HTTP 429")
	}
	if r.VerificationError() == nil {
		t.Errorf("expected verification error on HTTP 429, got nil")
	}
}
