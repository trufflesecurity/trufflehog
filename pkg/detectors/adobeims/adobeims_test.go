package adobeims

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

// makeTestJWT builds a minimal structurally-valid JWT from a JSON payload string.
func makeTestJWT(payloadJSON string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(payloadJSON))
	return header + "." + payload + ".AAABBBCCCDDDEEEFFFGGGHHHIIIJJJKKKLLLMMMNNNOOOPPPQQQRRRSSST"
}

var (
	accessToken  = makeTestJWT(`{"type":"access_token","client_id":"testclient123","as":"ims-na1"}`)
	refreshToken = makeTestJWT(`{"type":"refresh_token","client_id":"testclient123","as":"ims-na1"}`)
	nonIMSToken  = makeTestJWT(`{"type":"access_token","client_id":"testclient123","as":"example.com"}`)
)

// --- Pattern tests ---

func TestAdobeIMS_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "access_token in JSON",
			input: `{"access_token": "` + accessToken + `", "token_type": "bearer"}`,
			want:  []string{accessToken},
		},
		{
			name:  "access_token as env var",
			input: "ACCESS_TOKEN=" + accessToken,
			want:  []string{accessToken},
		},
		{
			name:  "refresh_token in JSON",
			input: `{"refresh_token": "` + refreshToken + `"}`,
			want:  []string{refreshToken},
		},
		{
			name:  "both tokens present",
			input: `{"access_token": "` + accessToken + `", "refresh_token": "` + refreshToken + `"}`,
			want:  []string{accessToken, refreshToken},
		},
		{
			name:  "non-IMS JWT — should not match",
			input: nonIMSToken,
			want:  nil,
		},
		{
			name:  "non-JWT value — should not match",
			input: `{"access_token": "notajwt"}`,
			want:  nil,
		},
		{
			name:  "malformed JWT payload — should not match",
			input: `{"access_token": "eyJhbGci.eyJOT1RWQUxJREpTT04.AAABBBCCCDDDEEEFFFGGG"}`,
			want:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(tt.input))

			if len(tt.want) == 0 {
				if len(matchedDetectors) == 0 {
					// Aho-Corasick correctly filtered out this input — keyword absent.
					return
				}
				// Keyword present but content should still yield no results
				results, err := d.FromData(context.Background(), false, []byte(tt.input))
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if len(results) != 0 {
					t.Errorf("expected no results, got %d", len(results))
				}
				return
			}

			if len(matchedDetectors) == 0 {
				t.Errorf("keywords %v not matched by input", d.Keywords())
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(tt.input))
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			got := make(map[string]struct{}, len(results))
			for _, r := range results {
				got[string(r.Raw)] = struct{}{}
			}
			want := make(map[string]struct{}, len(tt.want))
			for _, v := range tt.want {
				want[v] = struct{}{}
			}

			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestAdobeIMS_Verification_Request(t *testing.T) {
	payload, err := decodeJWTPayload(accessToken)
	if err != nil {
		t.Fatalf("decodeJWTPayload: %v", err)
	}

	var gotMethod, gotAuth, gotContentType, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotAuth = r.Header.Get("Authorization")
		gotContentType = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		fmt.Fprintf(w, `{"valid":true}`)
	}))
	defer srv.Close()

	validateToken(context.Background(), srv.Client(), srv.URL, accessToken, payload)

	if gotMethod != http.MethodPost {
		t.Errorf("method: want POST, got %s", gotMethod)
	}
	if gotAuth != "Bearer "+accessToken {
		t.Errorf("Authorization header wrong: %s", gotAuth)
	}
	if gotContentType != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type wrong: %s", gotContentType)
	}

	form, err := url.ParseQuery(gotBody)
	if err != nil {
		t.Fatalf("could not parse request body: %v", err)
	}
	if form.Get("type") != payload.Type {
		t.Errorf("body type: want %q, got %q", payload.Type, form.Get("type"))
	}
	if form.Get("client_id") != payload.ClientID {
		t.Errorf("body client_id: want %q, got %q", payload.ClientID, form.Get("client_id"))
	}
}

func TestAdobeIMS_Verification_Valid(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"valid":true}`)
	}))
	defer srv.Close()

	payload, err := decodeJWTPayload(accessToken)
	if err != nil {
		t.Fatalf("decodeJWTPayload: %v", err)
	}

	valid, verifyErr := validateToken(context.Background(), srv.Client(), srv.URL, accessToken, payload)
	if verifyErr != nil {
		t.Errorf("unexpected error: %v", verifyErr)
	}
	if !valid {
		t.Error("expected token to be verified")
	}
}

func TestAdobeIMS_Verification_Invalid(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"valid":false}`)
	}))
	defer srv.Close()

	payload, err := decodeJWTPayload(accessToken)
	if err != nil {
		t.Fatalf("decodeJWTPayload: %v", err)
	}

	valid, verifyErr := validateToken(context.Background(), srv.Client(), srv.URL, accessToken, payload)
	if verifyErr != nil {
		t.Errorf("unexpected error: %v", verifyErr)
	}
	if valid {
		t.Error("expected token to be invalid")
	}
}

func TestAdobeIMS_Verification_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	payload, err := decodeJWTPayload(accessToken)
	if err != nil {
		t.Fatalf("decodeJWTPayload: %v", err)
	}

	valid, verifyErr := validateToken(context.Background(), srv.Client(), srv.URL, accessToken, payload)
	if verifyErr != nil {
		t.Errorf("unexpected error: %v", verifyErr)
	}
	if valid {
		t.Error("expected token to be unverified")
	}
}

func TestAdobeIMS_Verification_Indeterminate_UnexpectedStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	payload, err := decodeJWTPayload(accessToken)
	if err != nil {
		t.Fatalf("decodeJWTPayload: %v", err)
	}

	valid, verifyErr := validateToken(context.Background(), srv.Client(), srv.URL, accessToken, payload)
	if verifyErr == nil {
		t.Error("expected a verification error for unexpected API response")
	}
	if valid {
		t.Error("expected token to be unverified")
	}
}


func TestAdobeIMS_Verification_Indeterminate_Timeout(t *testing.T) {
	handlerDone := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-handlerDone
	}))
	defer srv.Close()
	defer close(handlerDone)

	payload, err := decodeJWTPayload(accessToken)
	if err != nil {
		t.Fatalf("decodeJWTPayload: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	valid, verifyErr := validateToken(ctx, srv.Client(), srv.URL, accessToken, payload)
	if verifyErr == nil {
		t.Error("expected a verification error for timeout")
	}
	if valid {
		t.Error("expected token to be unverified")
	}
}
