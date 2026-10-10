package paystack

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern   = "sk_test_" + strings.Repeat("A", 40)
	invalidPattern = "sk_test_" + strings.Repeat("A", 19) + "?" + strings.Repeat("A", 20)
	keyword        = "paystack"
)

func TestPaystack_Pattern(t *testing.T) {
	d := Scanner{}
	core := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{name: "valid pattern", input: fmt.Sprintf("%s token = '%s'", keyword, validPattern), want: []string{validPattern}},
		{name: "invalid pattern", input: fmt.Sprintf("%s = '%s'", keyword, invalidPattern), want: []string{}},
		{name: "test key keyword", input: "sk_test_" + strings.Repeat("a", 40), want: []string{"sk_test_" + strings.Repeat("a", 40)}},
		{name: "live key keyword", input: "sk_live_" + strings.Repeat("b", 40), want: []string{"sk_live_" + strings.Repeat("b", 40)}},
		{name: "public key is not a secret key", input: "pk_test_" + strings.Repeat("a", 40), want: []string{}},
		{name: "not found", input: "ordinary configuration without credentials", want: []string{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if len(core.FindDetectorMatches([]byte(tc.input))) == 0 && len(tc.want) > 0 {
				t.Fatalf("keywords %v did not match input", d.Keywords())
			}
			results, err := d.FromData(context.Background(), false, []byte(tc.input))
			if err != nil {
				t.Fatalf("FromData error: %v", err)
			}
			got := make(map[string]struct{}, len(results))
			for _, result := range results {
				got[string(result.Raw)] = struct{}{}
				if result.SecretParts["key"] != string(result.Raw) {
					t.Errorf("SecretParts[key] = %q, want %q", result.SecretParts["key"], result.Raw)
				}
			}
			want := make(map[string]struct{}, len(tc.want))
			for _, value := range tc.want {
				want[value] = struct{}{}
			}
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("(-want +got):\n%s", diff)
			}
		})
	}
}

func TestVerifyPaystackStatuses(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		wantValid  bool
		wantErr    bool
	}{
		{name: "verified", statusCode: http.StatusOK, wantValid: true},
		{name: "invalid credential", statusCode: http.StatusUnauthorized},
		{name: "forbidden is indeterminate", statusCode: http.StatusForbidden, wantErr: true},
		{name: "unexpected server response is indeterminate", statusCode: http.StatusInternalServerError, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("method = %s, want GET", r.Method)
				}
				if got := r.Header.Get("Authorization"); got != "Bearer test-secret" {
					t.Errorf("Authorization = %q, want bearer token", got)
				}
				w.WriteHeader(tc.statusCode)
				_, _ = w.Write([]byte("response body"))
			}))
			defer server.Close()

			gotValid, err := verifyPaystackKeyWithClient(context.Background(), "test-secret", server.Client(), server.URL)
			if gotValid != tc.wantValid {
				t.Errorf("verified = %v, want %v", gotValid, tc.wantValid)
			}
			if (err != nil) != tc.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestVerifyPaystackTimeoutIsIndeterminate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	verified, err := verifyPaystackKeyWithClient(ctx, "test-secret", server.Client(), server.URL)
	if verified {
		t.Fatal("timed-out verification must not be marked verified")
	}
	if err == nil {
		t.Fatal("timed-out verification must return an indeterminate error")
	}
}
