package flutterwave

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestFlutterWave_Pattern(t *testing.T) {
	d := Scanner{}
	core := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{name: "live secret key", input: `{"flutterwave_secret":"FLWSECK-aylhdv2oo3wf5tylj8s4d9bqb8adoebx-X"}`, want: []string{"FLWSECK-aylhdv2oo3wf5tylj8s4d9bqb8adoebx-X"}},
		{name: "test secret key", input: `{"flutterwave_secret":"FLWSECK_TEST-aylhdv2oo3wf5tylj8s4d9bqb8adoebx-X"}`, want: []string{"FLWSECK_TEST-aylhdv2oo3wf5tylj8s4d9bqb8adoebx-X"}},
		{name: "public key is not a secret key", input: `{"flutterwave_public_key":"FLWPUBK_TEST-aylhdv2oo3wf5tylj8s4d9bqb8adoebx-X"}`, want: []string{}},
		{name: "reject malformed key", input: `{"flutterwave_secret":"FLWSECK_TEST-aylhdv2oo3wf5tylj8s4d9bqb8adoebx-XX"}`, want: []string{}},
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

func TestVerifyFlutterwaveStatuses(t *testing.T) {
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

			gotValid, err := verifyFlutterwaveWithClient(context.Background(), "test-secret", server.Client(), server.URL)
			if gotValid != tc.wantValid {
				t.Errorf("verified = %v, want %v", gotValid, tc.wantValid)
			}
			if (err != nil) != tc.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestVerifyFlutterwaveTimeoutIsIndeterminate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	verified, err := verifyFlutterwaveWithClient(ctx, "test-secret", server.Client(), server.URL)
	if verified {
		t.Fatal("timed-out verification must not be marked verified")
	}
	if err == nil {
		t.Fatal("timed-out verification must return an indeterminate error")
	}
}
