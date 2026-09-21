package clickhouse

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

const keyword = "clickhouse"

func TestClickHouse_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - native connection string",
			input: "dsn = 'clickhouse://analytics:s3cr3tpassword@ch.example.com:9000/metrics'",
			want:  []string{"ch.example.com:9000" + "analytics" + "s3cr3tpassword"},
		},
		{
			name:  "valid pattern - tls scheme",
			input: "dsn = 'clickhouses://analytics:s3cr3tpassword@ch.example.com:9440'",
			want:  []string{"ch.example.com:9440" + "analytics" + "s3cr3tpassword"},
		},
		{
			name:  "valid pattern - no port",
			input: "dsn = 'clickhouse://analytics:s3cr3tpassword@ch.example.com'",
			want:  []string{"ch.example.com" + "analytics" + "s3cr3tpassword"},
		},
		{
			name:  "valid pattern - omitted user defaults to default",
			input: "dsn = 'clickhouse://:s3cr3tpassword@ch.example.com:9000'",
			want:  []string{"ch.example.com:9000" + "default" + "s3cr3tpassword"},
		},
		{
			name:  "valid pattern - clickhouse cloud over https",
			input: "url = 'https://analytics:s3cr3tpassword@abc123.us-central1.gcp.clickhouse.cloud:8443'",
			want:  []string{"abc123.us-central1.gcp.clickhouse.cloud:8443" + "analytics" + "s3cr3tpassword"},
		},
		{
			name:  "valid pattern - ignore duplicate",
			input: "a = 'clickhouse://analytics:s3cr3tpassword@ch.example.com:9000' b = 'clickhouse://analytics:s3cr3tpassword@ch.example.com:9000'",
			want:  []string{"ch.example.com:9000" + "analytics" + "s3cr3tpassword"},
		},
		{
			name:  "invalid pattern - redacted password",
			input: fmt.Sprintf("%s dsn = 'clickhouse://analytics:*******@ch.example.com:9000'", keyword),
			want:  []string{},
		},
		{
			name:  "invalid pattern - unexpanded variable",
			input: fmt.Sprintf("%s dsn = 'clickhouse://analytics:$CLICKHOUSE_PASSWORD@ch.example.com:9000'", keyword),
			want:  []string{},
		},
		{
			name:  "invalid pattern - password too short",
			input: fmt.Sprintf("%s dsn = 'clickhouse://analytics:ab@ch.example.com:9000'", keyword),
			want:  []string{},
		},
		{
			name:  "invalid pattern - https url that is not clickhouse cloud",
			input: fmt.Sprintf("%s is configured at https://analytics:s3cr3tpassword@example.com:8443", keyword),
			want:  []string{},
		},
		{
			name:  "invalid pattern - no credentials in url",
			input: fmt.Sprintf("%s dsn = 'clickhouse://ch.example.com:9000/metrics'", keyword),
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

func TestClickHouse_HttpEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		hostPort string
		secure   bool
		want     string
	}{
		{"native port maps to http", "ch.example.com:9000", false, "http://ch.example.com:8123"},
		{"native tls port maps to https", "ch.example.com:9440", false, "https://ch.example.com:8443"},
		{"tls scheme with native port maps to https", "ch.example.com:9000", true, "https://ch.example.com:8443"},
		{"no port defaults to http interface", "ch.example.com", false, "http://ch.example.com:8123"},
		{"no port with tls defaults to https interface", "ch.example.com", true, "https://ch.example.com:8443"},
		{"http port is kept", "ch.example.com:8123", false, "http://ch.example.com:8123"},
		{"https port implies tls", "ch.example.com:8443", false, "https://ch.example.com:8443"},
		{"custom port is left alone", "ch.example.com:18123", false, "http://ch.example.com:18123"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := httpEndpoint(test.hostPort, test.secure); got != test.want {
				t.Errorf("httpEndpoint(%q, %v) = %q, want %q", test.hostPort, test.secure, got, test.want)
			}
		})
	}
}

func TestClickHouse_Verify(t *testing.T) {
	// Status codes below are what a real ClickHouse server answers on its HTTP
	// interface: 200 for a working credential and 403 for both a bad password
	// and an unknown user.
	tests := []struct {
		name         string
		status       int
		wantVerified bool
		wantErr      bool
	}{
		{"valid credential", http.StatusOK, true, false},
		{"authentication failed", http.StatusForbidden, false, false},
		{"unauthorized", http.StatusUnauthorized, false, false},
		{"server error is indeterminate", http.StatusInternalServerError, false, true},
		{"gateway error is indeterminate", http.StatusBadGateway, false, true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var gotUser, gotKey, gotQuery string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotUser = r.Header.Get("X-ClickHouse-User")
				gotKey = r.Header.Get("X-ClickHouse-Key")
				gotQuery = r.URL.Query().Get("query")
				w.WriteHeader(test.status)
			}))
			defer srv.Close()

			host := strings.TrimPrefix(srv.URL, "http://")
			verified, err := verifyClickHouse(context.Background(), srv.Client(), host, false, "analytics", "xK9mQ2vLp7wR4tZa")

			if verified != test.wantVerified {
				t.Errorf("verified = %v, want %v", verified, test.wantVerified)
			}
			if (err != nil) != test.wantErr {
				t.Errorf("err = %v, wantErr %v", err, test.wantErr)
			}
			if gotUser != "analytics" || gotKey != "xK9mQ2vLp7wR4tZa" {
				t.Errorf("auth headers = (%q, %q), want (analytics, xK9mQ2vLp7wR4tZa)", gotUser, gotKey)
			}
			if gotQuery != "SELECT 1" {
				t.Errorf("query = %q, want %q", gotQuery, "SELECT 1")
			}
		})
	}
}
