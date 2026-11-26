package browserstack

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVerifyBrowserStackCredentials(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		contentType string
		body        string
		want        bool
	}{
		{
			name:        "200 with JSON response verifies",
			statusCode:  http.StatusOK,
			contentType: "application/json",
			body:        `{"automate_plan":"small","parallel_sessions_max_allowed":5}`,
			want:        true,
		},
		{
			name:        "200 with HTML challenge page does not verify",
			statusCode:  http.StatusOK,
			contentType: "text/html; charset=UTF-8",
			body:        "<html><head><title>Client Challenge</title></head><body>Please verify you are human.</body></html>",
			want:        false,
		},
		{
			name:        "401 does not verify",
			statusCode:  http.StatusUnauthorized,
			contentType: "application/json",
			body:        `{"error":"Invalid username or access key"}`,
			want:        false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", test.contentType)
				w.WriteHeader(test.statusCode)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()

			originalURL := browserStackAPIURL
			browserStackAPIURL = server.URL
			defer func() { browserStackAPIURL = originalURL }()

			got, err := verifyBrowserStackCredentials(context.Background(), server.Client(), "someuser", "someaccesskey12345")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != test.want {
				t.Errorf("verifyBrowserStackCredentials() = %v, want %v", got, test.want)
			}
		})
	}
}
