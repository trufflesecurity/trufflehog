package common

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type bearerVerificationRoundTripper func(*http.Request) (*http.Response, error)

func (f bearerVerificationRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestVerifyBearerTokenStatuses(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		wantValid bool
		wantErr   bool
	}{
		{name: "verified", status: http.StatusOK, wantValid: true},
		{name: "unauthorized is invalid", status: http.StatusUnauthorized},
		{name: "forbidden is indeterminate", status: http.StatusForbidden, wantErr: true},
		{name: "rate limited is indeterminate", status: http.StatusTooManyRequests, wantErr: true},
		{name: "server error is indeterminate", status: http.StatusInternalServerError, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: bearerVerificationRoundTripper(func(req *http.Request) (*http.Response, error) {
				if req.Method != http.MethodGet {
					t.Errorf("method = %q, want GET", req.Method)
				}
				if req.URL.String() != "https://provider.example/read-only" {
					t.Errorf("URL = %q, unexpected endpoint", req.URL.String())
				}
				if got := req.Header.Get("Authorization"); got != "Bearer synthetic-secret" {
					t.Errorf("Authorization = %q, want bearer token", got)
				}
				return &http.Response{
					StatusCode: tc.status,
					Body:       io.NopCloser(strings.NewReader("synthetic response")),
					Header:     make(http.Header),
					Request:    req,
				}, nil
			})}
			valid, err := VerifyBearerToken(context.Background(), client, "https://provider.example/read-only", "synthetic-secret")
			if valid != tc.wantValid {
				t.Errorf("valid = %v, want %v", valid, tc.wantValid)
			}
			if (err != nil) != tc.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestVerifyBearerTokenCanceledRequestIsIndeterminate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client := &http.Client{Transport: bearerVerificationRoundTripper(func(req *http.Request) (*http.Response, error) {
		return nil, req.Context().Err()
	})}
	valid, err := VerifyBearerToken(ctx, client, "https://provider.example/read-only", "synthetic-secret")
	if valid {
		t.Fatal("canceled request must not be verified")
	}
	if err == nil {
		t.Fatal("canceled request must return an indeterminate error")
	}
}
