//go:build integration
// +build integration

package openvsxdetector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
)

func TestOpenVSXDetector_Integration_FromData(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	// Create a mock server to simulate the OpenVSX API
	// This allows us to test the verification logic without making actual API calls
	validToken := "12345678-abcd-1234-abcd-1234567890ab"
	invalidToken := "11111111-2222-3333-4444-555555555555"
	
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/redhat/verify-pat" {
			t.Fatalf("Expected to request '/api/redhat/verify-pat', got: %s", r.URL.Path)
		}
		
		token := r.URL.Query().Get("token")
		
		if token == validToken {
			// Simulate a valid token response
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error": "Insufficient access rights for namespace: redhat"}`))
		} else {
			// Simulate an invalid token response
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error": "Invalid access token."}`))
		}
	}))
	defer mockServer.Close()
	
	// Create a custom client that directs requests to our mock server
	customClient := &http.Client{
		Transport: &mockTransport{
			mockURL: mockServer.URL,
		},
	}
	
	s := Scanner{
		client: customClient,
	}
	
	// Test with valid token
	validData := []byte("VSX Token: " + validToken)
	results, err := s.FromData(ctx, true, validData)
	if err != nil {
		t.Fatalf("Error scanning data: %s", err)
	}
	
	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}
	
	// Check that the token was verified as valid
	if !results[0].Verified {
		t.Fatalf("Expected token to be verified")
	}
	
	// Test with invalid token
	invalidData := []byte("VSX Token: " + invalidToken)
	results, err = s.FromData(ctx, true, invalidData)
	if err != nil {
		t.Fatalf("Error scanning data: %s", err)
	}
	
	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}
	
	// Check that the token was not verified
	if results[0].Verified {
		t.Fatalf("Expected token to not be verified")
	}
}

// mockTransport is a custom http.RoundTripper that redirects requests to the mock server
type mockTransport struct {
	mockURL string
}

func (t *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Rewrite the request URL to point to our mock server
	req.URL.Scheme = "http"
	req.URL.Host = req.Host
	
	// Use the standard transport to perform the request
	return http.DefaultTransport.RoundTrip(req)
}