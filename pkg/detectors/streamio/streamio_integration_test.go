package streamio

import (
	"context"
	"testing"
)

// TestStreamIO_RealCredentials tests detection and verification with real Stream.io credentials
// INSTRUCTIONS TO USE:
// 1. Get real Stream.io credentials from https://getstream.io/dashboard/
// 2. Replace the placeholder values below
// 3. Run: go test -v -run TestStreamIO_RealCredentials
func TestStreamIO_RealCredentials(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping real credentials test in short mode")
	}

	// REPLACE THESE WITH YOUR REAL STREAM.IO CREDENTIALS FROM DASHBOARD
	realAppId := "1644228"        // Numeric ID from dashboard
	realApiKey := "4u3ncebvw27r"
	realApiSecret := "as57ayreare6wqz2vj2uvsgcmpgbjejcchkdd9723gku26dqvwezgpbwnbpwmsn7"

	// Skip if using placeholder values (commented out for testing)
	if realAppId == "your_app_id_here" {
		t.Skip("Replace realAppId, realApiKey, and realApiSecret with actual Stream.io credentials to run this test")
	}

	ctx := context.Background()
	scanner := Scanner{}

	// Create test input with real credentials
	input := `
stream_app_id=` + realAppId + `
stream_api_key=` + realApiKey + `
stream_api_secret=` + realApiSecret

	t.Logf("Testing with real Stream.io credentials")
	t.Logf("App ID: %s", realAppId)
	t.Logf("API Key: %s", realApiKey)
	t.Logf("API Secret: %s***", realApiSecret[:10]) // Only show first 10 chars

	// Test detection (without verification)
	t.Run("Detection", func(t *testing.T) {
		results, err := scanner.FromData(ctx, false, []byte(input))
		if err != nil {
			t.Fatalf("Error during detection: %v", err)
		}

		if len(results) == 0 {
			t.Fatal("No credentials detected!")
		}

		result := results[0]
		t.Logf("✅ Detection successful!")
		t.Logf("   App ID extracted: %s", result.SecretParts["app_id"])
		t.Logf("   API Key extracted: %s", result.SecretParts["api_key"])
		t.Logf("   API Secret extracted: %s***", result.SecretParts["api_secret"][:10])

		if result.SecretParts["app_id"] != realAppId {
			t.Errorf("App ID mismatch: got %q, want %q", result.SecretParts["app_id"], realAppId)
		}
		if result.SecretParts["api_key"] != realApiKey {
			t.Errorf("API Key mismatch: got %q, want %q", result.SecretParts["api_key"], realApiKey)
		}
		if result.SecretParts["api_secret"] != realApiSecret {
			t.Errorf("API Secret mismatch: got %q, want %q", result.SecretParts["api_secret"], realApiSecret)
		}
	})

	// Test verification (with actual API call)
	t.Run("Verification", func(t *testing.T) {
		results, err := scanner.FromData(ctx, true, []byte(input))
		if err != nil {
			t.Fatalf("Error during verification: %v", err)
		}

		if len(results) == 0 {
			t.Fatal("No credentials detected!")
		}

		result := results[0]
		t.Logf("Verification result: Verified=%v", result.Verified)

		if result.Verified {
			t.Logf("✅ Credentials verified successfully!")
		} else {
			t.Logf("⚠️  Credentials not verified (either invalid or verification endpoint issue)")
			if result.VerificationError() != nil {
				t.Logf("   Verification error: %v", result.VerificationError())
			}
		}

		// Note: We don't fail the test if verification fails, as it might be due to:
		// - Network issues
		// - Rate limiting
		// - Endpoint changes
		// The important part is that detection worked
	})
}

// TestStreamIO_DetectionOnly tests only the detection logic with sample credentials
// This runs even without real credentials
func TestStreamIO_DetectionOnly(t *testing.T) {
	ctx := context.Background()
	scanner := Scanner{}

	testCases := []struct {
		name      string
		apiKey    string
		apiSecret string
	}{
		{
			name:      "Short format",
			apiKey:    "abcd1234",
			apiSecret: "secret1234567890abcdefghijklmnopqrstuvwxyz12",
		},
		{
			name:      "Medium format",
			apiKey:    "streamkey12345",
			apiSecret: "streamsecret1234567890abcdefghijklmnopqrstuvwxyz123456",
		},
		{
			name:      "Long format",
			apiKey:    "mystreamkey123456789",
			apiSecret: "mystreamsecret1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdef",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			input := `
stream_api_key=` + tc.apiKey + `
stream_api_secret=` + tc.apiSecret

			results, err := scanner.FromData(ctx, false, []byte(input))
			if err != nil {
				t.Fatalf("Error: %v", err)
			}

			if len(results) == 0 {
				t.Fatal("Expected to find credentials, but got none")
			}

			result := results[0]
			if result.SecretParts["api_key"] != tc.apiKey {
				t.Errorf("API Key mismatch: got %q, want %q", result.SecretParts["api_key"], tc.apiKey)
			}
			if result.SecretParts["api_secret"] != tc.apiSecret {
				t.Errorf("API Secret mismatch: got %q, want %q", result.SecretParts["api_secret"], tc.apiSecret)
			}

			t.Logf("✅ Successfully detected: key=%s, secret=%s***",
				result.SecretParts["api_key"],
				result.SecretParts["api_secret"][:10])
		})
	}
}
