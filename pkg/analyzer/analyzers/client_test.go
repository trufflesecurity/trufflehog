package analyzers

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAnalyzerClientUnsafeSuccess(t *testing.T) {
	testCases := []struct {
		name           string
		method         string
		expectedStatus int
		expectedError  bool
	}{
		{
			name:           "Safe method (GET)",
			method:         http.MethodGet,
			expectedStatus: http.StatusOK,
			expectedError:  false,
		},
		{
			name:           "Safe method (HEAD)",
			method:         http.MethodHead,
			expectedStatus: http.StatusOK,
			expectedError:  false,
		},
		{
			name:           "Safe method (OPTIONS)",
			method:         http.MethodOptions,
			expectedStatus: http.StatusOK,
			expectedError:  false,
		},
		{
			name:           "Safe method (TRACE)",
			method:         http.MethodTrace,
			expectedStatus: http.StatusOK,
			expectedError:  false,
		},
		{
			name:           "Unsafe method (POST) with success status",
			method:         http.MethodPost,
			expectedStatus: http.StatusOK,
			expectedError:  true,
		},
		{
			name:           "Unsafe method (PUT) with success status",
			method:         http.MethodPut,
			expectedStatus: http.StatusOK,
			expectedError:  true,
		},
		{
			name:           "Unsafe method (DELETE) with success status",
			method:         http.MethodDelete,
			expectedStatus: http.StatusOK,
			expectedError:  true,
		},
		{
			name:           "Unsafe method (POST) with error status",
			method:         http.MethodPost,
			expectedStatus: http.StatusInternalServerError,
			expectedError:  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a test server that returns the expected status code
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.expectedStatus)
			}))
			defer server.Close()

			// Create a test request
			req, err := http.NewRequest(tc.method, server.URL, nil)
			if err != nil {
				t.Fatalf("Failed to create test request: %v", err)
			}

			// Create the AnalyzerRoundTripper with a test client
			client := NewAnalyzeClient(nil)

			// Perform the request
			resp, err := client.Do(req)
			if resp != nil {
				_ = resp.Body.Close()
			}

			// Check the error
			if err != nil && !tc.expectedError {
				t.Errorf("Unexpected error: %v", err)
			} else if err == nil && tc.expectedError {
				t.Errorf("Expected error, but got nil")
			}

			// Check the response status code
			if resp != nil && resp.StatusCode != tc.expectedStatus {
				t.Errorf("Expected status code: %d, but got: %d", tc.expectedStatus, resp.StatusCode)
			}
		})
	}
}
