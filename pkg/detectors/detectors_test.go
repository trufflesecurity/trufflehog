//go:build detectors
// +build detectors

package detectors

import (
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	regexp "github.com/wasilibs/go-re2"
)

func TestPrefixRegex(t *testing.T) {
	tests := []struct {
		keywords []string
		expected string
	}{
		{
			keywords: []string{"securitytrails"},
			expected: `(?i:securitytrails)(?:.|[\n\r]){0,40}?`,
		},
		{
			keywords: []string{"zipbooks"},
			expected: `(?i:zipbooks)(?:.|[\n\r]){0,40}?`,
		},
		{
			keywords: []string{"wrike"},
			expected: `(?i:wrike)(?:.|[\n\r]){0,40}?`,
		},
	}
	for _, tt := range tests {
		got := PrefixRegex(tt.keywords)
		if got != tt.expected {
			t.Errorf("PrefixRegex(%v) got: %v want: %v", tt.keywords, got, tt.expected)
		}
	}
}

func TestPrefixRegexKeywords(t *testing.T) {
	keywords := []string{"keyword1", "keyword2", "keyword3"}

	testCases := []struct {
		input    string
		expected bool
	}{
		{"keyword1 1234c4aabceeff4444442131444aab44", true},
		{"keyword1 1234567890ABCDEF1234567890ABBBCA", false},
		{"KEYWORD1 1234567890abcdef1234567890ababcd", true},
		{"KEYWORD1 1234567890ABCDEF1234567890ABdaba", false},
		{"keyword2 1234567890abcdef1234567890abeeff", true},
		{"keyword2 1234567890ABCDEF1234567890ABadbd", false},
		{"KEYWORD2 1234567890abcdef1234567890ababca", true},
		{"KEYWORD2 1234567890ABCDEF1234567890ABBBBs", false},
		{"keyword3 1234567890abcdef1234567890abccea", true},
		{"KEYWORD3 1234567890abcdef1234567890abaabb", true},
		{"keyword4 1234567890abcdef1234567890abzzzz", false},
		{"keyword3 1234567890ABCDEF1234567890AB", false},
		{"keyword4 1234567890ABCDEF1234567890AB", false},
	}

	keyPat := regexp.MustCompile(PrefixRegex(keywords) + `\b([0-9a-f]{32})\b`)

	for _, tc := range testCases {
		match := keyPat.MatchString(tc.input)
		if match != tc.expected {
			t.Errorf("Input: %s, Expected: %v, Got: %v", tc.input, tc.expected, match)
		}
	}
}

// The https://httpbin.org/uuid API returns a new UUID on each call.
// However, because we're using singleflight and issuing concurrent requests,
// all response bodies should be identical (only one actual HTTP request is made).
func TestVerificationRequest_Singleflight(t *testing.T) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Create two separate *http.Request instances pointing to same endpoint
	request1, err := http.NewRequest(http.MethodGet, "https://httpbin.org/uuid", http.NoBody)
	assert.NoError(t, err)

	request2, err := http.NewRequest(http.MethodGet, "https://httpbin.org/uuid", http.NoBody)
	assert.NoError(t, err)

	const key = "uuid-test"

	var wg sync.WaitGroup
	const goroutines = 5
	results := make([]*VerificationResult, goroutines)
	errors := make([]error, goroutines)

	// launch several concurrent goroutines all requesting the same identifier
	for i := range goroutines {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// alternate between two identical requests just to prove it doesn't matter
			req := request1
			if i%2 == 0 {
				req = request2
			}

			res, err := VerificationRequest(key, req, client)
			results[i] = res
			errors[i] = err
		}(i)
	}

	wg.Wait()

	for _, err := range errors {
		assert.NoError(t, err)
	}

	// all goroutines should get a non-nil result
	for _, r := range results {
		assert.NotNil(t, r)
	}

	// since singleflight coalesces concurrent calls, all results should have identical bodies
	firstBody := results[0].Body
	for i := 1; i < goroutines; i++ {
		assert.Equal(t, string(firstBody), string(results[i].Body),
			"Expected all results to share the same response body (one HTTP call only)")
	}

	t.Logf("All %d goroutines received the same UUID: %s", goroutines, string(firstBody))
}

func BenchmarkPrefixRegex(b *testing.B) {
	kws := []string{"securitytrails"}
	for i := 0; i < b.N; i++ {
		PrefixRegex(kws)
	}
}
