//go:build detectors
// +build detectors

package detectors

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
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

// TestDoWithDedup_Singleflight verifies that concurrent DoWithDedup calls sharing the
// same detector type and credential are coalesced into one network call. Each request
// the server receives returns a distinct body, so all goroutines should observe the
// body from exactly one actual server-side request.
func TestDoWithDedup_Singleflight(t *testing.T) {
	var requestCount int32

	// The 20 ms sleep keeps the first request in-flight long enough for all
	// goroutines to call DoWithDedup before the result is ready.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := atomic.AddInt32(&requestCount, 1)
		time.Sleep(20 * time.Millisecond)
		fmt.Fprintf(w, `{"request":%d}`, n)
	}))
	defer server.Close()

	client := NewClientWithDedup(server.Client())

	const goroutines = 5
	bodies := make([]string, goroutines)
	statuses := make([]int, goroutines)
	errs := make([]error, goroutines)

	var wg sync.WaitGroup
	for i := range goroutines {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL, http.NoBody)
			if err != nil {
				errs[i] = err
				return
			}
			resp, err := DoWithDedup(client, detector_typepb.DetectorType_Meraki, "test-credential", req)
			if err != nil {
				errs[i] = err
				return
			}
			defer resp.Body.Close()
			var buf [512]byte
			n, _ := resp.Body.Read(buf[:])
			bodies[i] = string(buf[:n])
			statuses[i] = resp.StatusCode
		}(i)
	}
	wg.Wait()

	for _, err := range errs {
		assert.NoError(t, err)
	}
	for _, s := range statuses {
		assert.Equal(t, http.StatusOK, s)
	}

	// Exactly one HTTP request must have reached the server.
	assert.Equal(t, int32(1), atomic.LoadInt32(&requestCount),
		"singleflight should coalesce all concurrent calls into one HTTP request")

	// Every goroutine must see the same response body.
	for i := 1; i < goroutines; i++ {
		assert.Equal(t, bodies[0], bodies[i])
	}
}

func BenchmarkPrefixRegex(b *testing.B) {
	kws := []string{"securitytrails"}
	for i := 0; i < b.N; i++ {
		PrefixRegex(kws)
	}
}
