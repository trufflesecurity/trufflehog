package azuredevopspersonalaccesstoken

import (
	"context"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKeyPatScanner_EndToEnd(t *testing.T) {
	scanner := Scanner{}

	// Mock HTTP client to simulate successful verification
	scanner.client = &http.Client{
		Transport: &mockTransport{
			statusCode: 200,
		},
	}

	// Test case with a valid key
	data := []byte("azure token: abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz")
	results, err := scanner.FromData(context.Background(), true, data)
	assert.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz", string(results[0].Raw))
	assert.True(t, results[0].Verified)

	// Test case with no key
	data = []byte("no key here")
	results, err = scanner.FromData(context.Background(), true, data)
	assert.NoError(t, err)
	assert.Len(t, results, 0)
}

type mockTransport struct {
	statusCode int
}

func (t *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: t.statusCode,
		Body:       ioutil.NopCloser(strings.NewReader("")),
	}, nil
}
