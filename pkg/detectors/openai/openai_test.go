package openai

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

// The default client must retry transient failures so a single slow or
// failed OpenAI API response does not record an indeterminate verification
// result (CSM-2131).
func TestOpenAI_DefaultClientRetriesTransientErrors(t *testing.T) {
	var requests atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	res, err := defaultClient.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		t.Errorf("expected retries to reach a 200 response, got %d", res.StatusCode)
	}
	if got := requests.Load(); got != 3 {
		t.Errorf("expected 3 attempts (initial + 2 retries), got %d", got)
	}
}

// When the API never recovers, the client must give up after the configured
// retry budget (initial attempt + 2 retries) and surface the failure rather
// than retrying indefinitely.
func TestOpenAI_DefaultClientGivesUpAfterRetryBudget(t *testing.T) {
	var requests atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	res, err := defaultClient.Do(req)
	if res != nil {
		defer func() { _ = res.Body.Close() }()
	}

	if err == nil && res.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected exhausted retries to surface the failure, got status %d with no error", res.StatusCode)
	}
	if got := requests.Load(); got != 3 {
		t.Errorf("expected 3 attempts (initial + 2 retries), got %d", got)
	}
}

func TestOpenAI_DoesNotMatchAdminKeys(t *testing.T) {
	d := Scanner{}
	adminKey := `OPENAI_ADMIN_KEY = "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"`

	results, err := d.FromData(context.Background(), false, []byte(adminKey))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 0 {
		t.Errorf("openai detector should not match admin keys, but got %d results", len(results))
	}
}

func TestOpenAI_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "user API key",
			input: "openai.api-key: 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",
			want:  []string{"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"},
		},
		{
			name:  "project API key",
			input: `OPENAI_API_KEY = "sk-proj-mpjtr05CFsJqs4TAeKlCT3BlbkFJsh1KtN0SUjTPeJiagE8K"`,
			want:  []string{"sk-proj-mpjtr05CFsJqs4TAeKlCT3BlbkFJsh1KtN0SUjTPeJiagE8K"},
		},
		{
			name:  "service account API key",
			input: `OPENAI_API_KEY = "sk-service-account-name-Ofbtr05CFsJqs4TAeKlCT3BlbkFJsh1KtN0SUjTPeJiaglyC"`,
			want:  []string{"sk-service-account-name-Ofbtr05CFsJqs4TAeKlCT3BlbkFJsh1KtN0SUjTPeJiaglyC"},
		},
		{
			name:  "newer user API key",
			input: `"OPENAI_API_KEY = "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"`,
			want:  []string{"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"},
		},
		{
			name:  "newer service account API key",
			input: `OPENAI_API_KEY = "sk-svcacct-IUXtc5gIZK-2cBfB-nTgEWbD8mi-fi-gc20oGtq8ve51sET3BlbkFJCg8iQkCVz_nmE_q1dCWlMpemoaoMqHzQ6D-FnWGqlz4C8A"`,
			want:  []string{"sk-svcacct-IUXtc5gIZK-2cBfB-nTgEWbD8mi-fi-gc20oGtq8ve51sET3BlbkFJCg8iQkCVz_nmE_q1dCWlMpemoaoMqHzQ6D-FnWGqlz4C8A"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			detectorMatches := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(detectorMatches) == 0 {
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
