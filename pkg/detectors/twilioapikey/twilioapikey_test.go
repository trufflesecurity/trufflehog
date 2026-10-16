package twilioapikey

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validAPIKey   = "SKbddcfb88fake8f7c4d9aefake7de1fc5"
	invalidAPIKey = "SK_bddcfb88fake8f7c4d9aefake7de1fc"
	validSecret   = "k7JXtY3WBtUqthisisfakeZDqVcjZxYI"
	invalidSecret = "k6JXtY3WBtU$thisisfakeZDqVcjZxYI"
	keyword       = "twilio"
)

func TestTwilioAPIKey_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword twilio",
			input: fmt.Sprintf("%s token - '%s'\n%s token - '%s'\n", keyword, validAPIKey, keyword, validSecret),
			want:  []string{validAPIKey + validSecret},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("%s token - '%s'\n%s token - '%s'\n", keyword, invalidAPIKey, keyword, invalidSecret),
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

func TestTwilioAPIKey_SecretRedacted(t *testing.T) {
	d := Scanner{}

	results, err := d.FromData(
		context.Background(),
		false,
		[]byte(fmt.Sprintf("%s token - '%s'\n%s token - '%s'\n", keyword, validAPIKey, keyword, validSecret)))
	if err != nil {
		t.Errorf("error = %v", err)
		return
	}

	if len(results) == 0 {
		t.Errorf("did not receive result")
	}

	if results[0].Redacted != validSecret[:5]+"..." {
		t.Errorf("expected redacted secret to be '%s', got '%s'", validSecret[:5]+"...", results[0].Redacted)
	}
}

type errorTransport struct{ err error }

func (t errorTransport) RoundTrip(*http.Request) (*http.Response, error) { return nil, t.err }

func TestTwilioAPIKey_VerificationDeterminacy(t *testing.T) {
	data := []byte(fmt.Sprintf("twilio %s %s", validAPIKey, validSecret))

	tests := []struct {
		name                string
		client              *http.Client
		wantVerified        bool
		wantVerificationErr bool
	}{
		{
			name:                "authenticated rejection is determinate",
			client:              common.ConstantResponseHttpClient(http.StatusUnauthorized, ""),
			wantVerified:        false,
			wantVerificationErr: false,
		},
		{
			name:                "forbidden rejection is determinate",
			client:              common.ConstantResponseHttpClient(http.StatusForbidden, ""),
			wantVerified:        false,
			wantVerificationErr: false,
		},
		{
			name:                "success is determinate",
			client:              common.ConstantResponseHttpClient(http.StatusOK, `{"services":[{"friendly_name":"n","sid":"s","account_sid":"a"}]}`),
			wantVerified:        true,
			wantVerificationErr: false,
		},
		{
			name:                "rate limit is indeterminate",
			client:              common.ConstantResponseHttpClient(http.StatusTooManyRequests, ""),
			wantVerified:        false,
			wantVerificationErr: true,
		},
		{
			name:                "connection reset is indeterminate",
			client:              &http.Client{Transport: errorTransport{err: errors.New("read: connection reset by peer")}},
			wantVerified:        false,
			wantVerificationErr: true,
		},
		{
			name:                "timeout is indeterminate",
			client:              &http.Client{Transport: errorTransport{err: context.DeadlineExceeded}},
			wantVerified:        false,
			wantVerificationErr: true,
		},
		{
			name:                "server error is indeterminate",
			client:              common.ConstantResponseHttpClient(http.StatusInternalServerError, "{}"),
			wantVerified:        false,
			wantVerificationErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results, err := Scanner{client: test.client}.FromData(context.Background(), true, data)
			if err != nil {
				t.Fatalf("FromData() error = %v", err)
			}
			if len(results) != 1 {
				t.Fatalf("expected 1 result, got %d", len(results))
			}

			got := results[0]
			if got.Verified != test.wantVerified {
				t.Errorf("Verified = %v, want %v", got.Verified, test.wantVerified)
			}
			if (got.VerificationError() != nil) != test.wantVerificationErr {
				t.Errorf("VerificationError() = %v, want error presence %v",
					got.VerificationError(), test.wantVerificationErr)
			}
			if e := got.VerificationError(); e != nil && strings.Contains(e.Error(), validSecret) {
				t.Errorf("verification error leaks the credential: %v", e)
			}
		})
	}
}

func TestTwilioAPIKey_Verification_HappyPath(t *testing.T) {
	data := []byte(fmt.Sprintf("twilio %s %s", validAPIKey, validSecret))
	mockBody := `{"services":[{"friendly_name":"Production Service","sid":"VA123","account_sid":"AC123"}]}`

	client := common.ConstantResponseHttpClient(http.StatusOK, mockBody)
	results, err := Scanner{client: client}.FromData(context.Background(), true, data)
	if err != nil {
		t.Fatalf("FromData() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	got := results[0]
	if !got.Verified {
		t.Errorf("Verified = %v, want true", got.Verified)
	}
	if got.VerificationError() != nil {
		t.Errorf("VerificationError() = %v, want nil", got.VerificationError())
	}
	if got.ExtraData["account_sid"] != "AC123" {
		t.Errorf("ExtraData[account_sid] = %q, want 'AC123'", got.ExtraData["account_sid"])
	}
	if got.ExtraData["friendly_name"] != "Production Service" {
		t.Errorf("ExtraData[friendly_name] = %q, want 'Production Service'", got.ExtraData["friendly_name"])
	}
}

func TestTwilioAPIKey_EndpointCustomization(t *testing.T) {
	data := []byte(fmt.Sprintf("twilio %s %s", validAPIKey, validSecret))

	t.Run("default cloud endpoint", func(t *testing.T) {
		var requestedURL string
		client := &http.Client{
			Transport: common.FakeTransport{
				CreateResponse: func(req *http.Request) (*http.Response, error) {
					requestedURL = req.URL.String()
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{"services":[]}`)),
					}, nil
				},
			},
		}

		s := Scanner{client: client}
		results, err := s.FromData(context.Background(), true, data)
		if err != nil {
			t.Fatalf("FromData() error = %v", err)
		}
		if len(results) != 1 || !results[0].Verified {
			t.Fatalf("expected verified result, got %+v", results)
		}

		wantURL := "https://verify.twilio.com/v2/Services"
		if requestedURL != wantURL {
			t.Errorf("requestedURL = %q, want %q", requestedURL, wantURL)
		}
	})

	t.Run("configured custom endpoint", func(t *testing.T) {
		var requestedURL string
		client := &http.Client{
			Transport: common.FakeTransport{
				CreateResponse: func(req *http.Request) (*http.Response, error) {
					requestedURL = req.URL.String()
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{"services":[]}`)),
					}, nil
				},
			},
		}

		s := Scanner{client: client}
		if err := s.SetConfiguredEndpoints("https://authproxy.corp.internal"); err != nil {
			t.Fatalf("SetConfiguredEndpoints error = %v", err)
		}

		results, err := s.FromData(context.Background(), true, data)
		if err != nil {
			t.Fatalf("FromData() error = %v", err)
		}
		if len(results) != 1 || !results[0].Verified {
			t.Fatalf("expected verified result, got %+v", results)
		}

		wantURL := "https://authproxy.corp.internal/v2/Services"
		if requestedURL != wantURL {
			t.Errorf("requestedURL = %q, want %q", requestedURL, wantURL)
		}
	})

	t.Run("trailing slash normalization", func(t *testing.T) {
		var requestedURL string
		client := &http.Client{
			Transport: common.FakeTransport{
				CreateResponse: func(req *http.Request) (*http.Response, error) {
					requestedURL = req.URL.String()
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{"services":[]}`)),
					}, nil
				},
			},
		}

		s := Scanner{client: client}
		if err := s.SetConfiguredEndpoints("https://authproxy.corp.internal/"); err != nil {
			t.Fatalf("SetConfiguredEndpoints error = %v", err)
		}

		results, err := s.FromData(context.Background(), true, data)
		if err != nil {
			t.Fatalf("FromData() error = %v", err)
		}
		if len(results) != 1 || !results[0].Verified {
			t.Fatalf("expected verified result, got %+v", results)
		}

		wantURL := "https://authproxy.corp.internal/v2/Services"
		if requestedURL != wantURL {
			t.Errorf("requestedURL = %q, want %q", requestedURL, wantURL)
		}
	})

	t.Run("multi-endpoint first fails then succeeds clears error", func(t *testing.T) {
		client := &http.Client{
			Transport: common.FakeTransport{
				CreateResponse: func(req *http.Request) (*http.Response, error) {
					if strings.Contains(req.URL.Host, "fail-proxy") {
						return &http.Response{
							StatusCode: http.StatusInternalServerError,
							Body:       io.NopCloser(strings.NewReader("server error")),
						}, nil
					}
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{"services":[]}`)),
					}, nil
				},
			},
		}

		s := Scanner{client: client}
		if err := s.SetConfiguredEndpoints("https://fail-proxy.internal.net", "https://success-proxy.internal.net"); err != nil {
			t.Fatalf("SetConfiguredEndpoints error = %v", err)
		}

		results, err := s.FromData(context.Background(), true, data)
		if err != nil {
			t.Fatalf("FromData() error = %v", err)
		}
		if len(results) != 1 || !results[0].Verified {
			t.Fatalf("expected verified result, got %+v", results)
		}
		if results[0].VerificationError() != nil {
			t.Errorf("VerificationError() = %v, want nil on successful subsequent endpoint", results[0].VerificationError())
		}
	})
}
