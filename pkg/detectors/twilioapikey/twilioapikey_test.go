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

	"github.com/go-logr/zapr"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
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

func TestTwilioAPIKey_CloudEndpoint_ReturnsFullURI(t *testing.T) {
	want := "https://verify.twilio.com/v2/Services"
	got := Scanner{}.CloudEndpoint()
	if got != want {
		t.Errorf("Scanner{}.CloudEndpoint() = %q, want %q", got, want)
	}
}

func TestTwilioAPIKey_DefaultVerification_HitsFullURI(t *testing.T) {
	data := []byte(fmt.Sprintf("twilio %s %s", validAPIKey, validSecret))
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
}

func TestTwilioAPIKey_CustomEndpoint_ExactURIPreserved(t *testing.T) {
	data := []byte(fmt.Sprintf("twilio %s %s", validAPIKey, validSecret))
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
	if err := s.SetConfiguredEndpoints("https://authproxy.corp.internal/v2/Services"); err != nil {
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
}

func TestTwilioAPIKey_CustomEndpoint_CustomPathPreserved(t *testing.T) {
	data := []byte(fmt.Sprintf("twilio %s %s", validAPIKey, validSecret))
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
	if err := s.SetConfiguredEndpoints("https://mock-verifier.internal/api/verify"); err != nil {
		t.Fatalf("SetConfiguredEndpoints error = %v", err)
	}

	results, err := s.FromData(context.Background(), true, data)
	if err != nil {
		t.Fatalf("FromData() error = %v", err)
	}
	if len(results) != 1 || !results[0].Verified {
		t.Fatalf("expected verified result, got %+v", results)
	}

	wantURL := "https://mock-verifier.internal/api/verify"
	if requestedURL != wantURL {
		t.Errorf("requestedURL = %q, want %q", requestedURL, wantURL)
	}
}

func TestTwilioAPIKey_CustomEndpoint_MissingPathEmitsWarningAndHitsRoot(t *testing.T) {
	data := []byte(fmt.Sprintf("twilio %s %s", validAPIKey, validSecret))

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

	var loggedMessages []string
	logger := zapr.NewLogger(zaptest.NewLogger(t, zaptest.WrapOptions(zap.Hooks(func(e zapcore.Entry) error {
		loggedMessages = append(loggedMessages, e.Message)
		return nil
	}))))

	ctx := logContext.WithLogger(context.Background(), logger)

	s := Scanner{client: client}
	if err := s.SetConfiguredEndpoints("https://authproxy.corp.internal"); err != nil {
		t.Fatalf("SetConfiguredEndpoints error = %v", err)
	}

	results, err := s.FromData(ctx, true, data)
	if err != nil {
		t.Fatalf("FromData() error = %v", err)
	}
	if len(results) != 1 || !results[0].Verified {
		t.Fatalf("expected verified result, got %+v", results)
	}

	if requestedURL != "https://authproxy.corp.internal" && requestedURL != "https://authproxy.corp.internal/" {
		t.Errorf("requestedURL = %q, want https://authproxy.corp.internal or https://authproxy.corp.internal/", requestedURL)
	}

	var foundWarning bool
	for _, msg := range loggedMessages {
		if strings.Contains(msg, "missing a path portion") {
			foundWarning = true
			break
		}
	}
	if !foundWarning {
		t.Errorf("expected log containing 'missing a path portion', got: %v", loggedMessages)
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

	t.Run("configured custom endpoint exact uri preserved", func(t *testing.T) {
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
		if err := s.SetConfiguredEndpoints("https://authproxy.corp.internal/v2/Services"); err != nil {
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
		if err := s.SetConfiguredEndpoints("https://fail-proxy.internal.net/v2/Services", "https://success-proxy.internal.net/v2/Services"); err != nil {
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

	t.Run("configured custom endpoint with custom path preserved", func(t *testing.T) {
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
		if err := s.SetConfiguredEndpoints("https://mock-verifier.internal/api/verify"); err != nil {
			t.Fatalf("SetConfiguredEndpoints error = %v", err)
		}

		results, err := s.FromData(context.Background(), true, data)
		if err != nil {
			t.Fatalf("FromData() error = %v", err)
		}
		if len(results) != 1 || !results[0].Verified {
			t.Fatalf("expected verified result, got %+v", results)
		}

		wantURL := "https://mock-verifier.internal/api/verify"
		if requestedURL != wantURL {
			t.Errorf("requestedURL = %q, want %q", requestedURL, wantURL)
		}
	})

	t.Run("configured custom endpoint targeting Core Accounts.json API", func(t *testing.T) {
		var requestedURL string
		client := &http.Client{
			Transport: common.FakeTransport{
				CreateResponse: func(req *http.Request) (*http.Response, error) {
					requestedURL = req.URL.String()
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{"accounts":[{"sid":"AC12345678901234567890123456789012","friendly_name":"Main Account","status":"active","type":"Full"}]}`)),
					}, nil
				},
			},
		}

		s := Scanner{client: client}
		if err := s.SetConfiguredEndpoints("https://api.twilio.com/2010-04-01/Accounts.json"); err != nil {
			t.Fatalf("SetConfiguredEndpoints error = %v", err)
		}

		results, err := s.FromData(context.Background(), true, data)
		if err != nil {
			t.Fatalf("FromData() error = %v", err)
		}
		if len(results) != 1 || !results[0].Verified {
			t.Fatalf("expected verified result, got %+v", results)
		}

		wantURL := "https://api.twilio.com/2010-04-01/Accounts.json"
		if requestedURL != wantURL {
			t.Errorf("requestedURL = %q, want %q", requestedURL, wantURL)
		}

		if results[0].ExtraData["account_sid"] != "AC12345678901234567890123456789012" {
			t.Errorf("account_sid = %q, want AC12345678901234567890123456789012", results[0].ExtraData["account_sid"])
		}
		if results[0].ExtraData["friendly_name"] != "Main Account" {
			t.Errorf("friendly_name = %q, want Main Account", results[0].ExtraData["friendly_name"])
		}
		if results[0].ExtraData["status"] != "active" {
			t.Errorf("status = %q, want active", results[0].ExtraData["status"])
		}
		if results[0].ExtraData["type"] != "Full" {
			t.Errorf("type = %q, want Full", results[0].ExtraData["type"])
		}
	})

	t.Run("configured custom endpoint with trailing slash on custom path", func(t *testing.T) {
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
		if err := s.SetConfiguredEndpoints("https://mock-verifier.internal/api/verify/"); err != nil {
			t.Fatalf("SetConfiguredEndpoints error = %v", err)
		}

		results, err := s.FromData(context.Background(), true, data)
		if err != nil {
			t.Fatalf("FromData() error = %v", err)
		}
		if len(results) != 1 || !results[0].Verified {
			t.Fatalf("expected verified result, got %+v", results)
		}

		if !strings.HasPrefix(requestedURL, "https://mock-verifier.internal/api/verify") {
			t.Errorf("requestedURL = %q, want prefix https://mock-verifier.internal/api/verify", requestedURL)
		}
	})

	t.Run("response body read error returns verification error", func(t *testing.T) {
		client := &http.Client{
			Transport: common.FakeTransport{
				CreateResponse: func(req *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(&errReader{err: errors.New("read error: connection reset")}),
					}, nil
				},
			},
		}

		s := Scanner{client: client}
		results, err := s.FromData(context.Background(), true, data)
		if err != nil {
			t.Fatalf("FromData() error = %v", err)
		}
		if len(results) != 1 {
			t.Fatalf("expected 1 result, got %d", len(results))
		}
		if results[0].Verified {
			t.Errorf("Verified = true, want false when response body read fails")
		}
		if results[0].VerificationError() == nil {
			t.Errorf("VerificationError() = nil, want non-nil on read error")
		}
	})

	t.Run("generic 200 OK without Twilio payload returns unverified", func(t *testing.T) {
		client := &http.Client{
			Transport: common.FakeTransport{
				CreateResponse: func(req *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{"status":"ok","message":"Welcome to Auth Proxy Portal"}`)),
					}, nil
				},
			},
		}

		s := Scanner{client: client}
		if err := s.SetConfiguredEndpoints("https://proxy.internal/"); err != nil {
			t.Fatalf("SetConfiguredEndpoints error = %v", err)
		}

		results, err := s.FromData(context.Background(), true, data)
		if err != nil {
			t.Fatalf("FromData() error = %v", err)
		}
		if len(results) != 1 {
			t.Fatalf("expected 1 result, got %d", len(results))
		}
		if results[0].Verified {
			t.Errorf("Verified = true, want false on generic non-Twilio 200 OK response")
		}
	})

	t.Run("userinfo password is redacted in warning log", func(t *testing.T) {
		var loggedMessages []string
		logger := zapr.NewLogger(zaptest.NewLogger(t, zaptest.WrapOptions(zap.Hooks(func(e zapcore.Entry) error {
			loggedMessages = append(loggedMessages, e.Message)
			return nil
		}))))

		ctx := logContext.WithLogger(context.Background(), logger)

		client := &http.Client{
			Transport: common.FakeTransport{
				CreateResponse: func(req *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{"services":[{"friendly_name":"Test","account_sid":"AC12345"}]}`)),
					}, nil
				},
			},
		}

		s := Scanner{client: client}
		if err := s.SetConfiguredEndpoints("https://user:secret123@authproxy.corp.internal"); err != nil {
			t.Fatalf("SetConfiguredEndpoints error = %v", err)
		}

		results, err := s.FromData(ctx, true, data)
		if err != nil {
			t.Fatalf("FromData() error = %v", err)
		}
		if len(results) != 1 || !results[0].Verified {
			t.Fatalf("expected verified result, got %+v", results)
		}

		var foundRedacted bool
		for _, msg := range loggedMessages {
			if strings.Contains(msg, "secret123") {
				t.Fatalf("found unredacted secret in log message: %q", msg)
			}
			if strings.Contains(msg, "xxxxx") {
				foundRedacted = true
			}
		}
		if !foundRedacted {
			t.Errorf("expected log message with redacted userinfo, got: %v", loggedMessages)
		}
	})

	t.Run("useCloudEndpoint false skips verification without outbound network requests", func(t *testing.T) {
		var requestCount int
		client := &http.Client{
			Transport: common.FakeTransport{
				CreateResponse: func(req *http.Request) (*http.Response, error) {
					requestCount++
					return nil, errors.New("outbound network call made when cloud disabled")
				},
			},
		}

		s := Scanner{client: client}
		s.SetCloudEndpoint(s.CloudEndpoint())
		s.UseCloudEndpoint(false)

		results, err := s.FromData(context.Background(), true, data)
		if err != nil {
			t.Fatalf("FromData() error = %v", err)
		}
		if len(results) != 1 {
			t.Fatalf("expected 1 result, got %d", len(results))
		}
		if results[0].Verified {
			t.Errorf("Verified = true, want false when cloud endpoint is disabled")
		}
		if requestCount != 0 {
			t.Errorf("requestCount = %d, want 0 network calls when cloud endpoint is disabled", requestCount)
		}
	})
}

func TestTwilioAPIKey_Verification_ClosedAccount_AccountsList(t *testing.T) {
	data := []byte(fmt.Sprintf("twilio %s %s", validAPIKey, validSecret))
	mockBody := `{"accounts":[{"sid":"AC12345678901234567890123456789012","friendly_name":"Old Account","status":"closed","type":"Full"}]}`

	client := common.ConstantResponseHttpClient(http.StatusOK, mockBody)
	s := Scanner{client: client}
	if err := s.SetConfiguredEndpoints("https://api.twilio.com/2010-04-01/Accounts.json"); err != nil {
		t.Fatalf("SetConfiguredEndpoints error = %v", err)
	}

	results, err := s.FromData(context.Background(), true, data)
	if err != nil {
		t.Fatalf("FromData() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	got := results[0]
	if got.Verified {
		t.Errorf("Verified = %v, want false for closed account", got.Verified)
	}
	if got.VerificationError() != nil {
		t.Errorf("VerificationError() = %v, want nil", got.VerificationError())
	}
	if got.ExtraData["account_sid"] != "AC12345678901234567890123456789012" {
		t.Errorf("account_sid = %q, want 'AC12345678901234567890123456789012'", got.ExtraData["account_sid"])
	}
	if got.ExtraData["status"] != "closed" {
		t.Errorf("status = %q, want 'closed'", got.ExtraData["status"])
	}
	if got.ExtraData["friendly_name"] != "Old Account" {
		t.Errorf("friendly_name = %q, want 'Old Account'", got.ExtraData["friendly_name"])
	}
}

func TestTwilioAPIKey_Verification_ClosedAccount_SingleAccount(t *testing.T) {
	data := []byte(fmt.Sprintf("twilio %s %s", validAPIKey, validSecret))
	mockBody := `{"sid":"AC12345678901234567890123456789012","friendly_name":"Closed Single Account","status":"closed","type":"Full"}`

	client := common.ConstantResponseHttpClient(http.StatusOK, mockBody)
	s := Scanner{client: client}
	if err := s.SetConfiguredEndpoints("https://api.twilio.com/2010-04-01/Accounts/AC12345678901234567890123456789012.json"); err != nil {
		t.Fatalf("SetConfiguredEndpoints error = %v", err)
	}

	results, err := s.FromData(context.Background(), true, data)
	if err != nil {
		t.Fatalf("FromData() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	got := results[0]
	if got.Verified {
		t.Errorf("Verified = %v, want false for closed single account", got.Verified)
	}
	if got.VerificationError() != nil {
		t.Errorf("VerificationError() = %v, want nil", got.VerificationError())
	}
	if got.ExtraData["account_sid"] != "AC12345678901234567890123456789012" {
		t.Errorf("account_sid = %q, want 'AC12345678901234567890123456789012'", got.ExtraData["account_sid"])
	}
	if got.ExtraData["status"] != "closed" {
		t.Errorf("status = %q, want 'closed'", got.ExtraData["status"])
	}
}

func TestTwilioAPIKey_Verification_SuspendedAccount(t *testing.T) {
	data := []byte(fmt.Sprintf("twilio %s %s", validAPIKey, validSecret))
	mockBody := `{"accounts":[{"sid":"AC12345678901234567890123456789012","friendly_name":"Suspended Account","status":"suspended","type":"Full"}]}`

	client := common.ConstantResponseHttpClient(http.StatusOK, mockBody)
	s := Scanner{client: client}
	if err := s.SetConfiguredEndpoints("https://api.twilio.com/2010-04-01/Accounts.json"); err != nil {
		t.Fatalf("SetConfiguredEndpoints error = %v", err)
	}

	results, err := s.FromData(context.Background(), true, data)
	if err != nil {
		t.Fatalf("FromData() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	got := results[0]
	if !got.Verified {
		t.Errorf("Verified = %v, want true for suspended account", got.Verified)
	}
	if got.VerificationError() != nil {
		t.Errorf("VerificationError() = %v, want nil", got.VerificationError())
	}
	if got.ExtraData["status"] != "suspended" {
		t.Errorf("status = %q, want 'suspended'", got.ExtraData["status"])
	}
}

func TestTwilioAPIKey_Verification_ClosedAccount_CaseInsensitive(t *testing.T) {
	data := []byte(fmt.Sprintf("twilio %s %s", validAPIKey, validSecret))
	mockBody := `{"sid":"AC12345678901234567890123456789012","status":"CLOSED"}`

	client := common.ConstantResponseHttpClient(http.StatusOK, mockBody)
	s := Scanner{client: client}
	if err := s.SetConfiguredEndpoints("https://api.twilio.com/2010-04-01/Accounts/AC12345678901234567890123456789012.json"); err != nil {
		t.Fatalf("SetConfiguredEndpoints error = %v", err)
	}

	results, err := s.FromData(context.Background(), true, data)
	if err != nil {
		t.Fatalf("FromData() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Verified {
		t.Errorf("Verified = %v, want false for status 'CLOSED'", results[0].Verified)
	}
	if results[0].VerificationError() != nil {
		t.Errorf("VerificationError() = %v, want nil", results[0].VerificationError())
	}
}

func TestTwilioAPIKey_ClosedAccount_StopsProbingAndClearsPriorError(t *testing.T) {
	data := []byte(fmt.Sprintf("twilio %s %s", validAPIKey, validSecret))
	var verifyCalls int
	client := &http.Client{
		Transport: common.FakeTransport{
			CreateResponse: func(req *http.Request) (*http.Response, error) {
				switch {
				case strings.Contains(req.URL.Host, "failing"):
					return &http.Response{
						StatusCode: http.StatusInternalServerError,
						Body:       io.NopCloser(strings.NewReader(`{"message":"internal error"}`)),
					}, nil
				case strings.Contains(req.URL.Host, "closed"):
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{"accounts":[{"sid":"AC12345678901234567890123456789012","status":"closed"}]}`)),
					}, nil
				case strings.Contains(req.URL.Host, "verify"):
					verifyCalls++
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{"services":[{"friendly_name":"TestService","sid":"VA123"}]}`)),
					}, nil
				default:
					return nil, fmt.Errorf("unexpected request to %s", req.URL.String())
				}
			},
		},
	}

	s := Scanner{client: client}
	if err := s.SetConfiguredEndpoints(
		"https://failing.internal",
		"https://closed.internal",
		"https://verify.internal",
	); err != nil {
		t.Fatalf("SetConfiguredEndpoints error = %v", err)
	}

	results, err := s.FromData(context.Background(), true, data)
	if err != nil {
		t.Fatalf("FromData() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	if verifyCalls != 0 {
		t.Errorf("verifyCalls = %d, want 0 (probing should stop at closed account)", verifyCalls)
	}
	if results[0].Verified {
		t.Errorf("Verified = true, want false for closed account")
	}
	if results[0].VerificationError() != nil {
		t.Errorf("VerificationError() = %v, want nil (prior endpoint error should be cleared)", results[0].VerificationError())
	}
	if results[0].ExtraData["status"] != "closed" {
		t.Errorf("status = %q, want 'closed'", results[0].ExtraData["status"])
	}
}

type errReader struct {
	err error
}

func (e *errReader) Read(p []byte) (n int, err error) {
	return 0, e.err
}
