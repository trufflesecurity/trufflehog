// verify.go provides the shared credential verification loop used by
// both the inline custom detector path (createResults) and the engine
// OAuth verification path (OAuthVerify). A single implementation
// ensures consistent behavior: body template resolution, header
// application, OAuth client wrapping, status code interpretation,
// endpoint fallback, response capture, and outcome logging.

package custom_detectors

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"golang.org/x/oauth2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
)

// VerifyEndpoint holds everything needed to attempt verification against
// a single endpoint. Both the inline custom detector path and the engine
// OAuth path populate this from their respective config sources.
type VerifyEndpoint struct {
	URL           string
	Headers       []string
	SuccessRanges []string
	RotatedRanges []string
	// Body is the customer-defined request body template with $token
	// references. Nil means use the caller-provided defaultBody.
	Body map[string]string
	// TokenSource supplies OAuth2 Bearer tokens for this endpoint.
	// Nil means no OAuth wrapping — the request is sent as-is.
	TokenSource oauth2.TokenSource
}

// VerifyOutcome captures the result of attempting verification across
// one or more endpoints.
type VerifyOutcome struct {
	// Verified is true when the credential was confirmed active.
	Verified bool
	// Definitive is true when at least one endpoint gave a conclusive
	// answer (verified or not). False means no endpoint matched any
	// configured range — the caller should treat this as an error.
	Definitive bool
	// Attempted is true when at least one endpoint was tried. When
	// Attempted is true but Definitive is false, verification was
	// configured but every endpoint failed (transport error, token
	// acquisition failure, etc.). Callers should surface this as a
	// verification error rather than silently reporting "unverified."
	Attempted bool
	// RangesInEffect is true when at least one endpoint had
	// successRanges or rotatedRanges configured. When true and
	// Definitive is false, it means a range-based endpoint failed
	// to match — a configuration or server error. When false and
	// Definitive is false, no endpoint returned 200 in default mode
	// — "not verified" but not an error.
	RangesInEffect bool
	// StatusCode is the HTTP status from the endpoint that produced
	// the definitive answer, or the last status code seen.
	StatusCode int
	// RespBody holds the response body from the definitive endpoint
	// (truncated to maxResponseLen). Empty when no definitive answer.
	RespBody string
}

// maxRespBodyLen caps the response body captured in VerifyOutcome so
// large responses don't bloat result metadata.
const maxRespBodyLen = 200

// VerifyCredential tries each endpoint in order until a definitive
// answer is reached. It handles OAuth2 client wrapping, body template
// resolution, header application, status code interpretation (default
// and range-based with single-range inference), endpoint fallback,
// response body capture, and outcome logging under the caller's trace.
//
// The vars map supplies runtime values for $token references in body
// templates ($secret, $detector_type, $detector_name). The $token var
// is resolved per-endpoint from the endpoint's TokenSource.
//
// When no endpoint produces a definitive answer, Verified is false and
// Definitive is false — the caller should set a verification error.
func VerifyCredential(
	ctx context.Context,
	baseClient *http.Client,
	endpoints []VerifyEndpoint,
	defaultBody []byte,
	vars map[string]string,
) VerifyOutcome {
	if baseClient == nil {
		baseClient = common.SaneHttpClient()
	}

	var (
		outcome        VerifyOutcome
		rangesInEffect bool
		traced         bool
		lastCtx        logContext.Context
	)

	for _, ep := range endpoints {
		if common.IsDone(ctx) {
			return outcome
		}

		outcome.Attempted = true

		// Per-endpoint context enrichment: if this endpoint has an
		// OAuth2 token source carrying a trace, set it on the context
		// so all downstream log messages inherit the correlation ID.
		epCtx := logContext.AddLogger(ctx)
		if ts, ok := ep.TokenSource.(*detectors.TracedTokenSource); ok {
			epCtx = ts.EnrichContext(epCtx)
			traced = true
		}
		logger := epCtx.Logger()

		// Build the request body. When the endpoint has a custom
		// template, resolve $token references. The $token var is
		// fetched per-endpoint since each can have its own token source.
		body := defaultBody
		if len(ep.Body) > 0 {
			epVars := make(map[string]string, len(vars)+1)
			for k, v := range vars {
				epVars[k] = v
			}
			if ep.TokenSource != nil {
				tok, err := ep.TokenSource.Token()
				if err != nil {
					logger.Error(err, "failed to acquire token for body template",
						"endpoint", ep.URL,
					)
					continue
				}
				epVars["$token"] = tok.AccessToken
			}
			resolved, err := ResolveRequestBody(ep.Body, epVars)
			if err != nil {
				logger.Error(err, "failed to resolve request body template",
					"endpoint", ep.URL,
				)
				continue
			}
			body = resolved
		}

		req, err := http.NewRequestWithContext(epCtx, "POST", ep.URL, bytes.NewReader(body))
		if err != nil {
			logger.Error(err, "failed to create verify request",
				"endpoint", ep.URL,
			)
			continue
		}

		// Apply customer-defined headers, then default Content-Type.
		// When no explicit Content-Type is set, unmarshal the body to
		// distinguish structured JSON (objects/arrays) from raw values.
		// Bare primitives like quoted strings or numbers are technically
		// valid JSON but not what verification endpoints expect as a
		// JSON payload, so they get text/plain.
		for _, h := range ep.Headers {
			key, value, found := strings.Cut(h, ":")
			if !found {
				continue
			}
			req.Header.Add(key, strings.TrimLeft(value, "\t\n\v\f\r "))
		}
		if req.Header.Get("Content-Type") == "" {
			var structured interface{}
			if json.Unmarshal(body, &structured) == nil {
				switch structured.(type) {
				case map[string]interface{}, []interface{}:
					req.Header.Set("Content-Type", "application/json")
				default:
					req.Header.Set("Content-Type", "text/plain")
				}
			} else {
				req.Header.Set("Content-Type", "text/plain")
			}
		}

		// If this endpoint has OAuth2 auth, wrap the base client with
		// oauth2.Transport so the Bearer token is added transparently.
		client := baseClient
		if ep.TokenSource != nil {
			logger.Info("sending OAuth2-authenticated verify request",
				"endpoint", ep.URL,
			)
			client = oauth2.NewClient(
				context.WithValue(epCtx, oauth2.HTTPClient, baseClient),
				ep.TokenSource,
			)
		}

		resp, err := client.Do(req)
		if err != nil {
			logger.Error(err, "verify request failed",
				"endpoint", ep.URL,
			)
			continue
		}
		defer func() {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}()

		lastCtx = epCtx
		outcome.StatusCode = resp.StatusCode

		// ── Status code interpretation ───────────────────────────
		//
		// The deferred drain+close handles cleanup on all paths.
		// Success paths do a capped read to capture the response
		// body; all other paths leave the body for the defer.
		successRanges := ep.SuccessRanges
		rotatedRanges := ep.RotatedRanges

		if len(successRanges) == 0 && len(rotatedRanges) == 0 {
			// Default: no ranges configured, 200 means verified.
			// Non-200 is a meaningful "not verified" — mark definitive
			// so a prior ranged verifier's rangesInEffect flag doesn't
			// cause a spurious error, then try the next endpoint.
			if resp.StatusCode == http.StatusOK {
				outcome.Verified = true
				outcome.Definitive = true
				b, _ := io.ReadAll(io.LimitReader(resp.Body, maxRespBodyLen))
				outcome.RespBody = string(b)
				break
			}
			outcome.Definitive = true
			continue
		}

		rangesInEffect = true
		outcome.RangesInEffect = true
		bothConfigured := len(successRanges) > 0 && len(rotatedRanges) > 0

		if StatusCodeMatchesRanges(resp.StatusCode, successRanges) {
			outcome.Verified = true
			outcome.Definitive = true
			b, _ := io.ReadAll(io.LimitReader(resp.Body, maxRespBodyLen))
			outcome.RespBody = string(b)
			break
		}

		if StatusCodeMatchesRanges(resp.StatusCode, rotatedRanges) {
			outcome.Definitive = true
			break
		}

		// Single-range inference: when only one side is configured and
		// the status didn't match, infer the opposite state.
		if !bothConfigured {
			outcome.Definitive = true
			if len(rotatedRanges) > 0 {
				// Only rotatedRanges configured, didn't match → verified.
				outcome.Verified = true
				b, _ := io.ReadAll(io.LimitReader(resp.Body, maxRespBodyLen))
				outcome.RespBody = string(b)
			}
			break
		}

		// Both configured but neither matched — try the next endpoint.
	}

	// Outcome logging under the caller's trace context so the full
	// lifecycle (token acquisition → verify → result) is visible.
	if traced && lastCtx != nil {
		logger := lastCtx.Logger()
		if outcome.Attempted && !outcome.Definitive {
			logger.Error(nil, "OAuth2 verification inconclusive; no endpoint gave a definitive answer",
				"status_code", outcome.StatusCode,
				"ranges_in_effect", rangesInEffect,
			)
		} else if outcome.Verified {
			logger.Info("OAuth2 verification succeeded",
				"status_code", outcome.StatusCode,
			)
		} else {
			logger.Info("OAuth2 verification completed, credential not verified",
				"status_code", outcome.StatusCode,
			)
		}
	}

	return outcome
}
