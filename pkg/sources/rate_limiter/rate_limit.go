package rate_limiter

import (
	"net/http"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

// APIRateLimit describes a single rate limit of an API.
//
// Implementation requirements:
//   - Be goroutine safe.
//   - .MaybeWait can *NEVER* sleep for a duration; it can only sleep _UNTIL_ a
//     time.
//
// Usage requirements:
// - APIRateLimits can only be used on a single API.
//   - An implementation might worry that it has to track request counts (etc.)
//     across different APIs, but this way it doesn't.
//   - This also means that APIRateLimits can be used in multiple
//     APIRateLimiters, as long as those APIRateLimiters are all only used
//     against the same API.
//
// For example, if an API has 2 endpoints, A with a 1r/s limit and another B
// with a 5r/s limit, and the API in general has a 500r/month limit, this
// configuration is possible:
//
// oneReqPerSecond := NewTokenBucketRateLimit(rate.Every(time.Second), 1)
// fiveReqsPerSecond := NewTokenBucketRateLimit(rate.Every(time.Second)/5, 1)
// fiveHundredReqsPerMonth := NewPersistentRateLimit(500, MONTH)
// rateLimiterA := NewAPIRateLimiter(oneReqPerSecond, fiveHundredReqsPerMonth)
// rateLimiterB := NewAPIRateLimiter(fiveReqsPerSecond, fiveHundredReqsPerMonth)
type APIRateLimit interface {
	// MaybeWait potentially sleeps in order to honor a rate limit, makes an HTTP
	// request, and returns the response or an error. Implementations should:
	// - Be goroutine safe
	// - Check if ctx has been canceled
	// - Not modify req
	// - *NEVER* sleep for a duration; only sleep _UNTIL_ a time
	//
	// APIRateLimiter calls the MaybeWait method of all its APIRateLimits in a
	// parallel loop. Any returned errors are combined into a single error, but
	// returning an error doesn't stop the APIRateLimiter from (maybe) waiting on
	// the other limits. Returning an error will prevent any further processing
	// of the HTTP request however (sending the request and updating the
	// RateLimts).
	MaybeWait(ctx context.Context, req *http.Request, now time.Time) error

	// Update updates the state of a APIRateLimit from an HTTP response, e.g. by
	// checking for HTTP status 429 or reading a RetryAfter header
	// - Be goroutine safe
	// - Check if ctx has been canceled
	// - Not modify res
	//
	// Services may only return rate limits as durations, e.g. `RetryAfter: 60`
	// (units are in seconds, cf. RFC-6585), which is incompatible with MaybeWait
	// as it can't wait a duration like 60 seconds, it can only wait until a
	// time. Therefore it's incumbent on Update to handle this somehow, generally
	// by converting the duration into a time in the future using the `now` arg.
	// It's also recommended to pad the time somewhat.
	//
	// APIRateLimiter calls the Update method of all its APIRateLimits in a
	// parallel loop. Any returned errors are combined into a single error, but
	// returning an error doesn't stop the APIRateLimiter from updating the other
	// limits.
	Update(ctx context.Context, res *http.Response, now time.Time) error
}
