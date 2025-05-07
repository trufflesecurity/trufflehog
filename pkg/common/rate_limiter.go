package common

import (
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

// RateLimiter provides a facility for honoring an API's rate limits. To use
// it:
// - Create a RateLimiter with its RateLimits
// - Call .Do instead of what you would normally call to make a request
// - Process the response (returned from .Do) as normal
//
// A RateLimiter should only be used on at most 1 API. If you're making
// requests to multiple APIs, use multiple RateLimiters.
type RateLimiter struct {
	limits []RateLimit
}

// RateLimit describes a single rate limit of an API.
//
// Implementation requirements:
//   - Be goroutine safe.
//   - .Execute can *NEVER* sleep for a duration; it can only sleep _UNTIL_ a
//     time.
//
// Usage requirements:
// - RateLimits can only be used on at most 1 API
//   - An implementation might worry that it has to track request counts (etc.)
//     across different APIs, but this way it doesn't.
//   - This also means that RateLimits can be used in multiple RateLimiters, as
//     long as those RateLimiters are all only used against the same API.
//
// For example, if an API has 2 endpoints, A with a 1r/s limit and another B
// with a 5r/s limit, and the API in general has a 500r/month limit, this
// configuration is possible:
//
// oneReqPerSecond := NewTokenBucketRateLimit(rate.Every(time.Second), 1)
// fiveReqsPerSecond := NewTokenBucketRateLimit(rate.Every(time.Second)/5, 1)
// fiveHundredReqsPerMonth := NewPersistentRateLimit(500, MONTH)
// rateLimiterA := NewRateLimiter(oneReqPerSecond, fiveHundredReqsPerMonth)
// rateLimiterB := NewRateLimiter(fiveReqsPerSecond, fiveHundredReqsPerMonth)
type RateLimit interface {
	// MaybeWait potentially sleeps in order to honor a rate limit, makes an HTTP
	// request, and returns the response or an error. Implementations should:
	// - Be goroutine safe
	// - Check if ctx has been canceled
	// - Not modify req
	// - *NEVER* sleep for a duration; only sleep _UNTIL_ a time
	//
	// RateLimiter calls the MaybeWait method of all its RateLimits in a serial
	// loop. Any returned errors are combined into a single error, but returning
	// an error doesn't stop the RateLimiter from (maybe) waiting on the other
	// limits. Returning an error will prevent any further processing of the HTTP
	// request however (sending the request and updating the RateLimts).
	MaybeWait(ctx context.Context, req *http.Request, now time.Time) error

	// Update updates the state of a RateLimit from an HTTP response, e.g. by
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
	// RateLimiter calls the Update method of all its RateLimits in a _parallel_
	// loop. Any returned errors are combined into a single error, but returning
	// an error doesn't stop the RateLimiter from updating the other limits.
	Update(ctx context.Context, res *http.Response, now time.Time) error
}

// Returns a new rate limiter with the given limits.
func NewRateLimiter(limits ...RateLimit) *RateLimiter {
	return &RateLimiter{limits: limits}
}

// Makes an HTTP request to an API while honoring its limits.
func (rl *RateLimiter) Do(
	ctx context.Context,
	req *http.Request,
	makeRequest func() (*http.Response, error),
) (*http.Response, error) {
	if len(rl.limits) == 0 {
		return makeRequest()
	}

	now := time.Now()

	var maybeWaitError error = nil

	for i, lim := range rl.limits {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		// [NOTE] It's perhaps better to do this asynchronously, in case an errant
		//		    limit sleeps for a duration instead of until a specific time, but
		//			  I haven't thought through that.
		if err := lim.MaybeWait(ctx, req, now); err != nil {
			maybeWaitError = errors.Join(maybeWaitError, fmt.Errorf(
				"error executing rate limit %d: %w", i, err,
			))
		}
	}

	if maybeWaitError != nil {
		return nil, fmt.Errorf("error honoring rate limits: %w", maybeWaitError)
	}

	res, err := makeRequest()
	if err != nil {
		return nil, fmt.Errorf("error making HTTP request: %w", err)
	}

	now = time.Now()

	// [NOTE] errgroup.Group oddly isn't what we want here. It presumes you want
	// 			  to stop all other processing if a single task fails (we don't), and
	// 			  that functionality is the only reason to use it instead of a
	// 			  WaitGroup.
	wg := &sync.WaitGroup{}
	updateErrorLock := &sync.Mutex{}
	var updateError error = nil

	for i, lim := range rl.limits {
		wg.Add(1)
		go func(i int, lim RateLimit) {
			defer wg.Done()

			if err := lim.Update(ctx, res, now); err != nil {
				err = fmt.Errorf("error updating rate limit %d: %w", i, err)

				updateErrorLock.Lock()
				if updateError == nil {
					updateError = err
				} else {
					updateError = errors.Join(updateError, err)
				}
				updateErrorLock.Unlock()
			}
		}(i, lim)
	}

	wg.Wait()

	if updateError != nil {
		return nil, fmt.Errorf("error updating rate limits: %w", updateError)
	}

	return res, nil
}
