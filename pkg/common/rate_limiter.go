package common

import (
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

// RateLimit represents a rate limiting implementation. A rate limiter
// comprises 0 or more limits. Implementation requirements:
//   - Be goroutine safe.
//   - .Execute can *NEVER* sleep for a duration; it can only sleep _UNTIL_ a
//     time.
//
// Usage requirements:
//
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
	// Execute and update execute and update a policy, respectively. These
	// should:
	// - Be goroutine safe
	// - Check if ctx has been canceled
	// - Not modify req/res
	// If they return an error, it's combined with errors from the
	// execution/updating of the other limits. Other limits will still be
	// executed/updated.
	//
	// If waiting/sleeping is required, Execute should do it. Keep in mind,
	// however, that each policy's Execute method is called serially, so Execute
	// should *NEVER* sleep for a duration--it should only sleep until a time.
	// This also means that if an API only returns durations, Update must
	// immediately convert them into times, and it's recommended to pad these
	// somewhat.
	Execute(ctx context.Context, req *http.Request, now time.Time) error
	Update(ctx context.Context, res *http.Response) error
}

// RateLimiter provides a facility for rate limiting HTTP requests. To use it:
// - Create a RateLimiter with its limits
// - Call .Do instead of what you would normally call to make a request
// - Process the response (returned from .Do) as normal
type RateLimiter struct {
	limits []RateLimit
}

// Returns a new rate limiter with the given limits.
func NewRateLimiter(limits ...RateLimit) *RateLimiter {
	return &RateLimiter{limits: limits}
}

// Makes an HTTP request subject to the rate limiter's limits.
func (rl *RateLimiter) Do(
	ctx context.Context,
	req *http.Request,
	makeRequest func() (*http.Response, error),
) (*http.Response, error) {
	if len(rl.limits) == 0 {
		return makeRequest()
	}

	now := time.Now()

	for i, lim := range rl.limits {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		// [NOTE] It's maybe better to do this asynchronously, in case an errant
		//		    limit sleeps for a duration instead of until a specific time, but
		//			  I haven't thought through that.
		if err := lim.Execute(ctx, req, now); err != nil {
			return nil, fmt.Errorf(
				"error executing rate limit policy %d: %w",
				i,
				err,
			)
		}
	}

	res, err := makeRequest()
	if err != nil {
		return nil, fmt.Errorf("error making HTTP request: %w", err)
	}

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

			if err := lim.Update(ctx, res); err != nil {
				err = fmt.Errorf("error updating rate limit policy %d: %w", i, err)

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
