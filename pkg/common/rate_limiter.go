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
// comprises 0 or more limits. Policies should be goroutine safe.
//
// Importantly, limits can assume they're only ever used on a single API, and
// thus can be used in more than one rate limiter. For example, if an API has 2
// endpoints, one accepts 5r/s and another accepts 1r/s, but both have a limit
// of total 500r/month, the policy implementing the 500r/month limit should be
// able to be used in both of the 2 rate limiters for the 5r/s and 1r/s limits.
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
