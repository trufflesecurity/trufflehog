package rate_limiter

import (
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

// APIRateLimiter provides a facility for honoring an API's rate limits. To use
// it:
// - Create a APIRateLimiter with its RateLimits
// - Call .Do instead of what you would normally call to make a request
// - Process the response (returned from .Do) as normal
//
// A APIRateLimiter should only be used on a single API. If you're making
// requests to multiple APIs, use multiple APIRateLimiters.
type APIRateLimiter struct {
	limits map[string]APIRateLimit
}

// Returns a new rate limiter with the given limits. Limits are passed by name
// in the map, ex:
//
//	NewAPIRateLimiter(map[string]RateLimit{
//	  "5r/s": fiveRequestsPerSecondLimit,
//	})
func NewAPIRateLimiter(limits map[string]APIRateLimit) *APIRateLimiter {
	return &APIRateLimiter{limits: limits}
}

// Makes an HTTP request to an API while honoring its limits.
func (api *APIRateLimiter) Do(
	ctx context.Context,
	req *http.Request,
	makeRequest func() (*http.Response, error),
) (*http.Response, error) {
	if len(api.limits) == 0 {
		return makeRequest()
	}

	now := time.Now()

	var maybeWaitError error = nil

	for name, lim := range api.limits {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		// [NOTE] It's perhaps better to do this asynchronously, in case an errant
		//		    limit sleeps for a duration instead of until a specific time, but
		//			  I haven't thought through that.
		if err := lim.MaybeWait(ctx, req, now); err != nil {
			maybeWaitError = errors.Join(maybeWaitError, fmt.Errorf(
				"error executing rate limit %s: %w", name, err,
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

	for name, lim := range api.limits {
		wg.Add(1)
		go func(name string, lim APIRateLimit) {
			defer wg.Done()

			if err := lim.Update(ctx, res, now); err != nil {
				err = fmt.Errorf("error updating rate limit %s: %w", name, err)

				updateErrorLock.Lock()
				if updateError == nil {
					updateError = err
				} else {
					updateError = errors.Join(updateError, err)
				}
				updateErrorLock.Unlock()
			}
		}(name, lim)
	}

	wg.Wait()

	if updateError != nil {
		return nil, fmt.Errorf("error updating rate limits: %w", updateError)
	}

	return res, nil
}
