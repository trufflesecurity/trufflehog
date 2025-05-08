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
	hostname string
	limits   map[string]APIRateLimit
}

// Returns a new rate limiter with the given limits. Limits are passed by name
// in the map, ex:
//
//	NewAPIRateLimiter(map[string]RateLimit{
//	  "5r/s": fiveRequestsPerSecondLimit,
//	})
func NewAPIRateLimiter(
	hostname string,
	limits map[string]APIRateLimit,
) (*APIRateLimiter, error) {
	for limitHostname := range limits {
		if limitHostname != hostname {
			return nil, fmt.Errorf(
				"cannot add rate limit for API %q to rate limiter for different API %q",
				limitHostname,
				hostname,
			)
		}
	}

	return &APIRateLimiter{hostname: hostname, limits: limits}, nil
}

// Makes an HTTP request to an API while honoring its limits.
func (api *APIRateLimiter) DoWithRateLimiting(
	ctx context.Context,
	req *http.Request,
	makeRequest func() (*http.Response, error),
) (*http.Response, error) {
	if len(api.limits) == 0 {
		return makeRequest()
	}

	if req.URL.Hostname() != api.hostname {
		return nil, fmt.Errorf(
			"cannot rate limit requests to API %q with a rate limiter for API %q",
			req.URL.Hostname(),
			api.hostname,
		)
	}

	now := time.Now()

	// [NOTE] errgroup.Group oddly isn't what we want here. It presumes you want
	// 			  to stop all other processing if a single task fails (we don't), and
	// 			  that functionality is the only reason to use it instead of a
	// 			  WaitGroup.
	maybeWaitGroup := &sync.WaitGroup{}
	maybeWaitErrorLock := &sync.Mutex{}
	var maybeWaitError error = nil

	for name, lim := range api.limits {
		maybeWaitGroup.Add(1)
		go func(name string, lim APIRateLimit) {
			defer maybeWaitGroup.Done()

			if err := lim.MaybeWait(ctx, req, now); err != nil {
				err = fmt.Errorf("error updating rate limit %s: %w", name, err)

				maybeWaitErrorLock.Lock()
				if maybeWaitError == nil {
					maybeWaitError = err
				} else {
					maybeWaitError = errors.Join(maybeWaitError, err)
				}
				maybeWaitErrorLock.Unlock()
			}
		}(name, lim)
	}

	maybeWaitGroup.Wait()

	if maybeWaitError != nil {
		return nil, fmt.Errorf("error honoring rate limits: %w", maybeWaitError)
	}

	res, err := makeRequest()
	if err != nil {
		return nil, fmt.Errorf("error making HTTP request: %w", err)
	}

	now = time.Now()

	updateWaitGroup := &sync.WaitGroup{}
	updateErrorLock := &sync.Mutex{}
	var updateError error = nil

	for name, lim := range api.limits {
		updateWaitGroup.Add(1)
		go func(name string, lim APIRateLimit) {
			defer updateWaitGroup.Done()

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

	updateWaitGroup.Wait()

	if updateError != nil {
		return nil, fmt.Errorf("error updating rate limits: %w", updateError)
	}

	return res, nil
}
