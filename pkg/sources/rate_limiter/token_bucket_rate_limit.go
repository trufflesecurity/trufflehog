package rate_limiter

import (
	"net/http"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"golang.org/x/time/rate"
)

// TokenBucketRateLimit implements a basic "requests per second with bursting"
// rate limiter.  It's a (very) thin wrapper around Google's rate limiter.
type TokenBucketRateLimit struct {
	limiter *rate.Limiter
}

// Creates a new TokenBucketRateLimit
// lim: a Limit representing the max number of requests per second
// burst: max number of requests that can be sent if any requests can be sent
func NewTokenBucketRateLimit(lim rate.Limit, burst int) *TokenBucketRateLimit {
	return &TokenBucketRateLimit{
		limiter: rate.NewLimiter(rate.Limit(lim), burst),
	}
}

func (tp *TokenBucketRateLimit) MaybeWait(
	ctx context.Context,
	req *http.Request,
	now time.Time,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	return tp.limiter.Wait(ctx)
}

func (tp *TokenBucketRateLimit) Update(
	ctx context.Context,
	res *http.Response,
	now time.Time,
) error {
	return nil
}
