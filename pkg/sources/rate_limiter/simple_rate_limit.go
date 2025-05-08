package rate_limiter

import (
	"net/http"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"golang.org/x/time/rate"
)

// SimpleRateLimit implements a basic "requests per second with bursting"
// rate limiter.  It's a (very) thin wrapper around Google's rate limiter with
// a hardcoded burst rate of 1.
type SimpleRateLimit struct {
	limiter *rate.Limiter
}

// Creates a new SimpleRateLimit
// lim: a Limit representing the max number of requests per second
// burst: max number of requests that can be sent if any requests can be sent
func NewSimpleRateLimit(requestsPerSecond int) *SimpleRateLimit {
	lim := rate.Every(time.Second / time.Duration(requestsPerSecond))
	return &SimpleRateLimit{
		limiter: rate.NewLimiter(lim, 1),
	}
}

func (tp *SimpleRateLimit) MaybeWait(
	ctx context.Context,
	req *http.Request,
	now time.Time,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	return tp.limiter.Wait(ctx)
}

func (tp *SimpleRateLimit) Update(
	ctx context.Context,
	res *http.Response,
	now time.Time,
) error {
	return nil
}
