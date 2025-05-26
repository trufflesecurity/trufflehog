//go:build no_postman

package postman

import (
	"context"

	"github.com/trufflesecurity/trufflehog/v3/pkg/engine"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func Scan(_ context.Context, _ sources.PostmanConfig, _ *engine.Engine) (sources.JobProgressRef, error) {
	return sources.JobProgressRef{}, engine.ErrSourceDisabled
}
