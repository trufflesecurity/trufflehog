//go:build no_gcs

package gcs

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func Scan(_ context.Context, _ sources.GCSConfig, _ *engine.Engine) (sources.JobProgressRef, error) {
	return sources.JobProgressRef{}, engine.ErrSourceDisabled
}
