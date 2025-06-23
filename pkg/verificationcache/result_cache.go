package verificationcache

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/cache"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
)

// ResultCache is a cache that holds individual detector results. It serves as a component of a VerificationCache.
type ResultCache cache.Cache[detectors.Result]
