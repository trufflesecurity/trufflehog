package accuweather

import (
	"context"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	v1 "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/accuweather/v1"
)

type Scanner struct {
	v1.Scanner
}

func (s Scanner) Version() int { return 2 }

var (
	// Ensure the Scanner satisfies the interface at compile time.
	_ detectors.Detector = (*Scanner)(nil)

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"accuweather"}) + `\b([a-zA-Z0-9]{32})\b`)
)

// FromData will find and optionally verify Accuweather secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllStringSubmatch(string(data), -1)
	return s.ProcessMatches(ctx, matches, verify)
}
