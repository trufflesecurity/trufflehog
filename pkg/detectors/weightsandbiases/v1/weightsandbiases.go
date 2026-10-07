package weightsandbiases

import (
	"context"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	base "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/weightsandbiases"
)

type Scanner struct {
	base.BaseScanner
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.Versioner = (*Scanner)(nil)

var keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"wandb"}) + `\b([0-9a-f]{40})\b`)

func (s Scanner) Version() int { return 1 }

func (s Scanner) Keywords() []string { return []string{"wandb"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	return s.BaseScanner.FromData(ctx, verify, data, keyPat, s.Version())
}

