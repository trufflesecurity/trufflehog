package weightsandbiases

import (
	"context"
	"net/http"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	common "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/weightsandbiases"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct{ client *http.Client }

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.Versioner = (*Scanner)(nil)

var keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"wandb"}) + `\b([0-9a-f]{40})\b`)

func (s Scanner) Version() int { return 1 }

func (s Scanner) Keywords() []string { return []string{"wandb"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	client := s.client
	if client == nil {
		client = common.DefaultClient
	}
	return common.FromData(ctx, verify, client, data, keyPat)
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_WeightsAndBiases
}

func (s Scanner) Description() string {
	return "Weights & Biases is a Machine Learning Operations (MLOps) platform that helps track experiments, version datasets, evaluate model performance, and collaborate with team members"
}
