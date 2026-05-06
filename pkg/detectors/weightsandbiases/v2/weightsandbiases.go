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

// wandb_v1_<27 alphanumeric chars>_<49 alphanumeric chars>
// Example: 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
var keyPat = regexp.MustCompile(`\b(wandb_v1_[A-Za-z0-9]{27}_[A-Za-z0-9]{49})\b`)

func (s Scanner) Version() int { return 2 }

func (s Scanner) Keywords() []string { return []string{"wandb_v1_"} }

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
