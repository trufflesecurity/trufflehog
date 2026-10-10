package paystack

import (
	"context"
	"net/http"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	client *http.Client
}

var _ detectors.Detector = Scanner{}

var (
	defaultClient = common.SaneHttpClient()
	keyPat        = regexp.MustCompile(`\bsk_(?:test|live)_[A-Za-z0-9]{40}\b`)
	verifyURL     = "https://api.paystack.co/balance"
)

func (s Scanner) Keywords() []string {
	return []string{"sk_test_", "sk_live_"}
}

func (s Scanner) httpClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	for _, key := range keyPat.FindAllString(string(data), -1) {
		result := detectors.Result{
			DetectorType: detector_typepb.DetectorType_Paystack,
			Raw:          []byte(key),
			SecretParts:  map[string]string{"key": key},
		}
		if verify {
			verified, verifyErr := common.VerifyBearerToken(ctx, s.httpClient(), verifyURL, key)
			result.Verified = verified
			if verifyErr != nil {
				result.SetVerificationError(verifyErr, key)
			}
		}
		results = append(results, result)
	}
	return results, nil
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Paystack
}

func (s Scanner) Description() string {
	return "Detects Paystack secret API keys"
}
