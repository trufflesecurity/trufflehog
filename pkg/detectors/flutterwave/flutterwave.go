package flutterwave

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
	keyPat        = regexp.MustCompile(`\bFLWSECK(?:_TEST)?-[A-Za-z0-9]{32}-X\b`)
	verifyURL     = "https://api.flutterwave.com/v3/subaccounts"
)

func (s Scanner) Keywords() []string {
	return []string{"FLWSECK-", "FLWSECK_TEST-"}
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
			DetectorType: detector_typepb.DetectorType_Flutterwave,
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
	return detector_typepb.DetectorType_Flutterwave
}

func (s Scanner) Description() string {
	return "Detects Flutterwave secret API keys (FLWSECK format)"
}
