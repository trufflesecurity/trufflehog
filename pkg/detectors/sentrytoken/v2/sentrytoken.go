package sentrytoken

import (
	"context"
	"net/http"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	v1 "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/sentrytoken/v1"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.Versioner = (*Scanner)(nil)

var (
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(`\b(sntryu_[a-f0-9]{64})\b`)
)

func (s Scanner) Version() int {
	return 2
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"sentry", "sntryu"}
}

// FromData will find and optionally verify SentryToken secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	// find all unique auth tokens
	var uniqueAuthTokens = make(map[string]struct{})

	for _, authToken := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueAuthTokens[authToken[1]] = struct{}{}
	}

	for authToken := range uniqueAuthTokens {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_SentryToken,
			Raw:          []byte(authToken),
		}

		if verify {
			if s.client == nil {
				s.client = common.SaneHttpClient()
			}
			extraData, isVerified, verificationErr := v1.VerifyToken(ctx, s.client, authToken)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, authToken)
			s1.ExtraData = extraData
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_SentryToken
}

func (s Scanner) Description() string {
	return "Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry tokens can be used to access and manage projects and organizations within Sentry."
}
