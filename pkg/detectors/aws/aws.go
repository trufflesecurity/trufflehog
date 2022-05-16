package aws

import (
	"context"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	// Key types are from this list https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-unique-ids
	keyPat    = regexp.MustCompile(`\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\b`)
	secretPat = regexp.MustCompile(`\b([A-Za-z0-9+/]{40})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{
		"AKIA",
		"ABIA",
		"ACCA",
		"ASIA",
	}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	dataStr := string(data)
	var results []detectors.Result

	keyMatches := keyPat.FindAllStringSubmatch(dataStr, -1)
	secretMatches := secretPat.FindAllStringSubmatch(dataStr, -1)

	for _, keyMatch := range keyMatches {
		if len(keyMatch) != 2 {
			continue
		}

		key := strings.TrimSpace(keyMatch[1])

		s := detectors.Result{
			DetectorType: detectorspb.DetectorType_AWS,
			Raw:          []byte(key),
			Redacted:     key,
		}
		// TODO: Remove possible matches if they verify positive.
		if verify {
			for _, secretMatch := range secretMatches {
				if len(secretMatch) != 2 {
					continue
				}

				secret := strings.TrimSpace(secretMatch[1])

				result, err := callerIdentity(ctx, key, secret)
				if err != nil {
					// It also errors for signature mismatches on the client side before sending, and it's quite noisy.
					continue
				}
				if result != nil && result.Account != nil {
					s.Verified = true
					break
				}
			}
		}

		if !s.Verified {
			if detectors.IsKnownFalsePositive(string(s.Raw), detectors.DefaultFalsePositives, true) {
				continue
			}
		}

		if len(secretMatches) > 0 {
			results = append(results, s)
		}
	}

	return detectors.CleanResults(results), nil
}

func callerIdentity(ctx context.Context, key, secret string) (*sts.GetCallerIdentityOutput, error) {
	svc := sts.New(sts.Options{
		HTTPClient:  common.SaneHttpClient(),
		Logger:      nil,
		Region:      "us-west-2",
		Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""),
	})
	result, err := svc.GetCallerIdentity(ctx, nil)
	return result, err
}
