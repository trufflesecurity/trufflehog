package brandfetch

import (
	"context"
	"net/http"
	"strconv"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	v2 "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/brandfetch/v2"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
}

func (s Scanner) Version() int { return 1 }

var (
	// Ensure the Scanner satisfies the interface at compile time.
	_             detectors.Detector  = (*Scanner)(nil)
	_             detectors.Versioner = (*Scanner)(nil)
	defaultClient                     = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"brandfetch"}) + `\b([0-9A-Za-z]{40})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"brandfetch"}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Brandfetch
}

func (s Scanner) Description() string {
	return "Brandfetch is a service that provides brand data, including logos, colors, fonts, and more. Brandfetch API keys can be used to access this data."
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}

	return defaultClient
}

// FromData will find and optionally verify Brandfetch secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueTokenMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueTokenMatches[match[1]] = struct{}{}
	}

	for match := range uniqueTokenMatches {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Brandfetch,
			Raw:          []byte(match),
			ExtraData:    map[string]string{"version": strconv.Itoa(s.Version())},
		}

		if verify {
			isVerified, verificationErr := v2.VerifyMatch(ctx, s.getClient(), match)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, match)
		}

		results = append(results, s1)
	}

	return
}
