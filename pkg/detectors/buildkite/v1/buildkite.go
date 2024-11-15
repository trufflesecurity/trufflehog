package buildkite

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

func (s Scanner) Version() int { return 1 }

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.Versioner = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"buildkite"}) + `\b([a-z0-9]{40})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"buildkite"}
}

// FromData will find and optionally verify Buildkite secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Buildkite,
			Raw:          []byte(resMatch),
		}

		if verify {
			isVerified, verificationErr := VerifyBuildKite(ctx, client, resMatch)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, resMatch)
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Buildkite
}

func (s Scanner) Description() string {
	return "Buildkite is a platform for running fast, secure, and scalable continuous integration pipelines. Buildkite API tokens can be used to access and modify pipeline data and configurations."
}

func VerifyBuildKite(ctx context.Context, client *http.Client, secret string) (bool, error) {
	// create a request
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.buildkite.com/v2/access-token", nil)
	if err != nil {
		return false, err
	}

	// add authorization header
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", secret))

	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	if res.StatusCode == http.StatusOK {
		return true, nil
	}

	return false, nil
}
