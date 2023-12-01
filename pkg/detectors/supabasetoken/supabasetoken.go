package supabasetoken

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(`\b(sbp_[a-z0-9]{40})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"sbp_"}
}

// FromData will find and optionally verify Supabasetoken secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_SupabaseToken,
			Raw:          []byte(resMatch),
		}

		if verify {
			isVerified, verificationErr := s.verifyMatch(ctx, resMatch)
			s1.Verified = isVerified
			s1.VerificationError = verificationErr
		}

		if !s1.Verified {
			// This function will check false positives for common test words, but also it will make sure the key appears 'random' enough to be a real key.
			if detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
				continue
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) verifyMatch(ctx context.Context, key string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.supabase.com/v1/projects", nil)
	if err != nil {
		return false, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", key))
	res, err := client.Do(req)
	if err != nil {
		return false, nil
	}
	defer func() {
		// Ensure we drain the response body so this connection can be reused.
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	if res.StatusCode >= 200 && res.StatusCode < 300 {
		return true, nil
	} else {
		return false, nil
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_SupabaseToken
}
