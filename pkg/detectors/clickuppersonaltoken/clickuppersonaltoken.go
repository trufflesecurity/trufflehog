package clickuppersonaltoken

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

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"clickup"}) + `\b(pk_[0-9]{7,9}_[0-9A-Z]{32})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"clickup"}
}

// FromData will find and optionally verify ClickupPersonalToken secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[strings.TrimSpace(match[1])] = struct{}{}
	}

	for resMatch := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_ClickupPersonalToken,
			Raw:          []byte(resMatch),
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}
			isVerified, err := verifyToken(ctx, client, resMatch)
			s1.Verified = isVerified
			s1.SetVerificationError(err, resMatch)
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_ClickupPersonalToken
}

func (s Scanner) Description() string {
	return "ClickUp is a project management tool. Personal tokens can be used to access and modify data within ClickUp on behalf of a user."
}

func verifyToken(ctx context.Context, client *http.Client, token string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.clickup.com/api/v2/user", nil)
	if err != nil {
		return false, err
	}
	req.Header.Add("Authorization", token)
	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code %d", res.StatusCode)
	}
}
