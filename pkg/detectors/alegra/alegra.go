package alegra

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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"alegra"}) + `\b([a-z0-9-]{20})\b`)
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"alegra"}) + common.EmailPattern)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"alegra"}
}

// FromData will find and optionally verify Alegra secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	keyMatches := keyPat.FindAllStringSubmatch(dataStr, -1)
	idMatches := idPat.FindAllStringSubmatch(dataStr, -1)

	uniqueTokens := make(map[string]struct{})
	uniqueIDs := make(map[string]struct{})

	for _, match := range keyMatches {
		uniqueTokens[match[1]] = struct{}{}
	}

	for _, match := range idMatches {
		id := match[0][strings.LastIndex(match[0], " ")+1:]
		uniqueIDs[id] = struct{}{}
	}

	for token := range uniqueTokens {
		for id := range uniqueIDs {
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Alegra,
				Raw:          []byte(token),
				RawV2:        []byte(token + ":" + id),
			}

			if verify {
				client := s.client
				if client == nil {
					client = defaultClient
				}

				isVerified, verificationErr := verifyCredentials(ctx, client, id, token)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr, token)
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func verifyCredentials(ctx context.Context, client *http.Client, username, token string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.alegra.com/api/v1/users/self", nil)
	if err != nil {
		return false, nil
	}
	req.SetBasicAuth(username, token)

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
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Alegra
}

func (s Scanner) Description() string {
	return "Alegra is a cloud-based accounting software. Alegra API keys can be used to access and modify accounting data and user information."
}
