package jupiterone

import (
	"context"
	"fmt"
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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"jupiterone"}) + `\b([0-9a-zA-Z]{76})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"jupiterone"}
}

// FromData will find and optionally verify Jupiterone secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_JupiterOne,
			Raw:          []byte(resMatch),
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			payload := strings.NewReader(`{
				"query": "query J1QL($query: String! = \"find jupiterone_account\", $variables: JSON, $cursor: String, $scopeFilters: [JSON!], $flags: QueryV1Flags) { queryV1(query: $query, variables: $variables, cursor: $cursor, scopeFilters: $scopeFilters, flags: $flags) { type data cursor }}"
			  }`,
			)
			req, err := http.NewRequestWithContext(ctx, "POST", "https://graphql.us.jupiterone.io/", payload)
			if err != nil {
				continue
			}

			req.Header.Add("Authorization", "Bearer "+resMatch)
			req.Header.Add("JupiterOne-Account", "12345678-1234-1234-1234-123412341234") // dummy account number
			req.Header.Add("Content-Type", "application/json")

			res, err := client.Do(req)
			if err == nil {
				defer res.Body.Close()
				if res.StatusCode == 200 {
					s1.Verified = true
				} else if res.StatusCode == 401 {
					// The secret is determinately not verified (nothing to do)
				} else {
					s1.SetVerificationError(fmt.Errorf("unexpected HTTP response status %d", res.StatusCode), resMatch)
				}
			} else {
				s1.SetVerificationError(err, resMatch)
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_JupiterOne
}

func (s Scanner) Description() string {
	return "JupiterOne is a cloud security management platform. JupiterOne API keys can be used to access and manage security data."
}
