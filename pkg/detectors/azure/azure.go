package azure

import (
	"context"
	"fmt"
	regexp "github.com/wasilibs/go-re2"
	"strings"

	"github.com/Azure/go-autorest/autorest/azure/auth"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

func mustFmtPat(id, pat string) *regexp.Regexp {
	combinedID := strings.ReplaceAll(id, "_", "") + "|" + id
	return regexp.MustCompile(fmt.Sprintf(pat, combinedID))
}

var (
	// TODO: Azure storage access keys and investigate other types of creds.

	// Azure App Oauth
	idPatFmt    = `(?i)(%s).{0,20}([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})`
	clientIDPat = mustFmtPat("client_id", idPatFmt)
	tenantIDPat = mustFmtPat("tenant_id", idPatFmt)

	// TODO: support old patterns
	secretPatFmt    = `(?i)(%s).{0,20}([a-z0-9_\.\-~]{34})`
	clientSecretPat = mustFmtPat("client_secret", secretPatFmt)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"azure"}
}

// FromData will find and optionally verify Azure secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	clientSecretMatches := clientSecretPat.FindAllStringSubmatch(dataStr, -1)
	for _, clientSecret := range clientSecretMatches {
		tenantIDMatches := tenantIDPat.FindAllStringSubmatch(dataStr, -1)
		for _, tenantID := range tenantIDMatches {
			clientIDMatches := clientIDPat.FindAllStringSubmatch(dataStr, -1)
			for _, clientID := range clientIDMatches {
				s := detectors.Result{
					DetectorType: detectorspb.DetectorType_Azure,
					Raw:          []byte(clientSecret[2]),
					RawV2:        []byte(clientID[2] + clientSecret[2] + tenantID[2]),
					Redacted:     clientID[2],
				}
				// Set the RotationGuideURL in the ExtraData
				s.ExtraData = map[string]string{
					"rotation_guide": "https://howtorotate.com/docs/tutorials/azure/",
				}

				if verify {
					cred := auth.NewClientCredentialsConfig(clientID[2], clientSecret[2], tenantID[2])
					token, err := cred.ServicePrincipalToken()
					if err != nil {
						continue
					}
					err = token.Refresh()
					if err == nil {
						s.Verified = true
					}
				}

				if !s.Verified {
					if detectors.IsKnownFalsePositive(s.Redacted, detectors.DefaultFalsePositives, true) {
						continue
					}
					if detectors.IsKnownFalsePositive(string(s.Raw), detectors.DefaultFalsePositives, true) {
						continue
					}
				}

				results = append(results, s)
			}
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Azure
}
