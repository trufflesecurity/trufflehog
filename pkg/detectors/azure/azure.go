package azure

import (
	"context"
	"fmt"
	"regexp"
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
	secretPatFmt    = `(?i)(%s).{0,20}([a-z0-9_.\-~]{34})`
	clientSecretPat = mustFmtPat("client_secret", secretPatFmt)
)

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("azure")}
}

// FromData will find and optionally verify Azure secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	clientSecretMatches := clientSecretPat.FindAllSubmatch(data, -1)

	for _, clientSecret := range clientSecretMatches {
		tenantIDMatches := tenantIDPat.FindAllSubmatch(data, -1)
		for _, tenantID := range tenantIDMatches {
			clientIDMatches := clientIDPat.FindAllSubmatch(data, -1)
			for _, clientID := range clientIDMatches {
				s := detectors.Result{
					DetectorType: detectorspb.DetectorType_Azure,
					Raw:          clientSecret[2],
					RawV2:        append(clientID[2], append(clientSecret[2], tenantID[2]...)...),
					Redacted:     string(clientID[2]),
				}

				if verify {
					cred := auth.NewClientCredentialsConfig(string(clientID[2]), string(clientSecret[2]), string(tenantID[2]))
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
					if detectors.IsKnownFalsePositive([]byte(s.Redacted), detectors.DefaultFalsePositives, true) {
						continue
					}
					if detectors.IsKnownFalsePositive(s.Raw, detectors.DefaultFalsePositives, true) {
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
