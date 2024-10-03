package azure

import (
	"context"
	"fmt"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/Azure/go-autorest/autorest/azure/auth"
	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	// TODO: Azure storage access keys and investigate other types of creds.

	// Azure App Oauth
	udidPatFmt  = `([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})`
	clientIDPat = regexp.MustCompile(detectors.PrefixRegex([]string{"client_id", "clientid"}) + udidPatFmt)
	tenantIDPat = regexp.MustCompile(detectors.PrefixRegex([]string{"microsoftonline", "tenant_id", "tenantid"}) + udidPatFmt)

	// According the Microsoft documentation, the client secret can be 24, 32, 40, 44, 56, or 88 characters long.
	// https://learn.microsoft.com/en-us/purview/sit-defn-client-secret-api-key
	clientSecretSubPatFmt = `(\b[a-zA-Z0-9_\.\-~]{%d}\b)`

	clientSecretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"client_secret", "clientsecret"}) + "(" +
		fmt.Sprintf(clientSecretSubPatFmt, 24) + "|" +
		fmt.Sprintf(clientSecretSubPatFmt, 32) + "|" +
		fmt.Sprintf(clientSecretSubPatFmt, 40) + "|" +
		fmt.Sprintf(clientSecretSubPatFmt, 44) + "|" +
		fmt.Sprintf(clientSecretSubPatFmt, 56) + "|" +
		fmt.Sprintf(clientSecretSubPatFmt, 88) + ")")
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"azure", "microsoftonline", "microsoft"}
}

func trimUniqueMatches(matches [][]string) (result map[string]struct{}) {
	result = make(map[string]struct{})
	for _, match := range matches {
		if len(match) > 1 {
			trimmedString := strings.TrimSpace(match[1])
			result[trimmedString] = struct{}{}
		}
	}
	return result
}

// FromData will find and optionally verify Azure secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueClientSecretMatches := trimUniqueMatches(clientSecretPat.FindAllStringSubmatch(dataStr, -1))
	uniqueClientIDMatches := trimUniqueMatches(clientIDPat.FindAllStringSubmatch(dataStr, -1))
	uniqueTenantIDMatches := trimUniqueMatches(tenantIDPat.FindAllStringSubmatch(dataStr, -1))

	for clientSecret := range uniqueClientSecretMatches {
		for clientID := range uniqueClientIDMatches {
			for tenantID := range uniqueTenantIDMatches {
				// to reduce false positives, we can check if they are the same
				if (tenantID == clientID) ||
					(tenantID == clientSecret) ||
					(clientID == clientSecret) {
					continue
				}

				s := detectors.Result{
					DetectorType: detectorspb.DetectorType_Azure,
					Raw:          []byte(clientSecret),
					RawV2:        []byte(clientID + clientSecret + tenantID),
					Redacted:     clientID,
				}
				// Set the RotationGuideURL in the ExtraData
				s.ExtraData = map[string]string{
					"rotation_guide": "https://howtorotate.com/docs/tutorials/azure/",
				}

				if verify {
					cred := auth.NewClientCredentialsConfig(clientID, clientSecret, tenantID)
					token, err := cred.ServicePrincipalToken()
					if err != nil {
						continue
					}
					err = token.RefreshWithContext(ctx)
					if err == nil {
						res.Verified = true
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

func (s Scanner) Description() string {
	return "Azure is a cloud service offering a wide range of services including compute, analytics, storage, and networking. Azure credentials can be used to access and manage these services."
}
