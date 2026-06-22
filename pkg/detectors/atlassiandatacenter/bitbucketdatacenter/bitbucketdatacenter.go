package bitbucketdatacenter

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/atlassiandatacenter"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	client *http.Client
	detectors.DefaultMultiPartCredentialProvider
	detectors.EndpointSetter
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.EndpointCustomizer = (*Scanner)(nil)

var (
	defaultClient = detectors.DetectorHttpClientWithLocalAddresses

	// Bitbucket pat start with BBDC- prefix
	// and are usually between the length of 40-50 character
	// consisting of both alphanumeric and some special character like +, _, @ and etc
	userPat = regexp.MustCompile(`\b(BBDC-[A-Za-z0-9+/@_-]{40,50})(?:[^A-Za-z0-9+/@_-]|$)`)
	urlPat  = atlassiandatacenter.GetURLPat([]string{"atlassian", "bitbucket"})
)

func (s Scanner) Keywords() []string {
	return []string{"BBDC-"}
}

// FromData will find and optionally verify HashiCorp Vault AppRole secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	var uniqueSecretPat = make(map[string]struct{})
	for _, match := range userPat.FindAllStringSubmatch(dataStr, -1) {
		secretPat := strings.TrimSpace(match[1])
		uniqueSecretPat[secretPat] = struct{}{}
	}

	if len(uniqueSecretPat) == 0 {
		return results, nil
	}

	endpoints := atlassiandatacenter.FindEndpoints(dataStr, urlPat, s.Endpoints)

	// create combination results that can be verified
	for secret := range uniqueSecretPat {
		for _, bitBucketURL := range endpoints {
			s1 := detectors.Result{
				DetectorType: detector_typepb.DetectorType_BitbucketDataCenter,
				Raw:          []byte(secret),
				SecretParts: map[string]string{
					"secret": secret,
					"url":    bitBucketURL,
				},
				RawV2: []byte(fmt.Sprintf("%s:%s", secret, bitBucketURL)),
				ExtraData: map[string]string{
					"URL": bitBucketURL,
				},
			}

			if verify {
				client := s.client
				if client == nil {
					client = defaultClient
				}

				isVerified, verificationErr := verifyMatch(ctx, client, secret, bitBucketURL)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr, secret, bitBucketURL)
			}
			results = append(results, s1)
		}
	}
	return results, nil
}

func verifyMatch(ctx context.Context, client *http.Client, secretPat, baseURL string) (bool, error) {
	u, err := detectors.ParseURLAndStripPathAndParams(baseURL)
	if err != nil {
		return false, err
	}
	u.Path = "rest/api/1.0/projects"
	q := u.Query()
	q.Set("limit", "1")
	u.RawQuery = q.Encode()

	isVerified, _, err := atlassiandatacenter.MakeVerifyRequest(ctx, client, u.String(), secretPat)
	return isVerified, err
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_BitbucketDataCenter
}

func (s Scanner) Description() string {
	return "Bitbucket is a Git repository hosting service by Atlassian. Bitbucket PATs are used to authenticate bitbucket data center(on prem) rest endpoint requests."
}
