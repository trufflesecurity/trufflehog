package sumologickey

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"

	regexp "github.com/wasilibs/go-re2"
)

type Scanner struct {
	client *http.Client
	detectors.EndpointSetter
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var (
	_ detectors.Detector           = (*Scanner)(nil)
	_ detectors.EndpointCustomizer = (*Scanner)(nil)
)

var (
	defaultClient = common.SaneHttpClient()

	// Detect which instance the key is associated with.
	// https://help.sumologic.com/docs/api/getting-started/#documentation
	urlPat = regexp.MustCompile(`(?i)api\.(?:au|ca|de|eu|fed|jp|kr|in|us2)\.sumologic\.com`)

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"sumo", "accessId"}) + `\b(su[A-Za-z0-9]{12})\b`)
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"sumo", "accessKey"}) + `\b([A-Za-z0-9]{64})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"sumo", "accessId", "accessKey"}
}

// Default US API endpoint.
func (Scanner) CloudEndpoint() string { return "api.sumologic.com" }

// FromData will find and optionally verify SumoLogicKey secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	idMatches := make(map[string]struct{})
	for _, match := range idPat.FindAllStringSubmatch(dataStr, -1) {
		idMatches[match[1]] = struct{}{}
	}
	keyMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		keyMatches[match[1]] = struct{}{}
	}
	endpointMatches := make(map[string]struct{})
	for _, match := range urlPat.FindAllStringSubmatch(dataStr, -1) {
		endpointMatches[match[0]] = struct{}{}
	}
	if len(endpointMatches) == 0 {
		endpointMatches[s.CloudEndpoint()] = struct{}{}
	}

	for accessKey := range keyMatches {
		var (
			r           *detectors.Result
			accessId    string
			apiEndpoint string
		)

		for id := range idMatches {
			accessId = id

			for e := range endpointMatches {
				apiEndpoint = e

				if verify {
					client := s.client
					if client == nil {
						client = defaultClient
					}

					isVerified, verificationErr := verifyMatch(ctx, client, apiEndpoint, accessId, accessKey)
					if isVerified {
						r = createResult(accessId, accessKey, apiEndpoint, isVerified, verificationErr)
					}
				}
			}
		}

		if r == nil {
			// Only include the accessId if we're confident which one it is.
			if len(idMatches) != 1 {
				accessId = ""
			}
			if len(endpointMatches) != 1 || apiEndpoint == s.CloudEndpoint() {
				apiEndpoint = ""
			}
			r = createResult(accessId, accessKey, apiEndpoint, false, nil)
		}
		results = append(results, *r)
	}

	return results, nil
}

func verifyMatch(ctx context.Context, client *http.Client, endpoint string, id string, key string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://%s/api/v1/users", endpoint), nil)
	if err != nil {
		return false, err
	}

	req.SetBasicAuth(id, key)
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
		// If the endpoint returns useful information, we can return it as a map.
		return true, nil
	case http.StatusUnauthorized:
		// The secret is determinately not verified (nothing to do)
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func createResult(accessId string, accessKey string, endpoint string, verified bool, err error) *detectors.Result {
	r := &detectors.Result{
		DetectorType: detectorspb.DetectorType_SumoLogicKey,
		Raw:          []byte(accessKey),
		Verified:     verified,
		ExtraData: map[string]string{
			"rotation_guide": "https://howtorotate.com/docs/tutorials/sumologic/",
		},
	}
	r.SetVerificationError(err, accessKey)

	// |endpoint| and |accessId| won't be specified unless there's a confident match.
	if accessId != "" {
		var sb strings.Builder
		sb.WriteString(`{`)
		sb.WriteString(`"accessId":"` + accessId + `"`)
		sb.WriteString(`,"accessKey":"` + accessKey + `"`)
		if endpoint != "" {
			sb.WriteString(`,"url":"` + endpoint + `"`)
		}
		sb.WriteString(`}`)
		r.RawV2 = []byte(sb.String())
	}

	return r
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_SumoLogicKey
}

func (s Scanner) Description() string {
	return "Sumo Logic is a cloud-based machine data analytics service. Sumo Logic keys can be used to access and manage data within the Sumo Logic platform."
}
