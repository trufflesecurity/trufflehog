package appsync

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	client *http.Client
	detectors.DefaultMultiPartCredentialProvider
}

// Compile-time interface check
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	apiKeyPat = regexp.MustCompile(
		`\b(da2-[a-z0-9]{26})\b`,
	)

	endpointPat = regexp.MustCompile(
		`(https:\/\/[a-z0-9]{26}\.appsync-api\.[a-z0-9-]+\.amazonaws\.com(?:\/graphql)?)`,
	)
)

func (s Scanner) Keywords() []string {
	return []string{"da2-"}
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

func (s Scanner) FromData(
	ctx context.Context,
	verify bool,
	data []byte,
) (results []detectors.Result, err error) {

	dataStr := string(data)

	keys := make(map[string]struct{})
	endpoints := make(map[string]struct{})

	for _, m := range apiKeyPat.FindAllStringSubmatch(dataStr, -1) {
		keys[m[1]] = struct{}{}
	}

	for _, m := range endpointPat.FindAllStringSubmatch(dataStr, -1) {
		endpoints[m[1]] = struct{}{}
	}

	for key := range keys {
		for endpoint := range endpoints {
			normalizedEndpoint := normalizeEndpoint(endpoint)

			result := detectors.Result{
				DetectorType: detector_typepb.DetectorType_AWSAppSync,
				Raw:          []byte(key),
				RawV2:        []byte(fmt.Sprintf("%s:%s", normalizedEndpoint, key)),
				SecretParts: map[string]string{
					"key":      key,
					"endpoint": normalizedEndpoint,
				},
			}

			if verify {
				verified, verificationErr := verifyAppSyncKey(
					ctx,
					s.getClient(),
					normalizedEndpoint,
					key,
				)

				result.SetVerificationError(verificationErr, key)
				result.Verified = verified
			}

			results = append(results, result)
		}
	}

	return
}

func verifyAppSyncKey(
	ctx context.Context,
	client *http.Client,
	endpoint string,
	key string,
) (bool, error) {

	query := `{"query":"query { __typename }"}`

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		endpoint,
		bytes.NewBufferString(query),
	)
	if err != nil {
		return false, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", key)

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

	case http.StatusUnauthorized,
		http.StatusForbidden:
		return false, nil

	default:
		return false, fmt.Errorf(
			"unexpected HTTP response status %d",
			res.StatusCode,
		)
	}
}

func normalizeEndpoint(endpoint string) string {
	if !strings.HasSuffix(endpoint, "/graphql") {
		return endpoint + "/graphql"
	}
	return endpoint
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_AWSAppSync
}

func (s Scanner) Description() string {
	return "AWS AppSync is a managed GraphQL service. This detector identifies exposed AppSync API keys."
}
