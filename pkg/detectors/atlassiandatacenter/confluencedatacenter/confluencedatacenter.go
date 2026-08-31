package confluencedatacenter

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/cache/simple"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/atlassiandatacenter"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
	detectors.EndpointSetter
	client *http.Client
}

var (
	_ detectors.Detector           = (*Scanner)(nil)
	_ detectors.EndpointCustomizer = (*Scanner)(nil)
)

func (Scanner) CloudEndpoint() string { return "" }

var (
	defaultClient = detectors.DetectorHttpClientWithLocalAddresses

	keywords = []string{"confluence", "atlassian", "wiki"}

	// 44-char base64 PAT; decoded form must match the structural check in atlassiandatacenter.IsStructuralPAT.
	tokenPat = atlassiandatacenter.GetDCTokenPat(keywords)
	urlPat   = atlassiandatacenter.GetURLPat(keywords)

	invalidHosts = simple.NewCache[struct{}]()
	errNoHost    = errors.New("no such host")
)

func (s Scanner) Keywords() []string {
	return keywords
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_ConfluenceDataCenter
}

func (s Scanner) Description() string {
	return "Confluence Data Center is Atlassian's self-hosted wiki product. Personal Access Tokens (PATs) authenticate via Bearer auth against the REST API and grant access scoped to the issuing user."
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueTokens := make(map[string]struct{})
	for _, m := range tokenPat.FindAllStringSubmatch(dataStr, -1) {
		if _, seen := uniqueTokens[m[1]]; seen {
			continue
		}
		if atlassiandatacenter.IsStructuralPAT(m[1]) {
			uniqueTokens[m[1]] = struct{}{}
		}
	}
	if len(uniqueTokens) == 0 {
		return nil, nil
	}

	allURLs := atlassiandatacenter.FindEndpoints(dataStr, urlPat, s.Endpoints)

	// Filter hosts cached as unreachable from prior calls once up front.
	// invalidHosts may also grow during this call (see the verify branch
	// below); those are skipped lazily inside the inner loop.
	liveURLs := make([]string, 0, len(allURLs))
	for _, u := range allURLs {
		if !invalidHosts.Exists(u) {
			liveURLs = append(liveURLs, u)
		}
	}

	for token := range uniqueTokens {
		emitted := false
		for _, baseURL := range liveURLs {
			if invalidHosts.Exists(baseURL) {
				continue
			}

			r := detectors.Result{
				DetectorType: detector_typepb.DetectorType_ConfluenceDataCenter,
				Raw:          []byte(token),
				SecretParts: map[string]string{
					"token": token,
					"url":   baseURL,
				},
				RawV2: []byte(fmt.Sprintf("%s:%s", token, baseURL)),
				ExtraData: map[string]string{
					"base_url": baseURL,
				},
			}

			if verify {
				isVerified, vErr := verifyPAT(ctx, s.getClient(), baseURL, token)
				r.Verified = isVerified
				if vErr != nil {
					if errors.Is(vErr, errNoHost) {
						invalidHosts.Set(baseURL, struct{}{})
					}
					r.SetVerificationError(vErr, token)
				}
			}

			results = append(results, r)
			emitted = true
		}

		if !emitted {
			// No reachable URL in context — emit an unverified token-only
			// result and annotate why we couldn't verify.
			results = append(results, detectors.Result{
				DetectorType: detector_typepb.DetectorType_ConfluenceDataCenter,
				Raw:          []byte(token),
				SecretParts:  map[string]string{"token": token},
				RawV2:        []byte(token),
				ExtraData: map[string]string{
					"verification_note": "no reachable Confluence Data Center URL found in context; token reported unverified",
				},
			})
		}
	}

	return results, nil
}

func verifyPAT(ctx context.Context, client *http.Client, baseURL, token string) (bool, error) {
	endpoint := strings.TrimRight(baseURL, "/") + "/rest/api/user/current"

	isVerified, _, err := atlassiandatacenter.MakeVerifyRequest(ctx, client, endpoint, token)
	if err != nil {
		if strings.Contains(err.Error(), "no such host") {
			return false, errNoHost
		}
		return false, err
	}
	return isVerified, nil
}
