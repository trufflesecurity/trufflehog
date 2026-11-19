package metabase

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = detectors.DetectorHttpClientWithLocalAddresses

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"metabase"}) + `\b([a-zA-Z0-9-]{36})\b`)

	baseURL = regexp.MustCompile(detectors.PrefixRegex([]string{"metabase"}) + `\b(https?:\/\/[-a-zA-Z0-9@:%._\+~#=]{7,256})\b`)

	// metabaseMarketingHosts are the Metabase marketing and documentation sites.
	// They are not Metabase instances, so a candidate URL on one of these hosts
	// can never verify a session token: docs links such as
	// https://www.metabase.com/docs/latest/api get paired with any nearby UUID
	// and verified against the marketing site, which only produces 404 noise.
	// Subdomains of metabase.com are NOT listed here: a customer instance such
	// as https://mycompany.metabase.com is a real Metabase deployment and must
	// still be verified.
	metabaseMarketingHosts = map[string]struct{}{
		"metabase.com":     {},
		"www.metabase.com": {},
	}
)

// isMetabaseMarketingHost reports whether host is the Metabase marketing or
// documentation site rather than a Metabase instance.
func isMetabaseMarketingHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	_, ok := metabaseMarketingHosts[host]
	return ok
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"metabase"}
}

// FromData will find and optionally verify Metabase secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	urlMatches := baseURL.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		for _, urlMatch := range urlMatches {
			resURLMatch := strings.TrimSpace(urlMatch[1])

			u, err := detectors.ParseURLAndStripPathAndParams(resURLMatch)
			if err != nil {
				// if the URL is invalid just move onto the next one
				continue
			}

			if isMetabaseMarketingHost(u.Hostname()) {
				// The Metabase marketing and docs sites are not Metabase
				// instances, so no session token can verify against them.
				// Skip the candidate instead of sending a verification
				// request that can only 404.
				continue
			}

			s1 := detectors.Result{
				DetectorType: detector_typepb.DetectorType_Metabase,
				Raw:          []byte(resMatch),
				SecretParts: map[string]string{
					"key": resMatch,
					"url": resURLMatch,
				},
				RawV2: []byte(resMatch + resURLMatch),
			}

			if verify {
				isVerified, verificationErr := verifyMatch(ctx, client, u, resMatch)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr, resMatch)
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func verifyMatch(ctx context.Context, client *http.Client, u *url.URL, resMatch string) (bool, error) {
	u.Path = "/api/user/current"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return false, err
	}
	req.Header.Add("X-Metabase-Session", resMatch)

	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = res.Body.Close() }()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return false, err
	}
	if res.StatusCode == http.StatusOK && json.Valid(body) {
		return true, nil
	}

	return false, nil
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Metabase
}

func (s Scanner) Description() string {
	return "Metabase is an open-source business intelligence tool. Metabase session tokens can be used to access and interact with the Metabase API."
}
