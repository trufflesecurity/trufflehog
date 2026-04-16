package boxoauth

import (
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
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	clientIdPat     = regexp.MustCompile(detectors.PrefixRegex([]string{"id"}) + `\b([a-zA-Z0-9]{32})\b`)
	clientSecretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"secret"}) + `\b([a-zA-Z0-9]{32})\b`)
	// Box enterprise and user IDs are numeric strings.
	subjectIdPat = regexp.MustCompile(detectors.PrefixRegex([]string{
		"enterprise", "enterprise_id", "user_id", "subject", "box_subject",
	}) + `\b([0-9]{6,20})\b`)
)

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"box"}
}

func (s Scanner) Description() string {
	return "Box is a service offering various service for secure collaboration, content management, and workflow. Box Oauth credentials can be used to access and interact with this data."
}

// FromData will find and optionally verify Box secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueIdMatches := make(map[string]struct{})
	for _, match := range clientIdPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueIdMatches[match[1]] = struct{}{}
	}

	uniqueSecretMatches := make(map[string]struct{})
	for _, match := range clientSecretPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueSecretMatches[match[1]] = struct{}{}
	}

	uniqueSubjectIdMatches := make(map[string]struct{})
	for _, match := range subjectIdPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueSubjectIdMatches[match[1]] = struct{}{}
	}
	// Sentinel empty entry so a single loop body handles the "no subject_id
	// found" case alongside the normal one.
	if len(uniqueSubjectIdMatches) == 0 {
		uniqueSubjectIdMatches[""] = struct{}{}
	}

	for resIdMatch := range uniqueIdMatches {
	clientSecretLoop:
		for resSecretMatch := range uniqueSecretMatches {
			if resIdMatch == resSecretMatch {
				continue
			}
			var isVerified bool
			var verificationErr error
			if verify {
				isVerified, verificationErr = verifyMatch(ctx, s.getClient(), resIdMatch, resSecretMatch)
			}

			s1 := detectors.Result{
				DetectorType: s.Type(),
				Raw:          []byte(resIdMatch),
				RawV2:        []byte(resIdMatch + resSecretMatch),
				Verified:     isVerified,
			}
			s1.SetVerificationError(verificationErr, resIdMatch)
			for subjectId := range uniqueSubjectIdMatches {
				// AnalysisInfo is what triggers the analyzer downstream. It is
				// only meaningful when (a) the credential pair verified - an
				// unverified pair would just cause the analyzer to fail auth -
				// and (b) we actually have a subject_id, since Box CCG auth
				// requires all three values and the analyzer hard-fails
				// without subject_id.
				if isVerified && subjectId != "" {
					s1.AnalysisInfo = map[string]string{
						"client_id":     resIdMatch,
						"client_secret": resSecretMatch,
						"subject_id":    subjectId,
					}
				}
				results = append(results, s1)

			}
			// A Box application has exactly one client_id/client_secret pair,
			// so once we've verified a pair there is no value in trying other
			// id/secret combinations from the same chunk.
			if isVerified {
				break clientSecretLoop
			}
		}
	}

	return
}

func verifyMatch(ctx context.Context, client *http.Client, id string, secret string) (bool, error) {
	url := "https://api.box.com/oauth2/token"
	payload := strings.NewReader("grant_type=client_credentials&client_id=" + id + "&client_secret=" + secret)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, payload)
	if err != nil {
		return false, err
	}

	req.Header = http.Header{"content-type": []string{"application/x-www-form-urlencoded"}}

	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	// We are using malformed request to check if the client id and secret are valid.
	// In this case, the Box OAuth API returns a 400 status code even if the credentials are valid.
	//
	// - If the client ID/secret are valid, the response contains "unauthorized_client"
	// - If the credentials are invalid, the response contains "invalid_client"
	//
	// So we check the response body for one of these keywords.
	switch res.StatusCode {
	case http.StatusBadRequest:
		{
			bodyBytes, err := io.ReadAll(res.Body)
			if err != nil {
				return false, err
			}
			body := string(bodyBytes)
			if strings.Contains(body, "unauthorized_client") {
				return true, nil
			} else if strings.Contains(body, "invalid_client") {
				return false, nil
			} else {
				return false, fmt.Errorf("response body missing expected keyword")
			}
		}
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_BoxOauth
}
