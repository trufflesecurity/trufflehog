package braintreepayments

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
	client     *http.Client
	useTestURL bool
}

// Ensure the Scanner satisfies the interface at compile time
var _ detectors.Detector = (*Scanner)(nil)

const (
	verifyURL     = "https://payments.braintree-api.com/graphql"
	verifyTestURL = "https://payments.sandbox.braintree-api.com/graphql"
)

var (
	defaultClient = common.SaneHttpClient()
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"braintree"}) + `\b([0-9a-f]{32})\b`)
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"braintree"}) + `\b([0-9a-z]{16})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"braintree"}
}

// FromData will find and optionally verify BraintreePayments secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	idMatches := idPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		for _, idMatch := range idMatches {
			resIdMatch := strings.TrimSpace(idMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_BraintreePayments,
				Raw:          []byte(resMatch),
			}

			if verify {
				client := s.getClient()
				url := s.getBraintreeURL()
				isVerified, verificationErr := verifyBraintree(ctx, client, url, resIdMatch, resMatch)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr, resMatch)
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func (s Scanner) getBraintreeURL() string {
	if s.useTestURL {
		return verifyTestURL
	}
	return verifyURL
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

func verifyBraintree(ctx context.Context, client *http.Client, url, pubKey, privKey string) (bool, error) {
	payload := strings.NewReader(`{"query": "query { ping }"}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, payload)
	if err != nil {
		return false, err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Braintree-Version", "2019-01-01")
	req.SetBasicAuth(pubKey, privKey)
	res, err := client.Do(req)
	if err != nil {
		return false, err
	}

	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	bodyString := string(bodyBytes)
	if !(res.StatusCode == http.StatusOK) {
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}

	validResponse := `"data":{`
	if strings.Contains(bodyString, validResponse) {
		return true, nil
	}

	return false, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_BraintreePayments
}

func (s Scanner) Description() string {
	return "Braintree is a full-stack payment platform that makes it easy to accept payments in your mobile app or website. Braintree API keys can be used to access and manage payment transactions, customer data, and other payment-related operations."
}
