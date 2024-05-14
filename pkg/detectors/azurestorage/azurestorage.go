package azurestorage

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	regexp "github.com/wasilibs/go-re2"
	"net/http"
	"strings"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
}

var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = http.DefaultClient
	keyPat        = regexp.MustCompile(`DefaultEndpointsProtocol=https;AccountName=(?P<account_name>[^;]+);AccountKey=(?P<account_key>[^;]+);EndpointSuffix=core\.windows\.net`)
)

func (s Scanner) Keywords() []string {
	return []string{"DefaultEndpointsProtocol=https;AccountName="}
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 3 {
			continue
		}
		accountName := strings.TrimSpace(match[1])
		accountKey := strings.TrimSpace(match[2])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_AzureStorage,
			Raw:          []byte(accountKey),
			ExtraData: map[string]string{
				"account_name": accountName,
			},
		}

		if verify {
			client := s.getClient()

			isVerified, verificationErr := verifyAzureStorageKey(ctx, client, accountName, accountKey)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, accountKey)
		}

		results = append(results, s1)
	}

	return results, nil
}

func verifyAzureStorageKey(ctx context.Context, client *http.Client, accountName, accountKey string) (bool, error) {
	now := time.Now().UTC().Format(http.TimeFormat)
	stringToSign := "GET\n\n\n\n\n\n\n\n\n\n\n\nx-ms-date:" + now + "\nx-ms-version:2019-12-12\n/" + accountName + "/\ncomp:list"
	accountKeyBytes, _ := base64.StdEncoding.DecodeString(accountKey)
	h := hmac.New(sha256.New, accountKeyBytes)
	h.Write([]byte(stringToSign))
	signature := base64.StdEncoding.EncodeToString(h.Sum(nil))

	url := "https://" + accountName + ".blob.core.windows.net/?comp=list"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("x-ms-date", now)
	req.Header.Set("x-ms-version", "2019-12-12")
	req.Header.Set("Authorization", "SharedKey "+accountName+":"+signature)

	res, err := client.Do(req)
	if err != nil {
		// If the host is not found, we can assume that the accountName is not valid
		if strings.Contains(err.Error(), "no such host") {
			return false, nil
		}
		return false, err
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusForbidden:
		// 403 if account id or key is invalid, or if the account is disabled
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_AzureStorage
}
