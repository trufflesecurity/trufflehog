package azurestorage

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"regexp"
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
			Raw:          []byte(accountName),
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			now := time.Now().UTC().Format(http.TimeFormat)
			stringToSign := "GET\n\n\n\n\n\n\n\n\n\n\n\nx-ms-date:" + now + "\nx-ms-version:2019-12-12\n/" + accountName + "/\ncomp:list"
			accountKeyBytes, _ := base64.StdEncoding.DecodeString(accountKey)
			h := hmac.New(sha256.New, accountKeyBytes)
			h.Write([]byte(stringToSign))
			signature := base64.StdEncoding.EncodeToString(h.Sum(nil))

			url := "https://" + accountName + ".blob.core.windows.net/?comp=list"
			req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
			req.Header.Set("x-ms-date", now)
			req.Header.Set("x-ms-version", "2019-12-12")
			req.Header.Set("Authorization", "SharedKey "+accountName+":"+signature)

			if err != nil {
				continue
			}
			res, err := client.Do(req)
			if err == nil {
				defer res.Body.Close()
				if res.StatusCode >= 200 && res.StatusCode < 300 {
					s1.Verified = true
				} else if res.StatusCode == 403 {
				} else {
					s1.VerificationError = fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
				}
			} else {
				s1.VerificationError = err
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_AzureStorage
}
