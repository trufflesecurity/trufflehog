package azurestorage

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"regexp"
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
	namePat       = regexp.MustCompile(`AccountName=([a-z0-9]{3,24})`) // Names can only be lowercase alphanumeric.
	keyPat        = regexp.MustCompile(`AccountKey=([a-zA-Z0-9+/-]{86,88}={0,2})`)
	key1Pat       = regexp.MustCompile(`DefaultEndpointsProtocol=https;AccountName=(?P<account_name>[^;]+);AccountKey=(?P<account_key>[^;]+);EndpointSuffix=core\.windows\.net`)

	// https://learn.microsoft.com/en-us/azure/storage/common/storage-use-emulator
	testNames = map[string]struct{}{
		"devstoreaccount1": {},
		"storagesample":    {},
	}
	testKeys = map[string]struct{}{
		"Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==": {},
	}
)

func (s Scanner) Keywords() []string {
	return []string{"DefaultEndpointsProtocol=http", "EndpointSuffix="}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	// Deduplicate results.
	names := make(map[string]struct{})
	for _, matches := range namePat.FindAllStringSubmatch(dataStr, -1) {
		name := matches[1]
		if _, ok := testNames[name]; ok {
			continue
		}
		names[name] = struct{}{}
	}
	if len(names) == 0 {
		return results, nil
	}

	keys := make(map[string]struct{})
	for _, matches := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		key := matches[1]
		if _, ok := testKeys[key]; ok {
			continue
		}
		keys[key] = struct{}{}
	}
	if len(keys) == 0 {
		return results, nil
	}

	// Check results.
	for name := range names {
		s1 := detectors.Result{
			DetectorType: s.Type(),
			Raw:          []byte(name),
		}

		for key := range keys {
			if verify {
				isVerified, verificationErr := s.verifyMatch(ctx, name, key)
				s1.Verified = isVerified
				s1.VerificationError = verificationErr
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func (s Scanner) verifyMatch(ctx context.Context, name string, key string) (bool, error) {
	client := s.client
	if client == nil {
		client = defaultClient
	}

	now := time.Now().UTC().Format(http.TimeFormat)
	stringToSign := "GET\n\n\n\n\n\n\n\n\n\n\n\nx-ms-date:" + now + "\nx-ms-version:2019-12-12\n/" + name + "/\ncomp:list"
	accountKeyBytes, _ := base64.StdEncoding.DecodeString(key)
	h := hmac.New(sha256.New, accountKeyBytes)
	h.Write([]byte(stringToSign))
	signature := base64.StdEncoding.EncodeToString(h.Sum(nil))

	url := "https://" + name + ".blob.core.windows.net/?comp=list"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false, err
	}

	req.Header.Set("x-ms-date", now)
	req.Header.Set("x-ms-version", "2019-12-12")
	req.Header.Set("Authorization", "SharedKey "+name+":"+signature)

	res, err := client.Do(req)
	if err == nil {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()

		if res.StatusCode >= 200 && res.StatusCode < 300 {
			return true, nil
		} else if res.StatusCode == 403 {
			return false, nil
		} else {
			return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
		}
	} else {
		return false, err
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_AzureStorage
}
