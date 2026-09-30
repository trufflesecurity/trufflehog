package dashscope

import (
	"context"
	"fmt"
	"io"
	"net/http"

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

	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"dashscope", "bailian", "aliyun", "qwen", "tongyi"}) + `\b(sk-[a-z0-9]{32})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"dashscope", "bailian", "aliyun", "qwen", "tongyi"}
}

// FromData will find and optionally verify DashScope secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for token := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_DashScope,
			Raw:          []byte(token),
			SecretParts:  map[string]string{"key": token},
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			verified, extraData, verificationErr := verifyToken(ctx, client, token)
			s1.Verified = verified
			s1.ExtraData = extraData
			s1.SetVerificationError(verificationErr)
		}

		results = append(results, s1)
	}

	return
}

func verifyToken(ctx context.Context, client *http.Client, token string) (bool, map[string]string, error) {
	regions := []struct {
		name     string
		endpoint string
	}{
		{
			name:     "cn-beijing",
			endpoint: "https://dashscope.aliyuncs.com/compatible-mode/v1/models",
		},
		{
			name:     "intl-singapore",
			endpoint: "https://dashscope-intl.aliyuncs.com/compatible-mode/v1/models",
		},
		{
			name:     "us-virginia",
			endpoint: "https://dashscope-us.aliyuncs.com/compatible-mode/v1/models",
		},
	}

	var firstErr error
	for _, region := range regions {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, region.endpoint, nil)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}

		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
		res, err := client.Do(req)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}

		statusCode := res.StatusCode
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()

		switch statusCode {
		case http.StatusOK:
			return true, map[string]string{"region": region.name}, nil
		case http.StatusUnauthorized, http.StatusForbidden:
			// The key is not valid for this region; try the next one.
		default:
			if firstErr == nil {
				firstErr = fmt.Errorf("unexpected HTTP response status %d from %s", statusCode, region.name)
			}
		}
	}

	return false, nil, firstErr
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_DashScope
}

func (s Scanner) Description() string {
	return "Alibaba Cloud Model Studio (DashScope) is an AI model service platform that provides access to Qwen and other large language models"
}
